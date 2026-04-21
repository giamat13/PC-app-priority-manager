#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Process Priority Manager
Changes CPU, RAM and I/O priority for any process.
Priority: 1=Lowest | 5=Normal | 10=Highest
"""

import os
import sys
import platform
import psutil
import subprocess
import ctypes
import threading
import signal
import atexit

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

OS = platform.system()

PROTECTED_PROCESSES = {
    "Windows": {
        "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "lsm.exe", "svchost.exe",
        "dwm.exe", "explorer.exe", "registry",
    },
    "Linux": {
        "init", "systemd", "kthreadd", "kworker", "ksoftirqd",
        "migration", "rcu_sched", "rcu_bh", "watchdog",
        "kdevtmpfs", "netns", "kauditd", "khungtaskd",
        "oom_reaper", "writeback", "kcompactd", "khugepaged",
    },
    "Darwin": {
        "kernel_task", "launchd", "kextd", "logd", "notifyd",
        "configd", "diskarbitrationd", "powerd", "securityd",
    },
}

PRIORITY_TO_NICE = {
    1: 19, 2: 15, 3: 10, 4: 5, 5: 0,
    6: -3, 7: -7, 8: -12, 9: -16, 10: -20,
}

WINDOWS_PRIORITY_CLASS = {
    1: psutil.IDLE_PRIORITY_CLASS,
    2: psutil.IDLE_PRIORITY_CLASS,
    3: psutil.BELOW_NORMAL_PRIORITY_CLASS,
    4: psutil.BELOW_NORMAL_PRIORITY_CLASS,
    5: psutil.NORMAL_PRIORITY_CLASS,
    6: psutil.NORMAL_PRIORITY_CLASS,
    7: psutil.ABOVE_NORMAL_PRIORITY_CLASS,
    8: psutil.HIGH_PRIORITY_CLASS,
    9: psutil.HIGH_PRIORITY_CLASS,
    10: psutil.HIGH_PRIORITY_CLASS,  # REALTIME avoided - dangerous
}

PRIORITY_LABELS = {
    1:  "[1]  Very Low  (Idle)",
    2:  "[2]  Low",
    3:  "[3]  Below Normal",
    4:  "[4]  Slightly Below Normal",
    5:  "[5]  Normal",
    6:  "[6]  Slightly Above Normal",
    7:  "[7]  Above Normal",
    8:  "[8]  High",
    9:  "[9]  Very High",
    10: "[10] Maximum (High)",
}


# ── Global state: tracks all active overrides ───────────────
# { pid: { "proc": psutil.Process, "level": int,
#           "orig_cpu": int, "orig_io": int } }
_overrides = {}
_monitor_stop = threading.Event()


# ── Process search ───────────────────────────────────────────

def find_processes(name):
    matches = []
    name_lower = name.lower()
    for proc in psutil.process_iter(["pid", "name", "status", "memory_info"]):
        try:
            if name_lower in proc.info["name"].lower():
                matches.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return matches


def is_protected(proc):
    protected = PROTECTED_PROCESSES.get(OS, set())
    try:
        return proc.name().lower() in protected
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return True


def is_system_critical(proc):
    try:
        return proc.pid <= 4
    except Exception:
        return True


# ── Snapshot original priorities ─────────────────────────────

def snapshot_priorities(proc):
    """Read and return current CPU and I/O priority of a process."""
    snap = {}
    try:
        snap["cpu"] = proc.nice()
    except Exception:
        snap["cpu"] = None
    try:
        snap["io"] = proc.ionice()
    except Exception:
        snap["io"] = None
    return snap


# ── Priority setters ─────────────────────────────────────────

def set_cpu_priority(proc, level):
    # Level 5 = Normal = no change
    if level == 5:
        return None, "Level 5 - no change (already normal)"
    try:
        if OS == "Windows":
            proc.nice(WINDOWS_PRIORITY_CLASS[level])
        else:
            nice_val = PRIORITY_TO_NICE[level]
            if nice_val < 0 and os.geteuid() != 0:
                try:
                    subprocess.run(
                        ["sudo", "renice", str(nice_val), "-p", str(proc.pid)],
                        check=True, capture_output=True
                    )
                    return True, f"nice={nice_val} (via sudo)"
                except subprocess.CalledProcessError:
                    proc.nice(0)
                    return True, "nice=0 (root required for higher priority)"
            else:
                proc.nice(nice_val)
        return True, "CPU priority changed successfully"
    except psutil.AccessDenied:
        return False, "Access denied - run as Administrator"
    except Exception as e:
        return False, str(e)


def set_io_priority(proc, level):
    # Level 5 = Normal = no change
    if level == 5:
        return None, "Level 5 - no change (already normal)"
    try:
        if OS == "Windows":
            if level <= 2:
                io_class = psutil.IOPRIO_VERYLOW
            elif level <= 4:
                io_class = psutil.IOPRIO_LOW
            elif level <= 7:
                io_class = psutil.IOPRIO_NORMAL
            else:
                io_class = psutil.IOPRIO_HIGH
            proc.ionice(io_class)
            return True, "I/O priority changed"

        elif OS == "Linux":
            if level <= 2:
                ioclass, iodata = 3, 0
            elif level <= 4:
                ioclass, iodata = 2, 7
            elif level <= 6:
                ioclass, iodata = 2, 4
            elif level <= 8:
                ioclass, iodata = 2, 0
            else:
                ioclass, iodata = 1, 4
            proc.ionice(ioclass, iodata)
            return True, f"I/O class={ioclass}, data={iodata}"

        else:
            return None, "macOS: I/O priority not supported"

    except AttributeError:
        return None, "ionice not supported in this psutil version"
    except psutil.AccessDenied:
        return False, "Access denied"
    except Exception as e:
        return False, str(e)


def set_memory_priority(proc, level):
    # Level 5 = Normal = no change
    if level == 5:
        return None, "Level 5 - no change (already normal)"
    try:
        if OS == "Linux":
            oom_path = f"/proc/{proc.pid}/oom_score_adj"
            if not os.path.exists(oom_path):
                return None, "/proc path not found"
            oom_map = {
                1: 800, 2: 600, 3: 400, 4: 200, 5: 0,
                6: -100, 7: -300, 8: -500, 9: -700, 10: -900,
            }
            oom_val = oom_map[level]
            if os.geteuid() != 0 and oom_val < 0:
                return None, "Root required for negative OOM score"
            with open(oom_path, "w") as f:
                f.write(str(oom_val))
            return True, f"OOM score_adj={oom_val}"

        elif OS == "Windows":
            PROCESS_SET_QUOTA = 0x0100 | 0x0400
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_SET_QUOTA, False, proc.pid)
            if handle:
                if level <= 2:
                    ctypes.windll.kernel32.SetProcessWorkingSetSize(handle, -1, -1)
                    ctypes.windll.kernel32.CloseHandle(handle)
                    return True, "Working Set trimmed (RAM freed)"
                else:
                    ctypes.windll.kernel32.CloseHandle(handle)
                    return None, "Windows: RAM boost not directly supported via this API"
            return False, "Could not open process handle"

        else:
            return None, "macOS: RAM priority not supported"

    except PermissionError:
        return False, "Access denied"
    except Exception as e:
        return False, str(e)


# ── Restore original priorities ──────────────────────────────

def restore_process(pid, entry):
    """Restore a single process to its original priorities."""
    proc = entry["proc"]
    orig = entry["orig"]
    try:
        proc.status()  # check still alive
    except psutil.NoSuchProcess:
        return
    try:
        if orig["cpu"] is not None:
            proc.nice(orig["cpu"])
    except Exception:
        pass
    try:
        if orig["io"] is not None:
            if OS == "Windows":
                proc.ionice(orig["io"])
            elif OS == "Linux":
                proc.ionice(orig["io"].ioclass, orig["io"].value)
    except Exception:
        pass


def restore_all():
    """Called on exit - restores every tracked process."""
    if not _overrides:
        return
    print(f"\n{YELLOW}Restoring original priorities for {len(_overrides)} process(es)...{RESET}")
    for pid, entry in list(_overrides.items()):
        try:
            name = entry["proc"].name()
        except Exception:
            name = f"PID {pid}"
        restore_process(pid, entry)
        print(f"  {GREEN}Restored{RESET}  {name} (PID {pid})")
    print(f"{GREEN}All restored.{RESET}")


# ── Background monitor ───────────────────────────────────────

def _monitor_loop():
    """Every 10 seconds, re-apply overrides if the OS changed them."""
    while not _monitor_stop.wait(10):
        dead = []
        for pid, entry in list(_overrides.items()):
            proc = entry["proc"]
            level = entry["level"]
            try:
                proc.status()
            except psutil.NoSuchProcess:
                dead.append(pid)
                continue

            # Check CPU drift
            try:
                current_nice = proc.nice()
                expected_nice = WINDOWS_PRIORITY_CLASS[level] if OS == "Windows" else PRIORITY_TO_NICE[level]
                if current_nice != expected_nice and level != 5:
                    set_cpu_priority(proc, level)
            except Exception:
                pass

            # Check I/O drift
            try:
                if OS == "Windows" and level != 5:
                    current_io = proc.ionice()
                    if level <= 2:
                        expected_io = psutil.IOPRIO_VERYLOW
                    elif level <= 4:
                        expected_io = psutil.IOPRIO_LOW
                    elif level <= 7:
                        expected_io = psutil.IOPRIO_NORMAL
                    else:
                        expected_io = psutil.IOPRIO_HIGH
                    if current_io != expected_io:
                        set_io_priority(proc, level)
            except Exception:
                pass

        for pid in dead:
            _overrides.pop(pid, None)


# ── UI ───────────────────────────────────────────────────────

def print_header():
    print(f"""
{CYAN}{BOLD}+------------------------------------------------------+
|        Process Priority Manager                      |
|        Priority: 1=Lowest  5=Normal  10=Highest      |
+------------------------------------------------------+{RESET}
""")


def pick_priority():
    print(f"\n{CYAN}Priority levels:{RESET}")
    for lvl, label in PRIORITY_LABELS.items():
        marker = f"{BOLD} <-- default{RESET}" if lvl == 5 else ""
        print(f"  {label}{marker}")
    print()
    while True:
        try:
            val = input(f"{YELLOW}Enter priority (1-10, 0 to cancel): {RESET}").strip()
            if val == "0":
                return None
            level = int(val)
            if 1 <= level <= 10:
                return level
            print(f"{RED}Valid range: 1-10{RESET}")
        except ValueError:
            print(f"{RED}Enter a number only.{RESET}")
        except KeyboardInterrupt:
            return None


def confirm_dangerous(proc, level):
    if level in (1, 10):
        action = "MAXIMUM boost" if level == 10 else "MINIMUM priority"
        print(f"\n{RED}{BOLD}WARNING: {action} may affect system stability!{RESET}")
        print(f"  Process: {proc.name()} (PID {proc.pid})")
        ans = input(f"{YELLOW}Are you sure? (yes/no): {RESET}").strip().lower()
        return ans in ("yes", "y")
    return True


def apply_priorities(proc, level):
    print(f"\n{CYAN}{'-'*55}{RESET}")
    print(f"{BOLD}Applying priority {level} to {proc.name()} (PID {proc.pid}){RESET}")
    print(f"{CYAN}{'-'*55}{RESET}\n")

    # Snapshot originals before touching anything (only first time for this pid)
    if proc.pid not in _overrides:
        orig = snapshot_priorities(proc)
        _overrides[proc.pid] = {"proc": proc, "level": level, "orig": orig}
    else:
        _overrides[proc.pid]["level"] = level  # update level if changed

    ok, msg = set_cpu_priority(proc, level)
    icon = (GREEN + "OK ") if ok else (YELLOW + "-- " if ok is None else RED + "ERR")
    print(f"  {icon}{RESET}  CPU Priority:  {msg}")

    ok, msg = set_io_priority(proc, level)
    icon = (GREEN + "OK ") if ok else (YELLOW + "-- " if ok is None else RED + "ERR")
    print(f"  {icon}{RESET}  I/O Priority:  {msg}")

    ok, msg = set_memory_priority(proc, level)
    icon = (GREEN + "OK ") if ok else (YELLOW + "-- " if ok is None else RED + "ERR")
    print(f"  {icon}{RESET}  RAM / Memory:  {msg}")

    if level == 5:
        print(f"\n{YELLOW}Priority 5 = Normal: no changes were made.{RESET}")
    else:
        print(f"\n{GREEN}Done! Monitoring every 10s to keep this priority.{RESET}")


# ── Main loop ────────────────────────────────────────────────

def main():
    print_header()

    # Register restore-on-exit
    atexit.register(restore_all)
    try:
        signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
    except (OSError, ValueError):
        pass  # SIGTERM not available on all platforms

    # Start background monitor thread
    monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
    monitor_thread.start()

    while True:
        print(f"\n{CYAN}{'='*55}{RESET}")
        try:
            name = input(f"{BOLD}Enter process name (or part of it), blank to exit: {RESET}").strip()
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Exiting.{RESET}")
            break

        if not name:
            print(f"{YELLOW}Goodbye!{RESET}")
            break

        procs = find_processes(name)
        if not procs:
            print(f"{RED}No processes found matching '{name}'.{RESET}")
            continue

        # Filter out protected/critical before asking for priority
        valid_procs = []
        for p in procs:
            if is_system_critical(p):
                print(f"{RED}BLOCKED: Critical system process (PID <= 4) - skipped.{RESET}")
            elif is_protected(p):
                print(f"{RED}BLOCKED: '{p.name()}' is a protected system process - skipped.{RESET}")
            else:
                valid_procs.append(p)

        if not valid_procs:
            continue

        print(f"\n{CYAN}Found {len(valid_procs)} process(es) - will apply to all:{RESET}")
        for p in valid_procs:
            try:
                mem_mb = p.memory_info().rss / 1024 / 1024
                print(f"  PID {p.pid:<8} {p.name():<30} {mem_mb:.1f} MB")
            except Exception:
                print(f"  PID {p.pid}")

        level = pick_priority()
        if level is None:
            continue

        if not confirm_dangerous(valid_procs[0], level):
            print(f"{YELLOW}Cancelled.{RESET}")
            continue

        for proc in valid_procs:
            try:
                proc.status()
                apply_priorities(proc, level)
            except psutil.NoSuchProcess:
                print(f"{RED}PID {proc.pid} ended before changes could be applied.{RESET}")
            except KeyboardInterrupt:
                print(f"\n{YELLOW}Cancelled by user.{RESET}")
                break

        print(f"\n{CYAN}Press Ctrl+C at any time to stop monitoring and restore all priorities.{RESET}")


def is_number(s):
    try:
        v = int(s)
        return 1 <= v <= 10
    except (ValueError, TypeError):
        return False


def parse_cli_args(args):
    """
    Parse flexible CLI args into a list of (name, level_or_None) pairs.
    Supports:
      chrome              -> [("chrome", None)]   ask for priority
      8                   -> [(None, 8)]           ask for name, skip priority
      chrome 8            -> [("chrome", 8)]
      chrome 8 vscode cmd 6  -> [("chrome", 8), ("vscode", 6), ("cmd", 6)]
    """
    pairs = []
    i = 0
    while i < len(args):
        token = args[i]
        if is_number(token):
            # bare number - apply to interactive name selection
            pairs.append((None, int(token)))
            i += 1
        else:
            # it's a name - look ahead for optional number
            name = token
            if i + 1 < len(args) and is_number(args[i + 1]):
                pairs.append((name, int(args[i + 1])))
                i += 2
            else:
                pairs.append((name, None))
                i += 1
    # if multiple names share a trailing number, distribute it
    # e.g. "vscode cmd 6" -> vscode gets None initially, fix it
    # re-scan: any name without a level inherits the next found level
    result = []
    pending_names = []
    for name, level in pairs:
        if name is None:
            # bare number - skip (handled separately)
            result.append((name, level))
        elif level is not None:
            # flush pending names with this level
            for pn in pending_names:
                result.append((pn, level))
            pending_names = []
            result.append((name, level))
        else:
            pending_names.append(name)
    # any remaining pending names have no level -> will ask
    for pn in pending_names:
        result.append((pn, None))
    return result


def cli_apply(name, level):
    """Find processes by name, optionally ask for level, then apply."""
    if name is None:
        # bare number was given - ask for process name interactively
        try:
            name = input(f"{BOLD}Enter process name: {RESET}").strip()
        except KeyboardInterrupt:
            return False
        if not name:
            return False

    procs = find_processes(name)
    if not procs:
        print(f"{RED}No processes found matching '{name}'.{RESET}")
        return False

    valid_procs = [p for p in procs if not is_system_critical(p) and not is_protected(p)]
    if not valid_procs:
        print(f"{RED}All matching processes for '{name}' are protected - skipped.{RESET}")
        return False

    print(f"\n{CYAN}Found {len(valid_procs)} process(es) for '{name}':{RESET}")
    for p in valid_procs:
        try:
            mem_mb = p.memory_info().rss / 1024 / 1024
            print(f"  PID {p.pid:<8} {p.name():<30} {mem_mb:.1f} MB")
        except Exception:
            print(f"  PID {p.pid}")

    if level is None:
        level = pick_priority()
        if level is None:
            return False

    if level in (1, 10):
        action = "MAXIMUM boost" if level == 10 else "MINIMUM priority"
        print(f"{RED}{BOLD}WARNING: {action} may affect system stability!{RESET}")
        ans = input(f"{YELLOW}Are you sure? (yes/no): {RESET}").strip().lower()
        if ans not in ("yes", "y"):
            print(f"{YELLOW}Cancelled.{RESET}")
            return False

    for proc in valid_procs:
        try:
            apply_priorities(proc, level)
        except psutil.NoSuchProcess:
            print(f"{RED}PID {proc.pid} ended before changes could be applied.{RESET}")
    return True


if __name__ == "__main__":
    try:
        args = sys.argv[1:]

        if args:
            atexit.register(restore_all)
            try:
                signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
            except (OSError, ValueError):
                pass

            monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
            monitor_thread.start()

            print_header()
            pairs = parse_cli_args(args)
            for name, level in pairs:
                cli_apply(name, level)

            total = len(_overrides)
            if total:
                print(f"\n{CYAN}Monitoring {total} process(es). Press Ctrl+C to stop and restore.{RESET}")
                try:
                    _monitor_stop.wait()
                except KeyboardInterrupt:
                    pass
        else:
            main()

    except KeyboardInterrupt:
        print(f"\n{YELLOW}Exiting.{RESET}")
    finally:
        _monitor_stop.set()
        sys.exit(0)