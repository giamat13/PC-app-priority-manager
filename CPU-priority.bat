@echo off
setlocal enabledelayedexpansion

:: Ask for process name
set /p procName=Enter the process name (e.g. WinRAR.exe):

:: Ask for priority
echo.
echo Select desired priority level:
echo 1 - Realtime
echo 2 - High
echo 3 - Above Normal
echo 4 - Normal
echo 5 - Below Normal
echo 6 - Low
set /p priorityChoice=Enter number (1-6):

:: Map the choice to WMIC priority value
set priorityValue=
if "%priorityChoice%"=="1" set priorityValue=256
if "%priorityChoice%"=="2" set priorityValue=128
if "%priorityChoice%"=="3" set priorityValue=32768
if "%priorityChoice%"=="4" set priorityValue=32
if "%priorityChoice%"=="5" set priorityValue=16384
if "%priorityChoice%"=="6" set priorityValue=64

if not defined priorityValue (
    echo Error: Invalid choice. Exiting...
    timeout /t 5 >nul
    exit /b
)

echo.
echo Monitoring process: %procName%
echo Target priority: %priorityChoice%
echo ------------------------------

:loop
for /f "tokens=2 delims=," %%A in ('tasklist /FI "IMAGENAME eq %procName%" /FO CSV /NH') do (
    echo Setting priority for PID %%A to %priorityChoice%
    wmic process where ProcessId=%%A CALL setpriority %priorityValue% >nul
)
timeout /t 5 >nul
goto loop
