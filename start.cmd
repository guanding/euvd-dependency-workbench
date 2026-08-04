@echo off
setlocal
set "ROOT=%~dp0"
if "%MATCHER_PORT%"=="" set "MATCHER_PORT=8090"
set "DATA_DIR=%ROOT%data"
set "OUTPUT_DIR=%ROOT%outputs"
set "PYTHONUTF8=1"

curl.exe -sS --fail "http://localhost:%MATCHER_PORT%/api/health" >nul 2>nul
if not errorlevel 1 (
    start "" "http://localhost:%MATCHER_PORT%"
    exit /b 0
)

if not exist "%ROOT%runtime\pythonw.exe" (
    PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\setup-runtime.ps1"
    if errorlevel 1 (
        echo Portable runtime setup failed.
        pause
        exit /b 1
    )
)

PowerShell.exe -NoProfile -Command "Start-Process -FilePath '%ROOT%runtime\python.exe' -ArgumentList '%ROOT%app\launcher.py' -WorkingDirectory '%ROOT%' -WindowStyle Hidden"

for /L %%I in (1,1,30) do (
    curl.exe -sS --fail "http://localhost:%MATCHER_PORT%/api/health" >nul 2>nul
    if not errorlevel 1 goto ready
    timeout /t 1 /nobreak >nul
)

:failed
echo EUVD Dependency Workbench failed to start.
pause
exit /b 1

:ready
echo EUVD Dependency Workbench is ready: http://localhost:%MATCHER_PORT%
start "" "http://localhost:%MATCHER_PORT%"
exit /b 0
