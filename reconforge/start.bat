@echo off
setlocal enabledelayedexpansion
title ReconForge - Running
color 0B

echo.
echo  ============================================
echo       ReconForge - Universal OSINT Engine
echo  ============================================
echo.

:: Activate virtual environment
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
) else (
    echo  [!] Virtual environment not found. Run setup.bat first.
    pause
    exit /b 1
)

:: Add tools to PATH
set "PATH=%CD%\tools_bin;%CD%\tools_bin\jadx\bin;%PATH%"

:: Check if port is already in use
netstat -an | findstr ":8800 " | findstr "LISTENING" >nul 2>&1
if %errorlevel% equ 0 (
    echo  [!] Port 8800 already in use. ReconForge may already be running.
    echo  [!] Open http://localhost:8800 in your browser.
    echo.
    set /p KILL_PORT="  Kill existing process? (Y/N): "
    if /i "!KILL_PORT!"=="Y" (
        for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8800 " ^| findstr "LISTENING"') do (
            taskkill /PID %%p /F >nul 2>&1
        )
        echo  [OK] Killed existing process
        timeout /t 2 /nobreak >nul
    ) else (
        exit /b 0
    )
)

:: Ensure data directories
if not exist "data" mkdir data
if not exist "data\uploads" mkdir data\uploads
if not exist "data\reports" mkdir data\reports

echo  [*] Starting ReconForge server...
echo  [*] Web UI: http://localhost:8800
echo  [*] API Docs: http://localhost:8800/docs
echo.
echo  Press Ctrl+C to stop.
echo.

:: Start the server
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8800 --reload

pause
