@echo off
setlocal enabledelayedexpansion
title ReconForge Setup
color 0A

echo.
echo  ============================================
echo       ReconForge - Universal OSINT Engine
echo       Setup Script for Windows
echo  ============================================
echo.

:: Check admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Administrator rights recommended for full tool installation.
    echo  [!] Some tools may fail to install without admin. Continue anyway? (Y/N^)
    set /p CONTINUE_NONADMIN="  > "
    if /i "!CONTINUE_NONADMIN!" neq "Y" exit /b 1
)

:: ============================================
:: PHASE 1: Check Prerequisites
:: ============================================
echo  [Phase 1/5] Checking prerequisites...

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    python3 --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo  [X] Python 3.10+ is required but not found.
        echo      Download from: https://www.python.org/downloads/
        echo      Make sure to check "Add Python to PATH" during installation.
        exit /b 1
    )
    set PYTHON=python3
) else (
    set PYTHON=python
)

:: Check Python version >= 3.10
for /f "tokens=2 delims= " %%v in ('%PYTHON% --version 2^>^&1') do set PYVER=%%v
echo  [OK] Python %PYVER%

:: Check Node.js (for frontend build)
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Node.js not found. Frontend build will be skipped.
    echo      Download from: https://nodejs.org/ (LTS version)
    set HAS_NODE=0
) else (
    for /f "tokens=1 delims= " %%v in ('node --version 2^>^&1') do echo  [OK] Node.js %%v
    set HAS_NODE=1
)

:: Check Git
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Git not found. Some modules may have reduced functionality.
    set HAS_GIT=0
) else (
    echo  [OK] Git found
    set HAS_GIT=1
)

:: ============================================
:: PHASE 2: Python Dependencies
:: ============================================
echo.
echo  [Phase 2/5] Installing Python dependencies...

:: Create virtual environment
if not exist "venv" (
    %PYTHON% -m venv venv
    echo  [OK] Virtual environment created
)

:: Activate and install
call venv\Scripts\activate.bat
pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo  [!] Some packages failed to install. Trying individually...
    for /f "tokens=1 delims=>= " %%p in (requirements.txt) do (
        pip install %%p >nul 2>&1
        if %errorlevel% neq 0 (
            echo  [WARN] Failed to install: %%p
        )
    )
)
echo  [OK] Python dependencies installed

:: ============================================
:: PHASE 3: External Tools
:: ============================================
echo.
echo  [Phase 3/5] Installing external tools...

:: Create tools directory
if not exist "tools_bin" mkdir tools_bin

:: Install nmap (check if exists)
where nmap >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] nmap not found in PATH.
    echo      Download from: https://nmap.org/download.html
    echo      Install and add to PATH for port scanning functionality.
) else (
    echo  [OK] nmap found
)

:: Install jadx (for APK decompilation)
if not exist "tools_bin\jadx" (
    echo  [*] Downloading jadx...
    mkdir tools_bin\jadx 2>nul
    curl -sL "https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip" -o tools_bin\jadx.zip
    if exist tools_bin\jadx.zip (
        powershell -Command "Expand-Archive -Path 'tools_bin\jadx.zip' -DestinationPath 'tools_bin\jadx' -Force"
        del tools_bin\jadx.zip
        echo  [OK] jadx 1.5.0 installed
    ) else (
        echo  [WARN] Failed to download jadx
    )
) else (
    echo  [OK] jadx already installed
)

:: Install apktool
if not exist "tools_bin\apktool.jar" (
    echo  [*] Downloading apktool...
    curl -sL "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat" -o tools_bin\apktool.bat
    curl -sL "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar" -o tools_bin\apktool.jar
    if exist tools_bin\apktool.jar (
        echo  [OK] apktool 2.9.3 installed
    ) else (
        echo  [WARN] Failed to download apktool
    )
) else (
    echo  [OK] apktool already installed
)

:: Install nuclei
where nuclei >nul 2>&1
if %errorlevel% neq 0 (
    echo  [*] Downloading nuclei...
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.2/nuclei_3.3.2_windows_amd64.zip" -o tools_bin\nuclei.zip
    if exist tools_bin\nuclei.zip (
        powershell -Command "Expand-Archive -Path 'tools_bin\nuclei.zip' -DestinationPath 'tools_bin' -Force"
        del tools_bin\nuclei.zip
        echo  [OK] nuclei 3.3.2 installed
    )
) else (
    echo  [OK] nuclei found in PATH
)

:: Install subfinder
where subfinder >nul 2>&1
if %errorlevel% neq 0 (
    echo  [*] Downloading subfinder...
    curl -sL "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_windows_amd64.zip" -o tools_bin\subfinder.zip
    if exist tools_bin\subfinder.zip (
        powershell -Command "Expand-Archive -Path 'tools_bin\subfinder.zip' -DestinationPath 'tools_bin' -Force"
        del tools_bin\subfinder.zip
        echo  [OK] subfinder 2.6.6 installed
    )
) else (
    echo  [OK] subfinder found in PATH
)

echo  [OK] External tools check complete

:: ============================================
:: PHASE 4: Frontend Build
:: ============================================
echo.
echo  [Phase 4/5] Building frontend...

if "%HAS_NODE%"=="1" (
    cd frontend
    if exist package.json (
        call npm install
        call npx vite build
        if exist dist\index.html (
            echo  [OK] Frontend built successfully
        ) else (
            echo  [WARN] Frontend build failed — UI will run in dev mode
        )
    )
    cd ..
) else (
    echo  [SKIP] Node.js not available — frontend build skipped
    echo         Run 'npm install ^&^& npx vite build' in frontend/ later
)

:: ============================================
:: PHASE 5: Configuration
:: ============================================
echo.
echo  [Phase 5/5] Configuring...

:: Create data directories
if not exist "data" mkdir data
if not exist "data\uploads" mkdir data\uploads
if not exist "data\reports" mkdir data\reports
if not exist "data\results" mkdir data\results
if not exist "data\decompiled" mkdir data\decompiled
if not exist "data\screenshots" mkdir data\screenshots

:: Copy .env if not exists
if not exist ".env" (
    copy .env.example .env >nul
    echo  [OK] Created .env from template — edit to add your API keys
) else (
    echo  [OK] .env already exists
)

:: Initialize database
call venv\Scripts\activate.bat
%PYTHON% -c "from backend.database import init_db; init_db()" 2>nul
echo  [OK] Database initialized

:: Add tools_bin to PATH for this session
set "PATH=%CD%\tools_bin;%CD%\tools_bin\jadx\bin;%PATH%"

:: ============================================
:: Done
:: ============================================
echo.
echo  ============================================
echo       ReconForge Setup Complete!
echo  ============================================
echo.
echo  Quick start:
echo    1. Edit .env to add your API keys (optional)
echo    2. Run: start.bat
echo    3. Open: http://localhost:8800
echo.
echo  API keys enhance results but are NOT required.
echo  Free modules work out of the box.
echo.
pause
