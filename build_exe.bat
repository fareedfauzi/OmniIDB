@echo off
setlocal EnableDelayedExpansion

title OmniIDB - Executable Builder
cd /d "%~dp0"

echo =======================================================
echo          OmniIDB Windows Executable Builder            
echo =======================================================
echo.

REM 0. Ensure existing OmniIDB instance is closed
tasklist /fi "imagename eq OmniIDB.exe" 2>nul | findstr /i "OmniIDB.exe" >nul
if not errorlevel 1 (
    echo [*] Closing running OmniIDB instance so the binary can be updated...
    taskkill /f /im OmniIDB.exe >nul 2>&1
    timeout /t 1 /nobreak >nul
)

REM 1. Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not found in system PATH.
    echo Please install Python 3.10+ and check "Add Python to PATH".
    goto :error
)

for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYTHON_VER=%%i
echo [*] Found: !PYTHON_VER!

REM 2. Ensure pip dependencies are installed
echo [*] Checking required build dependencies...
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pip is not found!
    goto :error
)

echo [*] Installing / verifying build prerequisites (pyinstaller, pillow, reportlab, openai)...
python -m pip install -q -r requirements.txt pyinstaller

REM 3. Generate icon if missing
if not exist "omni-IDB-logo.ico" (
    if exist "omni-IDB-logo.png" (
        echo [*] Generating omni-IDB-logo.ico from omni-IDB-logo.png...
        python -c "from PIL import Image; img=Image.open('omni-IDB-logo.png'); img.save('omni-IDB-logo.ico', format='ICO', sizes=[(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)])"
        if errorlevel 1 (
            echo [WARNING] Could not convert omni-IDB-logo.png to omni-IDB-logo.ico.
        ) else (
            echo [OK] Generated omni-IDB-logo.ico successfully.
        )
    ) else (
        echo [WARNING] omni-IDB-logo.png not found. Continuing without custom icon.
    )
)

REM 4. Build executable with PyInstaller
echo.
echo [*] Compiling OmniIDB into standalone Windows executable...
set ICON_ARG=
if exist "omni-IDB-logo.ico" set ICON_ARG=--icon="omni-IDB-logo.ico"
set FONT_ARG=
if exist "JetBrainsMono.ttf" set FONT_ARG=--add-data "JetBrainsMono.ttf;."

python -m PyInstaller --noconfirm --clean --onefile --windowed --name OmniIDB !ICON_ARG! !FONT_ARG! --add-data "scripts;scripts" --add-data "omni-IDB-logo.png;." --add-data "omni-IDB-logo.ico;." --collect-all omni_idb omni_idb\__main__.py

if errorlevel 1 (
    echo.
    echo [ERROR] PyInstaller compilation failed!
    goto :error
)

REM 5. Relocate executable & clean up all leftover build clutter
if exist "dist\OmniIDB.exe" (
    echo [*] Relocating OmniIDB.exe to project root...
    if exist "OmniIDB.exe" del /f /q "OmniIDB.exe" 2>nul
    move /y "dist\OmniIDB.exe" "OmniIDB.exe" >nul
)

echo [*] Cleaning up build leftovers (build/, dist/, spec file)...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
if exist "OmniIDB.spec" del /f /q "OmniIDB.spec"

REM 6. Verification
if exist "OmniIDB.exe" (
    echo.
    echo =======================================================
    echo  [SUCCESS] OmniIDB executable created successfully!
    echo =======================================================
    echo  Binary Location: %~dp0OmniIDB.exe
    echo.
    echo Build leftovers removed. You can run "OmniIDB.exe" directly.
    echo.
    goto :finish
) else (
    echo.
    echo [ERROR] Final OmniIDB.exe was not found.
    goto :error
)

:error
echo.
echo [FAILED] Build process encountered errors.
echo.
pause
exit /b 1

:finish
pause
exit /b 0
