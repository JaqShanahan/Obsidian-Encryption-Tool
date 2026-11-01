@echo off
REM Build the standalone executable with PyInstaller (onefile).
REM Output: dist\obsidian_crypto.exe

python -m PyInstaller --onefile --name obsidian_crypto --clean obsidian_crypto.py
if errorlevel 1 (
    echo.
    echo Build FAILED.
    exit /b 1
)

echo.
echo Build complete: dist\obsidian_crypto.exe
