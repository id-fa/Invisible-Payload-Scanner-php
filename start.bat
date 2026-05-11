@echo off
setlocal
cd /d "%~dp0"

set PORT=8765

where php >nul 2>nul
if errorlevel 1 (
  echo [ERROR] PHP not found in PATH. Install PHP 8.1+ and add it to PATH.
  pause
  exit /b 1
)

echo Invisible Payload Scanner
echo URL: http://127.0.0.1:%PORT%/
echo Press Ctrl+C in this window to stop.
echo.

start "" http://127.0.0.1:%PORT%/
php -S 127.0.0.1:%PORT% -t "%~dp0"
