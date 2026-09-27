@echo off
setlocal
set "APP_DIR=%~dp0"
set "APP_FILE=%APP_DIR%index.html"

if not exist "%APP_FILE%" (
    echo AiKya index file not found.
    echo Expected: %APP_FILE%
    pause
    exit /b 1
)

start "AiKya" "%APP_FILE%"

echo AiKya app is opening directly from its desktop file.
exit /b 0
