@echo off
setlocal
title AiKya Console
set "APP_DIR=%~dp0"
set "APP_FILE=%APP_DIR%index.html"

if not exist "%APP_FILE%" (
    echo AiKya index.html was not found.
    echo Expected: %APP_FILE%
    pause
    exit /b 1
)

:menu
cls
echo ==============================
echo          AiKya Console
echo ==============================
echo.
echo [1] Open AiKya
echo [2] Open project folder
echo [3] Exit
echo.
set /p "choice=Select an option: "

if "%choice%"=="1" (
    start "AiKya" "%APP_FILE%"
    echo AiKya is opening...
    timeout /t 2 /nobreak >nul
    goto menu
)
if "%choice%"=="2" (
    start "" "%APP_DIR%"
    goto menu
)
if "%choice%"=="3" exit /b 0
goto menu