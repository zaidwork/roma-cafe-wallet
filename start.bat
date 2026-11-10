@echo off
chcp 65001 >nul
echo ========================================================
echo   ☕ Roma Cafe Dual Loyalty System - Production Server
echo ========================================================
echo.
echo Checking Node.js installation...
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH!
    echo Please install Node.js from https://nodejs.org
    pause
    exit /b 1
)

if not exist node_modules (
    echo [INFO] Installing required dependencies...
    call npm install --production
    echo.
)

echo [INFO] Starting Roma Cafe Production Server...
echo.
node server.js
pause

