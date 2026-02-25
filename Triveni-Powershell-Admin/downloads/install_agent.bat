@echo off
setlocal
set SERVICE_NAME=SystemAgent
set AGENT_EXE=System-Agent.exe
set SERVER_URL=http://192.168.1.4:8080/dl/System-Agent.exe

:: Check for Administrative privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Please run this script as Administrator.
    pause
    exit /b 1
)

echo [INFO] Downloading System Agent...
powershell -Command "Invoke-WebRequest -Uri '%SERVER_URL%' -OutFile '%AGENT_EXE%'"

if not exist "%AGENT_EXE%" (
    echo [ERROR] Failed to download agent binary.
    pause
    exit /b 1
)

echo [INFO] Stopping existing agent...
powershell -Command "Stop-Process -Name 'System-Agent' -Force -ErrorAction SilentlyContinue"

echo [INFO] Installing/Restarting System Agent Service...
powershell -ExecutionPolicy Bypass -Command "if (Get-Service -Name '%SERVICE_NAME%' -ErrorAction SilentlyContinue) { Stop-Service -Name '%SERVICE_NAME%' -Force; Start-Service -Name '%SERVICE_NAME%' } else { New-Service -Name '%SERVICE_NAME%' -BinaryPathName '%~dp0%AGENT_EXE%' -DisplayName 'System Agent' -StartupType Automatic; Start-Service -Name '%SERVICE_NAME%' }"

echo [SUCCESS] System Agent installed and started successfully!
pause
