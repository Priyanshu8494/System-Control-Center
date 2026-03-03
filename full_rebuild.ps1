$agentDir = "OnPremX-Agent"
$adminDir = "OnPremX-Admin"
$adminDownloadsDir = "$adminDir/downloads"
$batPath = "$adminDownloadsDir/install_agent.bat"

Write-Host "--- Rebuilding Project ---"

# 1. Build Agent
Write-Host "Building Agent..."
cd $agentDir
go build -o OnPremX-Agent.exe main.go
cd ..

# 2. Get Base64
Write-Host "Converting Agent to Base64..."
$base64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$agentDir/OnPremX-Agent.exe"))

# 3. Create Standalone BAT
Write-Host "Generating Standalone BAT..."
$batContent = @"
@echo off
setlocal enabledelayedexpansion

:: Check for Administrative privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Please run this script as Administrator.
    pause
    exit /b 1
)

set SERVICE_NAME=OnPremXAgent
set AGENT_EXE=OnPremX-Agent.exe
set CONFIG_FILE=OnPremX-Agent.config.json

:: Use absolute paths for the current execution directory
set INSTALL_DIR=%~dp0
cd /d "%INSTALL_DIR%"

:: Ask for Server IP
echo Current machine IP or Server IP is required for connection.
set /p SERVER_IP="Enter OnPremX Server IP (default: 192.168.1.19): "
if "!SERVER_IP!"=="" set SERVER_IP=192.168.1.19
set SERVER_URL=http://!SERVER_IP!:8080

echo [INFO] Extracting OnPremX Agent...
certutil -decode "%~f0" "%AGENT_EXE%" >nul 2>&1

if not exist "%AGENT_EXE%" (
    echo [ERROR] Failed to extract agent binary. 
    echo [HINT] This might happen if antivirus blocks the extraction.
    pause
    exit /b 1
)

echo [INFO] Creating configuration...
echo {"server_url": "!SERVER_URL!"} > "%CONFIG_FILE%"

echo [INFO] Stopping existing agent...
powershell -Command "Stop-Service -Name '%SERVICE_NAME%' -Force -ErrorAction SilentlyContinue"
powershell -Command "Get-Process -Name 'OnPremX-Agent' -ErrorAction SilentlyContinue | Stop-Process -Force"

echo [INFO] Installing/Restarting OnPremX Agent Service...
powershell -ExecutionPolicy Bypass -Command "if (Get-Service -Name '%SERVICE_NAME%' -ErrorAction SilentlyContinue) { sc.exe delete %SERVICE_NAME% | Out-Null; Start-Sleep -Seconds 1 }"
powershell -ExecutionPolicy Bypass -Command "New-Service -Name '%SERVICE_NAME%' -BinaryPathName '\"%INSTALL_DIR%%AGENT_EXE%\"' -DisplayName 'OnPremX Agent' -StartupType Automatic; Start-Service -Name '%SERVICE_NAME%'"

if %errorLevel% neq 0 (
    echo [ERROR] Failed to start service.
    pause
    exit /b 1
)

echo [SUCCESS] OnPremX Agent installed and started successfully!
echo [INFO] Connecting to: !SERVER_URL!
pause
goto :eof

-----BEGIN CERTIFICATE-----
$base64
-----END CERTIFICATE-----
"@

$batContent | Out-File -FilePath $batPath -Encoding ascii
Write-Host "Standalone Installer generated at $batPath"

# 4. Build Server
Write-Host "Building Server..."
cd "$adminDir/admin-frontend"
npm run build
cd ..
go build -o OnPremX-Admin.exe main.go
cd ..

# 5. Move binary to downloads
Move-Item -Path "$agentDir/OnPremX-Agent.exe" -Destination "$adminDownloadsDir/" -Force

Write-Host "--- Rebuild Complete ---"
