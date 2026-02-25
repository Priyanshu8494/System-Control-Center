$serviceName = "NexusAgent"
$agentExe = "Nexus-Agent.exe"

# Check if Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run this script as Administrator to install the Service."
    exit
}

# Check if Agent Exists
if (-not (Test-Path $agentExe)) {
    Write-Error "Nexus-Agent.exe not found in current directory."
    exit
}

$exePath = (Resolve-Path $agentExe).Path

# Stop existing process
Write-Host "Stopping existing agent processes..."
Stop-Process -Name 'Nexus-Agent' -Force -ErrorAction SilentlyContinue

# Check if Service Exists
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Service already exists. Restarting..."
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Service -Name $serviceName
} else {
    Write-Host "Installing Nexus Agent Service..."
    New-Service -Name $serviceName -BinaryPathName $exePath -DisplayName "Nexus Agent" -StartupType Automatic
    Start-Service -Name $serviceName
}

Write-Host "Nexus Agent Service Installed and Started!"
