# Simple Wazuh Agent Installation for Windows
# Uses the official Wazuh dashboard-generated installation commands

# Ensure the script is run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Please restart PowerShell as Administrator and try again." -ForegroundColor Red
    exit 1
}

# Display header
Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host "      WAZUH AGENT INSTALLATION FOR WINDOWS      " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# Prompt for manager IP
Write-Host "`nEnter Wazuh manager IP address" -ForegroundColor Yellow -NoNewline
Write-Host " [10.69.0.240]: " -NoNewline
$managerIP = Read-Host
if ([string]::IsNullOrEmpty($managerIP)) {
    $managerIP = "10.69.0.240"
}

# Prompt for agent name (optional)
Write-Host "Enter agent name (leave blank to use hostname): " -ForegroundColor Yellow -NoNewline
$agentName = Read-Host

# Prompt for agent group
Write-Host "Enter agent group" -ForegroundColor Yellow -NoNewline
Write-Host " [Windows11]: " -NoNewline
$agentGroup = Read-Host
if ([string]::IsNullOrEmpty($agentGroup)) {
    $agentGroup = "Windows11"
}

# Display settings
Write-Host "`nInstalling Wazuh agent with these settings:" -ForegroundColor Cyan
Write-Host "  Manager IP: " -NoNewline
Write-Host $managerIP -ForegroundColor Green
Write-Host "  Agent Group: " -NoNewline
Write-Host $agentGroup -ForegroundColor Green

if (-not [string]::IsNullOrEmpty($agentName)) {
    Write-Host "  Agent Name: " -NoNewline
    Write-Host $agentName -ForegroundColor Green
} else {
    Write-Host "  Agent Name: " -NoNewline
    Write-Host ([System.Net.Dns]::GetHostName()) -ForegroundColor Green -NoNewline
    Write-Host " (default hostname)"
}

Write-Host "`nStarting installation in 3 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Download Wazuh agent
Write-Host "`nDownloading Wazuh agent..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi" -OutFile "$env:tmp\wazuh-agent.msi"
    Write-Host "Download complete" -ForegroundColor Green
} catch {
    Write-Host "Failed to download Wazuh agent: $_" -ForegroundColor Red
    exit 1
}

# Install Wazuh agent
Write-Host "`nInstalling Wazuh agent..." -ForegroundColor Cyan

# Build installation arguments
$msiArgs = "/i `"$env:tmp\wazuh-agent.msi`" /q WAZUH_MANAGER='$managerIP' WAZUH_REGISTRATION_SERVER='$managerIP' WAZUH_AGENT_GROUP='$agentGroup'"

if (-not [string]::IsNullOrEmpty($agentName)) {
    $msiArgs += " WAZUH_AGENT_NAME='$agentName'"
}

try {
    Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -NoNewWindow
    Write-Host "Installation complete" -ForegroundColor Green
} catch {
    Write-Host "Failed to install Wazuh agent: $_" -ForegroundColor Red
    exit 1
}

# Start the Wazuh service
Write-Host "`nStarting Wazuh service..." -ForegroundColor Cyan
try {
    Start-Service -Name "WazuhSvc"
    Start-Sleep -Seconds 2

    $service = Get-Service -Name "WazuhSvc"
    if ($service.Status -eq "Running") {
        Write-Host "`n[SUCCESS] Wazuh agent installed and running!" -ForegroundColor Green
        Write-Host "Agent details:" -ForegroundColor Yellow
        Write-Host "  Manager: " -NoNewline
        Write-Host $managerIP -ForegroundColor Green
        Write-Host "  Group: " -NoNewline
        Write-Host $agentGroup -ForegroundColor Green
        Write-Host "  Status: " -NoNewline
        Write-Host "Running" -ForegroundColor Green
    } else {
        Write-Host "`n[ERROR] Wazuh agent is not running" -ForegroundColor Red
        Write-Host "Check status with:" -ForegroundColor Yellow -NoNewline
        Write-Host " Get-Service -Name WazuhSvc"
        exit 1
    }
} catch {
    Write-Host "Failed to start Wazuh service: $_" -ForegroundColor Red
    exit 1
}

# Cleanup
Remove-Item -Path "$env:tmp\wazuh-agent.msi" -Force -ErrorAction SilentlyContinue

# Installation of Osquery (if needed)
Write-Host "`nDo you want to install Osquery? (y/n): " -ForegroundColor Yellow -NoNewline
$installOsquery = Read-Host

if ($installOsquery -eq "y" -or $installOsquery -eq "Y") {
    Write-Host "`nInstalling Osquery..." -ForegroundColor Cyan
    
    # Download Osquery
    try {
        Invoke-WebRequest -Uri "https://pkg.osquery.io/windows/osquery-5.10.2.msi" -OutFile "$env:tmp\osquery.msi"
        Write-Host "Osquery download complete" -ForegroundColor Green
    } catch {
        Write-Host "Failed to download Osquery: $_" -ForegroundColor Red
    }
    
    # Install Osquery
    try {
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$env:tmp\osquery.msi`" /q" -Wait -NoNewWindow
        
        if (Test-Path "C:\Program Files\osquery\osqueryd\osqueryd.exe") {
            Write-Host "[SUCCESS] Osquery installed!" -ForegroundColor Green
        } else {
            Write-Host "[ERROR] Osquery installation could not be verified" -ForegroundColor Red
        }
        
        # Cleanup
        Remove-Item -Path "$env:tmp\osquery.msi" -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "Failed to install Osquery: $_" -ForegroundColor Red
    }
}

Write-Host "`nInstallation complete!" -ForegroundColor Green
Write-Host "To check agent status:" -ForegroundColor Yellow -NoNewline
Write-Host " Get-Service -Name WazuhSvc"
Write-Host "To view agent logs:" -ForegroundColor Yellow -NoNewline
Write-Host " Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log'"