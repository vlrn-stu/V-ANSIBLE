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

# Check internet connectivity
Write-Host "`nChecking internet connectivity..." -ForegroundColor Cyan
try {
    $internetCheck = Test-Connection -ComputerName 8.8.8.8 -Count 1 -ErrorAction Stop
    Write-Host "Internet connection available" -ForegroundColor Green
} catch {
    Write-Host "Warning: Internet connectivity check failed. This may affect downloads." -ForegroundColor Yellow
    Write-Host "Do you want to continue anyway? (y/n): " -ForegroundColor Yellow -NoNewline
    $continueAnyway = Read-Host
    if ($continueAnyway -ne "y" -and $continueAnyway -ne "Y") {
        Write-Host "Installation aborted." -ForegroundColor Red
        exit 1
    }
}

# Prompt for manager IP
Write-Host "`nEnter Wazuh manager IP address" -ForegroundColor Yellow -NoNewline
Write-Host " [10.69.0.240]: " -NoNewline
$managerIP = Read-Host
if ([string]::IsNullOrEmpty($managerIP)) {
    $managerIP = "10.69.0.240"
}

# Check if manager is reachable
Write-Host "`nChecking manager connection..." -ForegroundColor Cyan
try {
    $managerCheck = Test-Connection -ComputerName $managerIP -Count 1 -ErrorAction Stop
    Write-Host "Manager is reachable at $managerIP" -ForegroundColor Green
} catch {
    Write-Host "Warning: Cannot ping Wazuh manager at $managerIP" -ForegroundColor Yellow
    Write-Host "This may be due to firewall restrictions or the manager being unreachable." -ForegroundColor Yellow
    Write-Host "Do you want to continue anyway? (y/n): " -ForegroundColor Yellow -NoNewline
    $continueAnyway = Read-Host
    if ($continueAnyway -ne "y" -and $continueAnyway -ne "Y") {
        Write-Host "Installation aborted." -ForegroundColor Red
        exit 1
    }
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

# Download Wazuh agent with retry
Write-Host "`nDownloading Wazuh agent..." -ForegroundColor Cyan
$maxRetries = 3
$retryCount = 0
$downloadSuccess = $false

while ($retryCount -lt $maxRetries -and -not $downloadSuccess) {
    Write-Host "Download attempt $($retryCount+1)/$maxRetries..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi" -OutFile "$env:tmp\wazuh-agent.msi" -TimeoutSec 30
        if (Test-Path "$env:tmp\wazuh-agent.msi") {
            $fileInfo = Get-Item "$env:tmp\wazuh-agent.msi"
            if ($fileInfo.Length -gt 1000) {  # Check if file size is reasonable
                Write-Host "Download complete" -ForegroundColor Green
                $downloadSuccess = $true
            } else {
                Write-Host "Downloaded file is too small, might be incomplete" -ForegroundColor Yellow
                Remove-Item -Path "$env:tmp\wazuh-agent.msi" -Force
                $retryCount++
                Start-Sleep -Seconds 5
            }
        }
    } catch {
        Write-Host "Download attempt failed: $_" -ForegroundColor Yellow
        $retryCount++
        Start-Sleep -Seconds 5
    }
}

if (-not $downloadSuccess) {
    Write-Host "Failed to download Wazuh agent after $maxRetries attempts" -ForegroundColor Red
    Write-Host "Would you like to try an alternative installation method? (y/n): " -ForegroundColor Yellow -NoNewline
    $useAlternative = Read-Host
    
    if ($useAlternative -eq "y" -or $useAlternative -eq "Y") {
        Write-Host "`nAttempting alternative installation method..." -ForegroundColor Cyan
        # Alternative method: Direct download from a mirror or local network share could be implemented here
        Write-Host "No alternative installation method available. Please check your internet connection and try again." -ForegroundColor Red
        exit 1
    } else {
        Write-Host "Installation aborted." -ForegroundColor Red
        exit 1
    }
}

# Install Wazuh agent
Write-Host "`nInstalling Wazuh agent..." -ForegroundColor Cyan

# Build installation arguments
$msiArgs = "/i `"$env:tmp\wazuh-agent.msi`" /q WAZUH_MANAGER='$managerIP' WAZUH_REGISTRATION_SERVER='$managerIP'"

if (-not [string]::IsNullOrEmpty($agentGroup)) {
    $msiArgs += " WAZUH_AGENT_GROUP='$agentGroup'"
}

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

# Verify installation
Write-Host "`nVerifying installation..." -ForegroundColor Cyan
if (Test-Path "C:\Program Files (x86)\ossec-agent\ossec.conf") {
    Write-Host "Installation files verified" -ForegroundColor Green
    
    # Ensure proper configuration
    Write-Host "Configuring agent..." -ForegroundColor Cyan
    
    # Ensure proper settings in ossec.conf
    try {
        $ossecConfig = Get-Content -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Raw
        
        # Update manager address if needed
        if ($ossecConfig -match "<address>.*?</address>") {
            $ossecConfig = $ossecConfig -replace "<address>.*?</address>", "<address>$managerIP</address>"
            $ossecConfig | Set-Content -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Force
            Write-Host "Manager address updated in configuration" -ForegroundColor Green
        }
        
        # Update agent name if provided
        if (-not [string]::IsNullOrEmpty($agentName) -and $ossecConfig -match "<client>") {
            if ($ossecConfig -match "<client_name>.*?</client_name>") {
                $ossecConfig = $ossecConfig -replace "<client_name>.*?</client_name>", "<client_name>$agentName</client_name>"
            } else {
                $ossecConfig = $ossecConfig -replace "<client>", "<client>`n    <client_name>$agentName</client_name>"
            }
            $ossecConfig | Set-Content -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Force
            Write-Host "Agent name updated in configuration" -ForegroundColor Green
        }
    } catch {
        Write-Host "Warning: Could not update configuration file: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "Warning: Could not verify installation files" -ForegroundColor Yellow
}

# Register agent (explicitly running the agent-auth tool)
Write-Host "`nRegistering agent with manager..." -ForegroundColor Cyan
try {
    $authArgs = "-m $managerIP"
    
    if (-not [string]::IsNullOrEmpty($agentGroup)) {
        $authArgs += " -G $agentGroup"
    }
    
    if (-not [string]::IsNullOrEmpty($agentName)) {
        $authArgs += " -A $agentName"
    }
    
    Start-Process -FilePath "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -ArgumentList $authArgs -Wait -NoNewWindow
    Write-Host "Agent registered with manager" -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not register agent: $_" -ForegroundColor Yellow
    Write-Host "The agent may still work if the registration was handled during installation" -ForegroundColor Yellow
}

# Stop any existing service before starting
Write-Host "`nStopping any existing Wazuh service..." -ForegroundColor Cyan
try {
    Stop-Service -Name "WazuhSvc" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
} catch {
    # Ignore errors if service wasn't running
}

# Start the Wazuh service
Write-Host "`nStarting Wazuh service..." -ForegroundColor Cyan
try {
    Start-Service -Name "WazuhSvc"
    Start-Sleep -Seconds 5

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
        Write-Host "`n[WARNING] Wazuh agent is not running" -ForegroundColor Yellow
        Write-Host "Attempting to troubleshoot..." -ForegroundColor Yellow
        
        # Troubleshooting steps
        Write-Host "1. Checking service dependencies..." -ForegroundColor Cyan
        Get-Service -Name WazuhSvc -DependentServices | Format-Table -AutoSize
        
        Write-Host "2. Trying to restart service..." -ForegroundColor Cyan
        Restart-Service -Name "WazuhSvc" -Force
        
        Start-Sleep -Seconds 5
        $service = Get-Service -Name "WazuhSvc"
        if ($service.Status -eq "Running") {
            Write-Host "Service is now running!" -ForegroundColor Green
        } else {
            Write-Host "Service still not running." -ForegroundColor Red
            Write-Host "Please check the Windows event logs and Wazuh logs for more information." -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "Failed to start Wazuh service: $_" -ForegroundColor Red
    Write-Host "Please try starting the service manually: Start-Service -Name WazuhSvc" -ForegroundColor Yellow
}

# Cleanup
Remove-Item -Path "$env:tmp\wazuh-agent.msi" -Force -ErrorAction SilentlyContinue

# Installation of Osquery (if needed)
Write-Host "`nDo you want to install Osquery? (y/n): " -ForegroundColor Yellow -NoNewline
$installOsquery = Read-Host

if ($installOsquery -eq "y" -or $installOsquery -eq "Y") {
    Write-Host "`nInstalling Osquery..." -ForegroundColor Cyan
    
    # Download Osquery with retry
    $retryCount = 0
    $downloadSuccess = $false
    
    while ($retryCount -lt $maxRetries -and -not $downloadSuccess) {
        Write-Host "Download attempt $($retryCount+1)/$maxRetries..." -ForegroundColor Yellow
        try {
            Invoke-WebRequest -Uri "https://pkg.osquery.io/windows/osquery-5.10.2.msi" -OutFile "$env:tmp\osquery.msi" -TimeoutSec 30
            if (Test-Path "$env:tmp\osquery.msi") {
                $fileInfo = Get-Item "$env:tmp\osquery.msi"
                if ($fileInfo.Length -gt 1000) {
                    Write-Host "Osquery download complete" -ForegroundColor Green
                    $downloadSuccess = $true
                } else {
                    Write-Host "Downloaded file is too small, might be incomplete" -ForegroundColor Yellow
                    Remove-Item -Path "$env:tmp\osquery.msi" -Force
                    $retryCount++
                    Start-Sleep -Seconds 5
                }
            }
        } catch {
            Write-Host "Download attempt failed: $_" -ForegroundColor Yellow
            $retryCount++
            Start-Sleep -Seconds 5
        }
    }
    
    if ($downloadSuccess) {
        # Install Osquery
        try {
            Write-Host "Installing Osquery..." -ForegroundColor Cyan
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$env:tmp\osquery.msi`" /q" -Wait -NoNewWindow
            
            if (Test-Path "C:\Program Files\osquery\osqueryd\osqueryd.exe") {
                Write-Host "[SUCCESS] Osquery installed!" -ForegroundColor Green
                
                # Create basic Osquery configuration
                $osqueryConfDir = "C:\Program Files\osquery\osquery.conf.d"
                if (-not (Test-Path -Path $osqueryConfDir)) {
                    New-Item -Path $osqueryConfDir -ItemType Directory -Force | Out-Null
                }
                
                $osqueryConfig = @'
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "schedule_default_interval": "3600"
  },
  "schedule": {
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
      "interval": 86400
    },
    "processes": {
      "query": "SELECT pid, name, path, cmdline FROM processes;",
      "interval": 600
    }
  }
}
'@
                $osqueryConfig | Out-File -FilePath "$osqueryConfDir\wazuh-osquery.conf" -Encoding UTF8
                Write-Host "Created basic Osquery configuration" -ForegroundColor Green
                
                # Try to start Osquery service
                try {
                    Start-Service -Name "osqueryd" -ErrorAction SilentlyContinue
                    Write-Host "Osquery service started" -ForegroundColor Green
                } catch {
                    Write-Host "Note: Could not start Osquery service automatically" -ForegroundColor Yellow
                    Write-Host "You may need to start it manually: Start-Service -Name osqueryd" -ForegroundColor Yellow
                }
            } else {
                Write-Host "[WARNING] Osquery installation could not be verified" -ForegroundColor Yellow
            }
            
            # Cleanup
            Remove-Item -Path "$env:tmp\osquery.msi" -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "Failed to install Osquery: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Failed to download Osquery after $maxRetries attempts" -ForegroundColor Red
    }
}

Write-Host "`n=============================================================" -ForegroundColor Cyan
Write-Host "                 INSTALLATION COMPLETE                      " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "`nHere's how to verify everything is working:" -ForegroundColor Yellow
Write-Host "1. Check agent status: " -NoNewline
Write-Host "Get-Service -Name WazuhSvc" -ForegroundColor Green
Write-Host "2. View agent logs: " -NoNewline
Write-Host "Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log'" -ForegroundColor Green
Write-Host "3. Test connection to manager: " -NoNewline
Write-Host "Test-NetConnection $managerIP -Port 1514" -ForegroundColor Green
Write-Host "4. Check if agent is registered: Look in the Wazuh manager UI" -ForegroundColor Green

if ($installOsquery -eq "y" -or $installOsquery -eq "Y") {
    Write-Host "`nOsquery commands:" -ForegroundColor Yellow
    Write-Host "1. Check Osquery status: " -NoNewline
    Write-Host "Get-Service -Name osqueryd" -ForegroundColor Green
    Write-Host "2. Run a query: " -NoNewline
    Write-Host "'C:\Program Files\osquery\osqueryd\osqueryd.exe' --json --config_path='C:\Program Files\osquery\osquery.conf.d' --query 'SELECT * FROM processes LIMIT 5'" -ForegroundColor Green
}

Write-Host "`nThank you for installing Wazuh!" -ForegroundColor Cyan