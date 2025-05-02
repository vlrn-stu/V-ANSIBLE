# Wazuh Agent with Osquery Installation Script for Windows
# Simple script to install Wazuh agent and Osquery on Windows

# Ensure the script is run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Please restart PowerShell as Administrator and try again." -ForegroundColor Red
    exit 1
}

# Configuration - MODIFY THESE VALUES
$WAZUH_MANAGER = "10.69.0.240"
$WAZUH_AGENT_GROUP = "Windows11"
$WAZUH_REGISTRATION_PASSWORD = "wazuh1234"
$WAZUH_AGENT_NAME = ""  # Leave empty to use hostname

# Set colors for output
$GREEN = [ConsoleColor]::Green
$BLUE = [ConsoleColor]::Cyan
$YELLOW = [ConsoleColor]::Yellow
$RED = [ConsoleColor]::Red

# Helper functions
function Write-Header {
    param([string]$text)
    Write-Host "`n=====================================================================" -ForegroundColor $BLUE
    Write-Host "    $text" -ForegroundColor $BLUE
    Write-Host "=====================================================================" -ForegroundColor $BLUE
}

function Write-Success {
    param([string]$text)
    Write-Host "[SUCCESS] $text" -ForegroundColor $GREEN
}

function Write-Info {
    param([string]$text)
    Write-Host "[INFO] $text" -ForegroundColor $YELLOW
}

function Write-Error {
    param([string]$text)
    Write-Host "[ERROR] $text" -ForegroundColor $RED
}

Write-Header "WAZUH AGENT INSTALLATION FOR WINDOWS"
Write-Info "Manager: $WAZUH_MANAGER"
Write-Info "Group: $WAZUH_AGENT_GROUP"

# Create temporary directory
Write-Header "CREATING TEMPORARY DIRECTORY"
$tempDir = "$env:TEMP\wazuh_install"
if (Test-Path $tempDir) {
    Remove-Item -Path $tempDir -Recurse -Force
}
New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
Write-Success "Temporary directory created at $tempDir"

# Download and install Wazuh agent
Write-Header "INSTALLING WAZUH AGENT"
$wazuhUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.5.2-1.msi"
$wazuhMsiPath = "$tempDir\wazuh-agent.msi"

Write-Info "Downloading Wazuh agent installer"
try {
    Invoke-WebRequest -Uri $wazuhUrl -OutFile $wazuhMsiPath
    Write-Success "Downloaded Wazuh agent installer"
} catch {
    Write-Error "Failed to download Wazuh agent: $_"
    exit 1
}

# Install Wazuh agent
Write-Info "Installing Wazuh agent"
try {
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$wazuhMsiPath`" /qn" -Wait
    Start-Sleep -Seconds 5
    
    if (Get-Service -Name "Wazuh" -ErrorAction SilentlyContinue) {
        Write-Success "Wazuh agent installed successfully"
    } else {
        Write-Error "Wazuh agent service not found after installation"
        exit 1
    }
} catch {
    Write-Error "Failed to install Wazuh agent: $_"
    exit 1
}

# Configure Wazuh agent
Write-Header "CONFIGURING WAZUH AGENT"
$wazuhConfig = "C:\Program Files (x86)\ossec-agent\ossec.conf"

# Update manager IP address in configuration
Write-Info "Updating Wazuh configuration with manager information"
try {
    $content = Get-Content -Path $wazuhConfig -Raw
    $content = $content -replace "<address>.*?</address>", "<address>$WAZUH_MANAGER</address>"
    $content | Set-Content -Path $wazuhConfig
    Write-Success "Updated manager address in configuration"
} catch {
    Write-Error "Failed to update Wazuh configuration: $_"
    exit 1
}

# Register agent with manager
Write-Info "Registering agent with Wazuh manager"
try {
    $registerPath = "C:\Program Files (x86)\ossec-agent\agent-auth.exe"
    $arguments = "-m $WAZUH_MANAGER -P $WAZUH_REGISTRATION_PASSWORD -G $WAZUH_AGENT_GROUP"
    
    if ($WAZUH_AGENT_NAME) {
        $arguments += " -A $WAZUH_AGENT_NAME"
    }
    
    Start-Process -FilePath $registerPath -ArgumentList $arguments -Wait -NoNewWindow
    Write-Success "Agent registered with manager"
} catch {
    Write-Error "Failed to register agent: $_"
    exit 1
}

# Download and install Osquery
Write-Header "INSTALLING OSQUERY"
$osqueryUrl = "https://pkg.osquery.io/windows/osquery-5.10.2.msi"
$osqueryMsiPath = "$tempDir\osquery.msi"

Write-Info "Downloading Osquery installer"
try {
    Invoke-WebRequest -Uri $osqueryUrl -OutFile $osqueryMsiPath
    Write-Success "Downloaded Osquery installer"
} catch {
    Write-Error "Failed to download Osquery: $_"
    exit 1
}

# Install Osquery
Write-Info "Installing Osquery"
try {
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$osqueryMsiPath`" /qn" -Wait
    Start-Sleep -Seconds 5
    
    if (Test-Path "C:\Program Files\osquery\osqueryd\osqueryd.exe") {
        Write-Success "Osquery installed successfully"
    } else {
        Write-Error "Osquery executable not found after installation"
        exit 1
    }
} catch {
    Write-Error "Failed to install Osquery: $_"
    exit 1
}

# Configure Osquery
Write-Header "CONFIGURING OSQUERY"
$osqueryConfDir = "C:\Program Files\osquery\osquery.conf.d"

if (-not (Test-Path -Path $osqueryConfDir)) {
    New-Item -Path $osqueryConfDir -ItemType Directory -Force | Out-Null
}

# Create basic Osquery configuration
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
    },
    "listening_ports": {
      "query": "SELECT pid, port, process.name FROM listening_ports JOIN processes AS process USING (pid) WHERE port > 0;",
      "interval": 600
    },
    "scheduled_tasks": {
      "query": "SELECT name, action, path, enabled, next_run_time FROM scheduled_tasks;",
      "interval": 1800
    },
    "startup_items": {
      "query": "SELECT name, path, source FROM startup_items;",
      "interval": 3600
    },
    "services": {
      "query": "SELECT name, path, service_type, status, start_type, user_account FROM services WHERE NOT (path LIKE 'C:\\Windows\\System32\\%');",
      "interval": 3600
    }
  }
}
'@
$osqueryConfig | Out-File -FilePath "$osqueryConfDir\wazuh-osquery.conf" -Encoding UTF8
Write-Success "Osquery configuration created"

# Create simple Osquery integration script
Write-Header "CREATING OSQUERY INTEGRATION"
$integrationDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"

if (-not (Test-Path -Path $integrationDir)) {
    New-Item -Path $integrationDir -ItemType Directory -Force | Out-Null
}

$osqueryScript = @'
# Osquery wrapper for Wazuh
$osqueryExe = "C:\Program Files\osquery\osqueryd\osqueryd.exe"
$queries = @(
    "SELECT name, path, pid FROM processes WHERE name LIKE '%powershell%' OR name LIKE '%cmd.exe%'",
    "SELECT name, path, status, start_type FROM services WHERE NOT (path LIKE 'C:\\Windows\\System32\\%')",
    "SELECT name, path FROM startup_items"
)

$results = @{
    osquery_data = @{
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        hostname = [System.Net.Dns]::GetHostName()
        results = @()
    }
}

foreach ($query in $queries) {
    try {
        $output = & $osqueryExe --json --query "$query" 2>$null
        $parsedOutput = $output | ConvertFrom-Json
        $results.osquery_data.results += @{
            query = $query
            data = $parsedOutput
        }
    } catch {
        # Skip errors
    }
}

$jsonResult = ConvertTo-Json -InputObject $results -Depth 10
Write-Output $jsonResult
'@
$osqueryScript | Out-File -FilePath "$integrationDir\osquery_wrapper.ps1" -Encoding UTF8
Write-Success "Osquery wrapper script created"

# Configure Wazuh integration with Osquery
Write-Header "CONFIGURING WAZUH OSQUERY INTEGRATION"

# Backup original configuration
Copy-Item -Path $wazuhConfig -Destination "$wazuhConfig.bak" -Force

# Load current configuration
$currentConfig = Get-Content -Path $wazuhConfig -Raw

# Add Osquery integration
$wodleXml = @"
  <wodle name="command">
    <disabled>no</disabled>
    <tag>osquery</tag>
    <command>powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\osquery_wrapper.ps1"</command>
    <interval>1h</interval>
    <run_on_start>yes</run_on_start>
    <timeout>300</timeout>
  </wodle>
"@

# Insert before </ossec_config>
$updatedConfig = $currentConfig -replace "</ossec_config>", "$wodleXml`r`n</ossec_config>"
$updatedConfig | Set-Content -Path $wazuhConfig -Encoding UTF8
Write-Success "Wazuh integration with Osquery configured"

# Start Wazuh agent service
Write-Header "STARTING SERVICES"
try {
    Restart-Service -Name "Wazuh" -Force
    Start-Sleep -Seconds 5
    
    $service = Get-Service -Name "Wazuh"
    if ($service.Status -eq "Running") {
        Write-Success "Wazuh agent service started successfully"
    } else {
        Write-Error "Failed to start Wazuh agent service"
        exit 1
    }
} catch {
    Write-Error "Error managing Wazuh service: $_"
    exit 1
}

try {
    if (Get-Service -Name "osqueryd" -ErrorAction SilentlyContinue) {
        Restart-Service -Name "osqueryd" -Force
    } else {
        Start-Process -FilePath "C:\Program Files\osquery\osqueryd\osqueryd.exe" -ArgumentList "--install" -Wait
        Start-Service -Name "osqueryd"
    }
    
    $service = Get-Service -Name "osqueryd"
    if ($service.Status -eq "Running") {
        Write-Success "Osquery service started successfully"
    } else {
        Write-Error "Failed to start Osquery service"
        exit 1
    }
} catch {
    Write-Error "Error managing Osquery service: $_"
    exit 1
}

# Display installation summary
Write-Header "INSTALLATION COMPLETE"
Write-Success "Wazuh agent installed and registered to group: $WAZUH_AGENT_GROUP"
Write-Success "Osquery installed and configured to send data hourly"
Write-Info "Manager IP: $WAZUH_MANAGER"

Write-Info "`nService Status:"
Get-Service -Name "Wazuh" | Select-Object Status | Format-Table
Get-Service -Name "osqueryd" | Select-Object Status | Format-Table

Write-Info "`nTo check Wazuh agent status: Get-Service -Name 'Wazuh'"
Write-Info "To view agent logs: Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log'"

# Cleanup
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue