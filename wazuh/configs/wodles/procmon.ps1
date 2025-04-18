# Process Monitor Script for Wazuh on Windows 11 Pro
# Save this as C:\Program Files (x86)\ossec-agent\active-response\bin\procmon.ps1

# Get all running processes with enhanced details for Windows 11
$processes = Get-Process | Select-Object Id, ProcessName, Path, Company, Product, Description, @{Name="CPU";Expression={$_.CPU}}, @{Name="Memory";Expression={[math]::Round($_.WorkingSet / 1MB, 2)}}, Handles, StartTime

$result = @{
    "processes" = @()
    "timestamp" = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "hostname" = $env:COMPUTERNAME
}

foreach ($proc in $processes) {
    try {
        # Get command line arguments (requires admin rights)
        $cmdLine = $null
        try {
            $cmdLine = (Get-WmiObject -Class Win32_Process -Filter "ProcessId = '$($proc.Id)'").CommandLine
        } catch {
            # Command line retrieval requires elevation
        }
        
        $processInfo = @{
            "pid" = $proc.Id
            "name" = $proc.ProcessName
            "path" = if ($proc.Path) { $proc.Path } else { "N/A" }
            "company" = if ($proc.Company) { $proc.Company } else { "N/A" }
            "product" = if ($proc.Product) { $proc.Product } else { "N/A" }
            "description" = if ($proc.Description) { $proc.Description } else { "N/A" }
            "cpu" = if ($proc.CPU) { $proc.CPU } else { 0 }
            "memory" = $proc.Memory
            "handles" = $proc.Handles
            "commandLine" = if ($cmdLine) { $cmdLine } else { "N/A" }
            "start_time" = if ($proc.StartTime) { Get-Date $proc.StartTime -Format "yyyy-MM-dd HH:mm:ss" } else { "N/A" }
        }
        $result.processes += $processInfo
    } catch {
        # Skip processes that cause errors
    }
}

# Check for suspicious processes
$suspiciousPathPatterns = @(
    "\\Temp\\", 
    "\\Windows\\Temp\\", 
    "\\AppData\\Local\\Temp\\",
    "\\Users\\Public\\",
    "\\ProgramData\\^(?!Microsoft|Windows)"
)
$suspiciousNamePatterns = @(
    "^[a-zA-Z0-9]{16}$", 
    "^[0-9]{8}$", 
    "^svchost\d+$",
    "^scvhost\.exe$", # Typosquatting
    "^lsass\d*\.exe$",
    "^svch0st\.exe$",
    "^powershell\.com$"
)

foreach ($proc in $result.processes) {
    $isSuspicious = $false
    $suspiciousReasons = @()
    
    # Check suspicious paths
    foreach ($pattern in $suspiciousPathPatterns) {
        if ($proc.path -match $pattern) {
            $isSuspicious = $true
            $suspiciousReasons += "Suspicious path: $pattern"
        }
    }
    
    # Check suspicious names
    foreach ($pattern in $suspiciousNamePatterns) {
        if ($proc.name -match $pattern) {
            $isSuspicious = $true
            $suspiciousReasons += "Suspicious name pattern: $pattern"
        }
    }
    
    # Check for unsigned executables in Program Files
    if ($proc.path -match "C:\\Program Files" -and $proc.company -eq "N/A") {
        $isSuspicious = $true
        $suspiciousReasons += "Unsigned executable in Program Files"
    }
    
    if ($isSuspicious) {
        $proc["suspicious"] = $true
        $proc["suspiciousReasons"] = $suspiciousReasons
    } else {
        $proc["suspicious"] = $false
    }
}

$jsonResult = $result | ConvertTo-Json -Depth 4 -Compress
Write-Output $jsonResult