#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Automated script to initiate a Windows Defender Quick Scan for malware detection.

.DESCRIPTION
    Checks if Microsoft Defender is available and then initiates a Quick Scan using Start-MpScan.
    Detected threats are handled automatically by Windows Defender based on its configured settings
    (typically includes quarantining). Does not provide user choice for scan type.

.NOTES
    Author: Gemini (Modified from User's Script)
    Date: October 24, 2025
    Compatibility: Windows 10 and Windows 11
    WARNING: Intended for automated execution. Using 'irm | iex' to run scripts
             from the internet is inherently risky. Ensure the source is trusted.
             Progress must be monitored via Windows Security Center.
#>

[CmdletBinding()]
param() # No parameters needed for this automated version

# --- Functions ---

function Write-Status {
    param([string]$Message, [ValidateSet('Info','Warn','Error','Success')]$Level = 'Info')
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    switch ($Level) {
        'Info'    { Write-Host "[$timestamp] [INFO]    $Message" -ForegroundColor Cyan }
        'Warn'    { Write-Host "[$timestamp] [WARN]    $Message" -ForegroundColor Yellow }
        'Error'   { Write-Host "[$timestamp] [ERROR]   $Message" -ForegroundColor Red }
        'Success' { Write-Host "[$timestamp] [SUCCESS] $Message" -ForegroundColor Green }
    }
}

function Test-DefenderAvailable {
    # Check if the service exists and is not disabled
    $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if ($defenderService -and $defenderService.StartType -ne [System.ServiceProcess.ServiceStartMode]::Disabled) {
        # Check if the module can be loaded
         if (Get-Module -ListAvailable -Name Defender) { return $true }
    }
    return $false
}

function Invoke-DefenderQuickScan {
    Write-Status "Checking Microsoft Defender availability..." 'Info'

    if (-not (Test-DefenderAvailable)) {
        Write-Status "Microsoft Defender is unavailable or disabled. Unable to run scan." 'Error'
        # Throw an error to stop the script if Defender is not usable
        throw "Microsoft Defender service (WinDefend) is not running or the PowerShell module is missing."
    }

    Write-Status "Microsoft Defender is available." 'Info'

    # Ensure Defender module is loaded for Start-MpScan
    Import-Module Defender -ErrorAction SilentlyContinue
    if (-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) {
         throw "Start-MpScan command not found even though Defender module seems present. Update PowerShell or check Defender installation."
    }

    try {
        Write-Status "Starting Microsoft Defender Quick scan..." 'Info'
        Write-Host "Please monitor scan progress and results in the Windows Security Center." -ForegroundColor Yellow

        # Initiate the Quick Scan
        Start-MpScan -ScanType QuickScan -ErrorAction Stop

        # Note: Start-MpScan typically returns immediately after starting the scan process.
        # The actual scan runs in the background managed by the Defender service.

        Write-Status "Microsoft Defender Quick Scan initiated successfully." 'Success'
        Write-Status "Detected threats will be handled automatically (e.g., quarantined) based on Windows Security settings." 'Info'
        Write-Status "Review results in Windows Security > Virus & threat protection > Protection history." 'Info'

    } catch {
        Write-Status "Failed to start Defender Quick Scan: $($_.Exception.Message)" 'Error'
        # Re-throw the error to indicate script failure
        throw
    }
}

# --- Main Script Execution ---
Write-Status "Automated malware check starting..." 'Info'
$ErrorOccurred = $false

try {
    Invoke-DefenderQuickScan
} catch {
    # Catch errors from the scan function
    Write-Status "Script terminated with error: $($_.Exception.Message)" 'Error'
    $ErrorOccurred = $true
}

# Final Status Message
if ($ErrorOccurred) {
    Write-Status "Script finished with errors." 'Error'
    # Optional: Exit with non-zero code for automation checking
    # exit 1
} else {
    Write-Status "Automated check script completed initiation." 'Success'
}

# Keep console open briefly if run directly? Optional for debugging.
# Start-Sleep -Seconds 10
