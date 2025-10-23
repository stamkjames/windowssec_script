#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Automated script to run SFC, optionally DISM, and a Windows Defender Quick Scan.
    Designed for use cases where user interaction is not desired.

.DESCRIPTION
    Runs System File Checker (sfc /scannow).
    Optionally runs DISM RestoreHealth first if $RunDismFirst parameter below is set to $true.
    Runs a Windows Defender Quick Scan.
    Logs status messages to the console.

.NOTES
    Author: Gemini (Modified from User's Script)
    Date: October 24, 2025
    WARNING: Intended for automated execution. Using 'irm | iex' to run scripts
             from the internet is inherently risky. Ensure the source is trusted.
#>

[CmdletBinding()]
param(
    # --- Configuration ---
    # Set this to $true if you want DISM to run before SFC every time.
    [boolean]$RunDismFirst = $false,
    # Set this to $true to automatically open CBS.log if SFC finds unrepairable errors.
    [boolean]$OpenCbsLogOnFailure = $false
    # --- End Configuration ---
)

# Hardcoded Scan Type for automation
[string]$DefaultScanType = 'Quick'
[string[]]$DefaultScanPath = @() # Not used for Quick/Full scan

# --- Functions (Copied from your provided script) ---

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

function Invoke-DismRepair {
    Write-Status "Running DISM /Online /Cleanup-Image /RestoreHealth (this can take a while)..." 'Info'
    try {
        # Using Start-Process with explicit redirection and waiting
        $dismProcess = Start-Process dism.exe -ArgumentList '/Online', '/Cleanup-Image', '/RestoreHealth' -Wait -NoNewWindow -PassThru -RedirectStandardOutput "$env:TEMP\dism_output.log" -RedirectStandardError "$env:TEMP\dism_error.log"
        $dismOutput = Get-Content "$env:TEMP\dism_output.log" -Raw -ErrorAction SilentlyContinue
        $dismError = Get-Content "$env:TEMP\dism_error.log" -Raw -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\dism_output.log", "$env:TEMP\dism_error.log" -ErrorAction SilentlyContinue

        if ($dismProcess.ExitCode -ne 0) {
            Write-Status "DISM Error Output: $dismError" 'Error'
            throw "DISM returned exit code $($dismProcess.ExitCode)."
        }
        Write-Status "DISM completed successfully." 'Success'
        Write-Verbose "DISM Output: $dismOutput"
    } catch {
        Write-Status "DISM failed: $($_.Exception.Message)" 'Error'
        throw
    }
}

function Invoke-SfcScan {
    Write-Status "Running SFC /scannow (this can take a while)..." 'Info'
    $outFile = Join-Path $env:TEMP "sfc_output_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    try {
        # Using Start-Process for better control and exit code capture
        $sfcProcess = Start-Process sfc.exe -ArgumentList '/scannow' -Wait -NoNewWindow -PassThru -RedirectStandardOutput $outFile -RedirectStandardError "$env:TEMP\sfc_error.log"
        $output = Get-Content -Path $outFile -Raw -ErrorAction SilentlyContinue
        $sfcError = Get-Content "$env:TEMP\sfc_error.log" -Raw -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\sfc_error.log" -ErrorAction SilentlyContinue

        if ($null -ne $output) { Write-Verbose $output }
        if ($sfcProcess.ExitCode -ne 0) {
             Write-Status "SFC process exited with code $($sfcProcess.ExitCode). Error Output: $sfcError" 'Error'
             # Consider throwing an error or just reporting if exit code is non-zero but output parsing might still work
        }

        $status = 'Unknown'
        if ($output -match 'did not find any integrity violations') {
            $status = 'NoViolations'
            Write-Status "SFC result: No integrity violations found." 'Success'
        } elseif ($output -match 'found corrupt files and successfully repaired them') {
            $status = 'Repaired'
            Write-Status "SFC result: Corrupt files were found and repaired. A restart is recommended." 'Success'
        } elseif ($output -match 'found corrupt files but was unable to fix some of them') {
            $status = 'Unrepaired'
            Write-Status "SFC result: Some corrupt files could not be repaired. See CBS.log." 'Error'
        } else {
            Write-Status "SFC result: Scan completed. Review detailed output if needed ($outFile)." 'Warn'
        }

        if ($status -eq 'Unrepaired' -and $OpenCbsLogOnFailure) {
            $cbsLog = Join-Path $env:WinDir 'Logs\CBS\CBS.log' # Corrected path
            if (Test-Path $cbsLog) {
                Write-Status "Opening CBS.log ($cbsLog)..." 'Info'
                # Ensure Notepad path is correct or handle errors
                try {
                   Start-Process notepad.exe $cbsLog | Out-Null
                } catch {
                   Write-Status "Failed to open CBS.log with Notepad: $($_.Exception.Message)" 'Error'
                }
            } else {
                Write-Status "CBS.log not found at $cbsLog" 'Warn'
            }
        }

        [pscustomobject]@{
            Status     = $status
            OutputFile = $outFile # Keep the log file for reference
            ExitCode   = $sfcProcess.ExitCode
        }
    } catch {
        Write-Status "SFC failed: $($_.Exception.Message)" 'Error'
        # Clean up output file on error if it exists
        if (Test-Path $outFile) { Remove-Item $outFile -ErrorAction SilentlyContinue }
        throw
    }
}


function Test-DefenderAvailable {
    # Check if the service exists and is not disabled
    $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if ($defenderService -and $defenderService.StartType -ne [System.ServiceProcess.ServiceStartMode]::Disabled) {
        # Check if the module can be loaded (more reliable than Get-MpComputerStatus which might fail if service is stopped)
         if (Get-Module -ListAvailable -Name Defender) { return $true }
    }
    return $false
}


function Invoke-DefenderScan {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Quick','Full','Custom','None')]
        [string]$Type,
        [string[]]$Paths # Only relevant for Custom, but kept for signature consistency
    )

    if ($Type -eq 'None') { Write-Status "Skipping Microsoft Defender scan (ScanType=None)." 'Info'; return }

    if (-not (Test-DefenderAvailable)) {
        Write-Status "Microsoft Defender is unavailable or disabled. Unable to run scan." 'Warn'
        return
    }

    # Ensure Defender module is loaded for Start-MpScan
    Import-Module Defender -ErrorAction SilentlyContinue

    try {
         if ($Type -eq 'Quick') {
            Write-Status "Starting Microsoft Defender Quick scan..." 'Info'
            Start-MpScan -ScanType QuickScan -ErrorAction Stop
        }
        # Add Full/Custom logic here if needed for future modification, but keeping simple for now
        # elseif ($Type -eq 'Full') { ... }
        # elseif ($Type -eq 'Custom') { ... }
         else {
             Write-Status "Scan type '$Type' is configured but not explicitly handled in this automated version. Skipping." 'Warn'
             return
         }

        Write-Status "Microsoft Defender scan initiated. Review results in Windows Security or via Defender cmdlets." 'Success'
    } catch {
        Write-Status "Failed to start Defender scan: $($_.Exception.Message)" 'Error'
        # Consider specific error handling, e.g., if another scan is running
    }
}

# --- Main Script Execution ---
Write-Status "Automated system integrity and malware check starting..." 'Info'
$sfcResult = $null
$ErrorOccurred = $false

try {
    if ($RunDismFirst) {
        Invoke-DismRepair
    } else {
        Write-Verbose "Skipping DISM as RunDismFirst is set to false."
    }

    $sfcResult = Invoke-SfcScan

    # Check SFC status before proceeding (optional, could stop if SFC failed badly)
    if ($sfcResult -and $sfcResult.Status -eq 'Unrepaired') {
        Write-Status "SFC found unrepaired errors. Continuing with Defender scan, but system issues may persist." 'Warn'
    }

    Invoke-DefenderScan -Type $DefaultScanType #-Paths $DefaultScanPath # Paths not needed for Quick

} catch {
    # Catch errors from DISM or SFC functions
    Write-Status "Script terminated during repair phase with error: $($_.Exception.Message)" 'Error'
    $ErrorOccurred = $true
    # Consider specific exit codes based on where it failed
    # exit 1 # Exit immediately on critical failure
}

# Final Status Message
if ($ErrorOccurred) {
    Write-Status "Script finished with errors." 'Error'
    # Optional: Exit with non-zero code for automation checking
    # exit 1
} else {
    $sfcStatusMsg = if ($sfcResult) { "SFC Status=$($sfcResult.Status). SFC Output=$($sfcResult.OutputFile)" } else { "SFC did not run or failed to return status."}
    Write-Status "Automated check completed. $sfcStatusMsg" 'Success'
    # Optional: Clean up SFC output file if successful and not needed
    # if ($sfcResult -and $sfcResult.Status -ne 'Unrepaired') { Remove-Item $sfcResult.OutputFile -ErrorAction SilentlyContinue }
}

# Keep console open briefly if run directly? Optional.
# Start-Sleep -Seconds 5
