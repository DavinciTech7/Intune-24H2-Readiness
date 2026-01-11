<#
.SYNOPSIS
  Intune Proactive Remediations - Windows 11 24H2 Update Services Fix (Remediation)

.PURPOSE
  Ensures essential Windows Update–related services required for Windows 11 24H2 upgrade
  are correctly configured and running:
    - Windows Update (wuauserv)
    - Background Intelligent Transfer Service (BITS)
    - Cryptographic Services (cryptsvc)

.BEHAVIOR
  - Verifies service existence.
  - Sets startup type to Manual (or keeps Automatic/DelayedAuto).
  - Starts stopped services.
  - Logs all actions and errors.

.OUTPUT / EXIT CODES (Intune PR Remediation)
  - Exit 0 = remediation completed (best effort) with no fatal errors.
  - Exit 1 = remediation failed for one or more required services.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -------------------------
# Logging
# -------------------------
$LogRoot = 'C:\Temp\24H2_UpdateServices_Remediation'
try {
    if (-not (Test-Path -LiteralPath $LogRoot)) {
        New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
    }
} catch { }

$LogStamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile   = Join-Path $LogRoot "24H2_UpdateServices_Remediation_$LogStamp.log"

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Message
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] $Message"
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
}

Write-Log "=== Windows 11 24H2 Update Services Remediation ==="
Write-Log "Target services:"
Write-Log " - wuauserv  (Windows Update)"
Write-Log " - bits      (Background Intelligent Transfer Service)"
Write-Log " - cryptsvc  (Cryptographic Services)"
Write-Log ""

# -------------------------
# Helper
# -------------------------
function Ensure-ServiceHealthy {
    param(
        [Parameter(Mandatory=$true)][string]$ServiceName,
        [Parameter(Mandatory=$true)][string]$DisplayName
    )

    $result = [PSCustomObject]@{
        ServiceName  = $ServiceName
        DisplayName  = $DisplayName
        Exists       = $false
        StartupFixed = $false
        Started      = $false
        Error        = $null
    }

    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction Stop
        $result.Exists = $true
        Write-Log "[$ServiceName] Found service: Status=$($svc.Status), StartType=$((Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'").StartMode)"

        # Ensure startup type is at least Manual
        try {
            $svcWmi = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
            $currentStartMode = $svcWmi.StartMode # e.g. Auto, Manual, Disabled

            if ($currentStartMode -eq 'Disabled') {
                Write-Log "[$ServiceName] StartMode is Disabled. Changing to Manual."
                $changeResult = $svcWmi.ChangeStartMode('Manual')
                if ($changeResult.ReturnValue -eq 0) {
                    $result.StartupFixed = $true
                    Write-Log "[$ServiceName] StartMode successfully changed to Manual."
                } else {
                    $result.Error = "Failed to change StartMode to Manual. WMI return code: $($changeResult.ReturnValue)"
                    Write-Log "[$ServiceName] ERROR: $($result.Error)"
                }
            } else {
                Write-Log "[$ServiceName] StartMode is acceptable ($currentStartMode). No change required."
            }
        } catch {
            $result.Error = "Error while inspecting/changing StartMode: $($_.Exception.Message)"
            Write-Log "[$ServiceName] ERROR: $($result.Error)"
        }

        # Ensure service is running
        $svc.Refresh()
        if ($svc.Status -ne 'Running') {
            Write-Log "[$ServiceName] Service is not running (current Status=$($svc.Status)). Attempting to start..."
            try {
                Start-Service -Name $ServiceName -ErrorAction Stop
                Start-Sleep -Seconds 3
                $svc.Refresh()
                if ($svc.Status -eq 'Running') {
                    $result.Started = $true
                    Write-Log "[$ServiceName] Service successfully started."
                } else {
                    $result.Error = "Service failed to reach 'Running' state after Start-Service (Status=$($svc.Status))."
                    Write-Log "[$ServiceName] ERROR: $($result.Error)"
                }
            } catch {
                $result.Error = "Start-Service failed: $($_.Exception.Message)"
                Write-Log "[$ServiceName] ERROR: $($result.Error)"
            }
        } else {
            Write-Log "[$ServiceName] Service already running. No start required."
        }
    } catch {
        $result.Error = "Service not found or Get-Service failed: $($_.Exception.Message)"
        Write-Log "[$ServiceName] ERROR: $($result.Error)"
    }

    return $result
}

# -------------------------
# Process required services
# -------------------------
$targets = @(
    @{ Name = 'wuauserv'; DisplayName = 'Windows Update' },
    @{ Name = 'bits';     DisplayName = 'Background Intelligent Transfer Service' },
    @{ Name = 'cryptsvc'; DisplayName = 'Cryptographic Services' }
)

$results = @()
foreach ($t in $targets) {
    $results += (Ensure-ServiceHealthy -ServiceName $t.Name -DisplayName $t.DisplayName)
}

Write-Log ""
Write-Log "=== Summary ==="
$overallSuccess = $true

foreach ($r in $results) {
    $msg = "Service=$($r.ServiceName); Exists=$($r.Exists); StartupFixed=$($r.StartupFixed); Started=$($r.Started); Error=$($r.Error)"
    Write-Log $msg
    if (-not $r.Exists -or ($r.Error)) {
        $overallSuccess = $false
    }
}

if ($overallSuccess) {
    Write-Log "FINAL RESULT: Remediation completed successfully for all targeted services."
    exit 0
} else {
    Write-Log "FINAL RESULT: Remediation encountered one or more errors. Review log for details."
    exit 1
}
