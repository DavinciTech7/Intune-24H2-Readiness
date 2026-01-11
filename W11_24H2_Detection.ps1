<# 
.SYNOPSIS
  Intune Proactive Remediations - Windows 11 24H2 Readiness (Detection - STRICT, NO FALSE POSITIVES)

.PURPOSE
  Validates device readiness for Windows 11 24H2 upgrade with a strong bias toward avoiding false positives.
  "Compliant" is returned only when requirements are clearly and consistently proven from reliable sources.

.SCOPE / CONSTRAINTS
  - Read-only with respect to system configuration: NO registry writes, NO service changes, NO policy changes.
  - Allowed side effects: create log folder + write log file only.
  - If a requirement cannot be reliably proven OR data is conflicting => FAIL that check (avoid false positives).

.OUTPUT / EXIT CODES (Intune PR)
  - Writes exactly one line to STDOUT: "Compliant" or "NonCompliant"
  - Exit 0 = compliant, Exit 1 = noncompliant
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -------------------------
# Logging
# -------------------------
$LogRoot = 'C:\Temp\24H2_Detection_Readiness'
try {
    if (-not (Test-Path -LiteralPath $LogRoot)) {
        New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
    }
} catch { }

$LogStamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile   = Join-Path $LogRoot "24H2_Readiness_Detection_$LogStamp.log"

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Message
    )
    $lineTs = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $line = "[$lineTs] $Message"
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
}

# -------------------------
# Helpers
# -------------------------
function Mark-Result {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][bool]$Pass,
        [Parameter(Mandatory=$true)][string]$Detail
    )
    [PSCustomObject]@{ Name=$Name; Pass=$Pass; Detail=$Detail }
}

function Safe-GetCimInstance {
    param(
        [Parameter(Mandatory=$true)][string]$ClassName,
        [string]$Namespace = 'root\cimv2',
        [string]$Filter
    )
    try {
        if ($PSBoundParameters.ContainsKey('Filter') -and $Filter) {
            Get-CimInstance -Namespace $Namespace -ClassName $ClassName -Filter $Filter -ErrorAction Stop
        } else {
            Get-CimInstance -Namespace $Namespace -ClassName $ClassName -ErrorAction Stop
        }
    } catch { $null }
}

# -------------------------
# Header (timestamped baseline)
# -------------------------
Write-Log "=== Windows 11 24H2 Readiness Detection (STRICT, NO FALSE POSITIVES) ==="
Write-Log "Requirements Baseline:"
Write-Log "- Processor: 1 GHz or faster, 64-bit, dual-core minimum"
Write-Log "- RAM: ≥ 4 GB"
Write-Log "- Storage: ≥ 64 GB"
Write-Log "- System Firmware: UEFI with Secure Boot enabled"
Write-Log "- TPM: Version 2.0 present and ready"
Write-Log "- Graphics: DirectX 12+ with WDDM 2.0 driver"
Write-Log "- Display: HD (720p), > 9"" diagonal, 8-bit color"
Write-Log ""
Write-Log "=== Current System State (Snapshot) ==="

# -------------------------
# Snapshot (informational)
# -------------------------
try {
    $os   = Safe-GetCimInstance -ClassName Win32_OperatingSystem
    $cs   = Safe-GetCimInstance -ClassName Win32_ComputerSystem
    $bios = Safe-GetCimInstance -ClassName Win32_BIOS
    $cpu  = Safe-GetCimInstance -ClassName Win32_Processor

    if ($os)   { Write-Log ("OS: {0} (Build {1})" -f $os.Caption, $os.BuildNumber) }
    if ($cs)   { Write-Log ("Manufacturer/Model: {0} / {1}" -f $cs.Manufacturer, $cs.Model) }
    if ($bios) { Write-Log ("BIOS Version: {0}" -f ($bios.SMBIOSBIOSVersion -join ', ')) }
    if ($cpu)  { Write-Log ("CPU: {0}" -f (($cpu | Select-Object -First 1).Name)) }
} catch {
    Write-Log ("Snapshot error: {0}" -f $_.Exception.Message)
}

Write-Log ""
Write-Log "=== Requirement Checks (PASS/FAIL) ==="

$results = New-Object System.Collections.Generic.List[object]

# -------------------------
# 1) CPU
# -------------------------
$cpuPass = $false
$cpuDetail = "Unknown"
try {
    $cpu = Safe-GetCimInstance -ClassName Win32_Processor
    if ($cpu) {
        $c = $cpu | Select-Object -First 1
        $mhz = $c.MaxClockSpeed
        if (-not $mhz) { $mhz = $c.CurrentClockSpeed }

        # Sanity: discard obviously bogus values
        if ($mhz -and $mhz -gt 0 -and $mhz -lt 100000) {
            $ghz = [Math]::Round(($mhz / 1000), 2)
        } else {
            $ghz = $null
        }

        $cores   = $c.NumberOfCores
        $logical = $c.NumberOfLogicalProcessors
        $addrW   = $c.AddressWidth

        $freqOk = ($ghz -ne $null -and $ghz -ge 1.0)
        $coreOk = ($cores -ne $null -and [int]$cores -ge 2)
        $bitOk  = ($addrW -eq 64)

        # Inconsistency check: if any key field is null or clearly bogus, fail to avoid false positives
        $dataComplete = $freqOk -and $coreOk -and $bitOk

        $cpuPass = $dataComplete
        $cpuDetail = "GHz=$ghz; Cores=$cores; Logical=$logical; CPUAddressWidth=$addrW; DataComplete=$dataComplete"
    } else {
        $cpuDetail = "Win32_Processor unavailable"
    }
} catch {
    $cpuPass = $false
    $cpuDetail = "Error: $($_.Exception.Message)"
}
$results.Add((Mark-Result -Name "CPU" -Pass $cpuPass -Detail $cpuDetail)) | Out-Null
Write-Log ("CPU: {0} - {1}" -f ($(if($cpuPass){"PASS"}else{"FAIL"})), $cpuDetail)

# -------------------------
# 2) RAM
# -------------------------
$ramPass = $false
$ramDetail = "Unknown"
try {
    $cs = Safe-GetCimInstance -ClassName Win32_ComputerSystem
    if ($cs -and $cs.TotalPhysicalMemory) {
        $ramGB = [Math]::Round(($cs.TotalPhysicalMemory / 1GB), 2)

        # Sanity: discard nonsense values
        if ($ramGB -le 0 -or $ramGB -gt 4096) {
            $ramDetail = "TotalPhysicalMemoryGB=$ramGB (invalid range)"
            $ramPass = $false
        } else {
            $ramPass = ($ramGB -ge 4)
            $ramDetail = "TotalPhysicalMemoryGB=$ramGB"
        }
    } else {
        $ramDetail = "TotalPhysicalMemory unavailable"
    }
} catch {
    $ramPass = $false
    $ramDetail = "Error: $($_.Exception.Message)"
}
$results.Add((Mark-Result -Name "RAM" -Pass $ramPass -Detail $ramDetail)) | Out-Null
Write-Log ("RAM: {0} - {1}" -f ($(if($ramPass){"PASS"}else{"FAIL"})), $ramDetail)

# -------------------------
# 3) Storage (system drive total)
# -------------------------
$storagePass = $false
$storageDetail = "Unknown"
try {
    $systemDrive = $env:SystemDrive
    if (-not $systemDrive) { $systemDrive = "C:" }

    $ld = Safe-GetCimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $systemDrive)
    if ($ld -and $ld.Size) {
        $sizeGB = [Math]::Round(($ld.Size / 1GB), 2)
        $freeGB = if ($ld.FreeSpace) { [Math]::Round(($ld.FreeSpace / 1GB), 2) } else { $null }

        # Sanity: ignore impossible sizes
        if ($sizeGB -le 0 -or $sizeGB -gt 32768) {
            $storagePass = $false
            $storageDetail = "SystemDrive=$systemDrive; SizeGB=$sizeGB (invalid range); FreeGB=$freeGB"
        } else {
            $storagePass = ($sizeGB -ge 64)
            $storageDetail = "SystemDrive=$systemDrive; SizeGB=$sizeGB; FreeGB=$freeGB"
        }
    } else {
        $storageDetail = "Win32_LogicalDisk size unavailable for $systemDrive"
    }
} catch {
    $storagePass = $false
    $storageDetail = "Error: $($_.Exception.Message)"
}
$results.Add((Mark-Result -Name "Storage" -Pass $storagePass -Detail $storageDetail)) | Out-Null
Write-Log ("Storage: {0} - {1}" -f ($(if($storagePass){"PASS"}else{"FAIL"})), $storageDetail)

# -------------------------
# 4) Firmware: UEFI + Secure Boot (STRICT, multi-source, no false positives)
# -------------------------
$uefi = $false
$secureBootEnabled = $false
$firmwareProof = @()
$uefiEvidence = @()
$legacyEvidence = @()

# A) Registry proof (if available)
try {
    $pe = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -ErrorAction Stop
    if ($pe.PSObject.Properties.Name -contains "PEFirmwareType") {
        $val = $pe.PEFirmwareType
        if ($val -eq 2) { $uefiEvidence += "PEFirmwareType=2" }
        elseif ($val -eq 1) { $legacyEvidence += "PEFirmwareType=1" }
        else { $firmwareProof += "PEFirmwareType=$val (unrecognized)" }
    } else {
        $firmwareProof += "PEFirmwareType missing"
    }
} catch {
    $firmwareProof += "Registry read failed: $($_.Exception.Message)"
}

# B) BCD proof
try {
    $bcd = bcdedit /enum "{current}" 2>$null
    if ($bcd) {
        if ($bcd -match 'winload\.efi' -or $bcd -match '\\EFI\\') {
            $uefiEvidence += "BCD winload.efi/EFI path"
        } elseif ($bcd -match 'winload\.exe') {
            $legacyEvidence += "BCD winload.exe"
        } else {
            $firmwareProof += "BCD could not prove UEFI/Legacy"
        }
    } else {
        $firmwareProof += "BCD returned no output"
    }
} catch {
    $firmwareProof += "BCD failed: $($_.Exception.Message)"
}

# Determine UEFI / Legacy with conflict awareness
if ($uefiEvidence.Count -gt 0 -and $legacyEvidence.Count -eq 0) {
    $uefi = $true
} elseif ($legacyEvidence.Count -gt 0 -and $uefiEvidence.Count -eq 0) {
    $uefi = $false
    $firmwareProof += "Evidence clearly indicates Legacy BIOS"
} elseif ($uefiEvidence.Count -eq 0 -and $legacyEvidence.Count -eq 0) {
    $uefi = $false
    $firmwareProof += "No clear UEFI or Legacy evidence"
} else {
    # Conflicting evidence: treat as NOT proven UEFI to avoid false positive
    $uefi = $false
    $firmwareProof += "Conflicting firmware evidence: UEFIEvidence=[$($uefiEvidence -join ',')], LegacyEvidence=[$($legacyEvidence -join ',')]"
}

# Secure Boot (must be TRUE, explicit)
try {
    $sbResult = $null
    $sbError  = $null
    try {
        $sbResult = Confirm-SecureBootUEFI
    } catch {
        $sbError = $_.Exception.Message
    }

    if ($sbResult -is [bool]) {
        $secureBootEnabled = [bool]$sbResult
        $firmwareProof += "SecureBootExplicit=$secureBootEnabled"
    } elseif ($sbError) {
        # Cmdlet not supported / BIOS mode => no secure boot; avoid guessing
        $secureBootEnabled = $false
        $firmwareProof += "Confirm-SecureBootUEFI failed: $sbError"
    } else {
        $secureBootEnabled = $false
        $firmwareProof += "Confirm-SecureBootUEFI returned unexpected output"
    }
} catch {
    $secureBootEnabled = $false
    $firmwareProof += "Secure Boot check outer exception: $($_.Exception.Message)"
}

$firmwarePass = ($uefi -and $secureBootEnabled)
$firmwareDetail = "UEFI=$uefi; SecureBootEnabled=$secureBootEnabled; UEFIEvidence=[$($uefiEvidence -join '; ')]; LegacyEvidence=[$($legacyEvidence -join '; ')]; Proof=[$($firmwareProof -join '; ')]"
$results.Add((Mark-Result -Name "Firmware (UEFI + Secure Boot)" -Pass $firmwarePass -Detail $firmwareDetail)) | Out-Null
Write-Log ("Firmware: {0} - {1}" -f ($(if($firmwarePass){"PASS"}else{"FAIL"})), $firmwareDetail)

# -------------------------
# 5) TPM: 2.0 present and ready (strict, multi-source, no false positives)
# -------------------------
$tpmPass = $false
$tpmDetail = "Unknown"
try {
    $tpmPs  = $null
    $tpmWmi = $null
    try { $tpmPs  = Get-Tpm -ErrorAction Stop } catch { $tpmPs = $null }
    try { $tpmWmi = Safe-GetCimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName 'Win32_Tpm' } catch { $tpmWmi = $null }

    if ($tpmPs -or $tpmWmi) {
        $present   = $false
        $enabled   = $false
        $activated = $false
        $owned     = $null
        $specVersion = $null

        if ($tpmPs) {
            $present   = [bool]$tpmPs.TpmPresent
            $enabled   = [bool]$tpmPs.TpmEnabled
            $activated = [bool]$tpmPs.TpmActivated
            $owned     = $tpmPs.TpmOwned
        }

        if ($tpmWmi -and ($tpmWmi | Measure-Object).Count -gt 0) {
            $w = $tpmWmi | Select-Object -First 1
            if ($w.PSObject.Properties.Name -contains 'SpecVersion') {
                $specVersion = $w.SpecVersion
            }
        }

        $ready = ($present -and $enabled -and $activated)

        # TPM 2.0 proof: SpecVersion must clearly contain "2.0"
        $is2 = $false
        if ($specVersion -and ($specVersion -match '2\.0')) { $is2 = $true }

        # No TPM PASS unless both "ready" and version 2.0 are clearly proven
        $dataComplete = ($ready -and $is2)

        $tpmPass = $dataComplete
        $tpmDetail = "Present=$present; Enabled=$enabled; Activated=$activated; Owned=$owned; SpecVersion=$specVersion; DataComplete=$dataComplete"
    } else {
        $tpmDetail = "TPM information unavailable from both Get-Tpm and Win32_Tpm"
    }
} catch {
    $tpmPass = $false
    $tpmDetail = "Error: $($_.Exception.Message)"
}
$results.Add((Mark-Result -Name "TPM 2.0 (present + ready)" -Pass $tpmPass -Detail $tpmDetail)) | Out-Null
Write-Log ("TPM: {0} - {1}" -f ($(if($tpmPass){"PASS"}else{"FAIL"})), $tpmDetail)

# -------------------------
# 6) Graphics: DirectX 12+ and WDDM 2.0+ (strict, with sanity checks)
# -------------------------
$gfxPass = $false
$gfxDetail = "Unknown"
try {
    $tempDx = Join-Path $env:TEMP "dxdiag_$LogStamp.xml"
    $dxVersion = $null
    $wddmVersion = $null

    try {
        $dxdiagExe = Join-Path $env:SystemRoot "System32\dxdiag.exe"
        if (Test-Path -LiteralPath $dxdiagExe) {
            # Use XML output for more stable parsing [web:35]
            $p = Start-Process -FilePath $dxdiagExe -ArgumentList "/x `"$tempDx`"" -PassThru -NoNewWindow -ErrorAction Stop
            $p.WaitForExit(20000) | Out-Null

            if (Test-Path -LiteralPath $tempDx) {
                [xml]$xml = Get-Content -LiteralPath $tempDx -ErrorAction Stop

                # System tab: DirectXVersion
                $systemNode = $xml.DxDiag.SystemInformation
                if ($systemNode -and $systemNode.DirectXVersion) {
                    if ($systemNode.DirectXVersion -match 'DirectX\s*(\d+)') {
                        $dxVersion = [int]$Matches[1]
                    }
                }

                # Display tab(s): DriverModel (e.g., "WDDM 3.0")
                $displayNodes = $xml.DxDiag.DisplayDevices.DisplayDevice
                if (-not $displayNodes) { $displayNodes = @($xml.DxDiag.DisplayDevices.DisplayDevice) }

                foreach ($node in $displayNodes) {
                    if ($node.DriverModel -and $node.DriverModel -match 'WDDM\s*([0-9]+(\.[0-9]+)?)') {
                        $candidate = [double]$Matches[1]
                        if ($wddmVersion -eq $null -or $candidate -gt $wddmVersion) {
                            $wddmVersion = $candidate
                        }
                    }
                }
            }
        }
    } catch {
        Write-Log ("DxDiag collection error: {0}" -f $_.Exception.Message)
    }

    $dxOk   = ($dxVersion -ne $null -and $dxVersion -ge 12)
    $wddmOk = ($wddmVersion -ne $null -and $wddmVersion -ge 2.0)

    $dataComplete = ($dxOk -and $wddmOk)
    $gfxPass = $dataComplete
    $gfxDetail = "DirectX=$dxVersion; WDDM=$wddmVersion; DataComplete=$dataComplete; DxDiagFile=$tempDx"
} catch {
    $gfxPass = $false
    $gfxDetail = "Error: $($_.Exception.Message)"
}
$results.Add((Mark-Result -Name "Graphics (DirectX 12+ & WDDM 2.0+)" -Pass $gfxPass -Detail $gfxDetail)) | Out-Null
Write-Log ("Graphics: {0} - {1}" -f ($(if($gfxPass){"PASS"}else{"FAIL"})), $gfxDetail)

# -------------------------
# 7) Display: >= 720p, > 9", 8-bit color (strict, EDID sanity)
# -------------------------
$dispPass = $false
$dispDetail = "Unknown"
try {
    $vc = Safe-GetCimInstance -ClassName Win32_VideoController
    $hRes = $null
    $vRes = $null
    $bpp  = $null

    if ($vc) {
        $vc0 = $vc | Sort-Object -Property CurrentHorizontalResolution -Descending | Select-Object -First 1
        if ($vc0.PSObject.Properties.Name -contains 'CurrentHorizontalResolution') { $hRes = $vc0.CurrentHorizontalResolution }
        if ($vc0.PSObject.Properties.Name -contains 'CurrentVerticalResolution') { $vRes = $vc0.CurrentVerticalResolution }
        if ($vc0.PSObject.Properties.Name -contains 'CurrentBitsPerPixel') { $bpp = $vc0.CurrentBitsPerPixel }
    }

    $diagIn = $null
    $edid = Safe-GetCimInstance -Namespace 'root\wmi' -ClassName 'WmiMonitorBasicDisplayParams'
    if ($edid) {
        $m = $edid | Where-Object { $_.Active -eq $true } | Select-Object -First 1
        if (-not $m) { $m = $edid | Select-Object -First 1 }

        if ($m) {
            $hCm = $m.MaxHorizontalImageSize
            $vCm = $m.MaxVerticalImageSize

            # Sanity: per MS docs, zeros mean "unknown" – treat as no proof, not a small screen. [web:24]
            if ($hCm -and $vCm -and $hCm -gt 0 -and $vCm -gt 0) {
                $diagCm = [Math]::Sqrt(([double]$hCm * [double]$hCm) + ([double]$vCm * [double]$vCm))
                $diagIn = [Math]::Round(($diagCm / 2.54), 2)
            } else {
                $diagIn = $null
            }
        }
    }

    $resOk  = ($hRes -ne $null -and $vRes -ne $null -and [int]$vRes -ge 720)
    $diagOk = ($diagIn -ne $null -and [double]$diagIn -gt 9.0)
    $bppOk  = ($bpp -ne $null -and [int]$bpp -ge 24)

    $dataComplete = ($resOk -and $diagOk -and $bppOk)

    $dispPass = $dataComplete
    $dispDetail = "Resolution=${hRes}x${vRes}; DiagonalIn=$diagIn; BitsPerPixel=$bpp; DataComplete=$dataComplete"
} catch {
    $dispPass = $false
    $dispDetail = "Error: $($_.Exception.Message)"
}
$results.Add((Mark-Result -Name "Display (>=720p, >9in, 8-bit+)" -Pass $dispPass -Detail $dispDetail)) | Out-Null
Write-Log ("Display: {0} - {1}" -f ($(if($dispPass){"PASS"}else{"FAIL"})), $dispDetail)

# -------------------------
# Final summary
# -------------------------
Write-Log ""
Write-Log "=== Summary ==="

$allPass = $true
foreach ($r in $results) {
    $status = if ($r.Pass) { "PASS" } else { "FAIL" }
    Write-Log ("{0}: {1} ({2})" -f $r.Name, $status, $r.Detail)
    if (-not $r.Pass) { $allPass = $false }
}

Write-Log ""
Write-Log ("Overall Result: {0}" -f ($(if($allPass){"COMPLIANT"}else{"NONCOMPLIANT"})))

# -------------------------
# Intune PR output behavior
# -------------------------
if ($allPass) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "NonCompliant"
    exit 1
}
