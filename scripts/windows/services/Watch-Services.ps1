<#
.SYNOPSIS
    Monitors services against a baseline snapshot with dashboard output and CSV logging.
.DESCRIPTION
    Polls every N seconds comparing current service state to a Snapshot-Services.ps1 baseline.
    Alerts on: binary path changes, SDDL changes, startup type changes, new services, deleted services.
    Dashboard output with fixed columns, color-coded alerts, running totals, CSV logging.

.PARAMETER SnapshotFile
    Path to the baseline snapshot JSON. Default: services-snapshot.json in script directory.
.PARAMETER AutoRevert
    Automatically restore original SDDL and binary path from snapshot when changes detected.
.PARAMETER PollSeconds
    Polling interval in seconds. Default: 15.
.PARAMETER LogDir
    Directory for CSV log output. Default: current directory.
#>
param(
    [string]$SnapshotFile = (Join-Path $PSScriptRoot "services-snapshot.json"),
    [switch]$AutoRevert,
    [int]$PollSeconds = 15,
    [string]$LogDir = "."
)

. "$PSScriptRoot\..\monitoring\Dashboard.ps1"

if (-not (Test-Path $SnapshotFile)) {
    Write-Host "No snapshot found at $SnapshotFile. Run Snapshot-Services.ps1 first." -ForegroundColor Red
    exit 1
}

$baseline = [string]::Join("", (Get-Content $SnapshotFile)) | ConvertFrom-Json
$baselineByName = @{}
foreach ($svc in $baseline) { $baselineByName[$svc.Name] = $svc }

Initialize-Dashboard `
    -ScriptName "Watch-Services v1.0.0" `
    -PollSeconds $PollSeconds `
    -Columns @("DateTime", "Result", "Change", "Service", "Detail") `
    -Widths  @(20,          8,        14,       25,        0) `
    -LogDir $LogDir

Write-Host "Baseline: $($baseline.Count) services$(if ($AutoRevert) { ' | AutoRevert ON' } else { '' })" -ForegroundColor Cyan
Write-Host ""

while ($true) {
    Start-Sleep -Seconds $PollSeconds
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $currentServices = @{}

    Get-Service | ForEach-Object {
        $name = $_.Name
        $currentServices[$name] = $true
        $base = $baselineByName[$name]

        if (-not $base) {
            $binPath = "unknown"
            try { $wmi = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue; if ($wmi) { $binPath = $wmi.PathName } } catch {}
            Write-DashRow -Values @($ts, "[NEW]", "NEW_SVC", $name, "Display=$($_.DisplayName) Binary=$binPath") -Color "Yellow" -ResultType "NEW"
            return
        }

        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        $regKey = Get-ItemProperty $regPath -ErrorAction SilentlyContinue

        # Binary path change
        if ($regKey -and $regKey.ImagePath -ne $base.ImagePath) {
            $reverted = ""
            if ($AutoRevert -and $base.ImagePath) {
                Set-ItemProperty $regPath -Name "ImagePath" -Value $base.ImagePath -ErrorAction SilentlyContinue
                $reverted = " [REVERTED]"
            }
            Write-DashRow -Values @($ts, "[WARN]", "PATH_CHANGED", $name, "Was=$($base.ImagePath) Now=$($regKey.ImagePath)$reverted") -Color "Red" -ResultType "WARN"
        }

        # SDDL change
        $sddlLine = (sc.exe sdshow $name 2>&1 | Where-Object { $_ -match '^D:' -or $_ -match '^O:' }) | Select-Object -First 1
        $currentSDDL = if ($sddlLine) { $sddlLine.Trim() } else { "" }
        if ($currentSDDL -and $base.SDDL -and $currentSDDL -ne $base.SDDL) {
            $reverted = ""
            if ($AutoRevert -and $base.SDDL) {
                sc.exe sdset $name $base.SDDL 2>&1 | Out-Null
                $reverted = " [REVERTED]"
            }
            Write-DashRow -Values @($ts, "[WARN]", "SDDL_CHANGED", $name, "Permissions modified$reverted") -Color "Red" -ResultType "WARN"
        }

        # Startup type change
        if ($_.StartType.ToString() -ne $base.StartType) {
            Write-DashRow -Values @($ts, "[WARN]", "START_CHANGED", $name, "Was=$($base.StartType) Now=$($_.StartType)") -Color "Yellow" -ResultType "WARN"
        }
    }

    # Deleted services
    foreach ($name in $baselineByName.Keys) {
        if (-not $currentServices.ContainsKey($name)) {
            Write-DashRow -Values @($ts, "[FAIL]", "DELETED", $name, "Service removed") -Color "Red" -ResultType "FAIL"
        }
    }

    Start-Sleep -Seconds $PollSeconds
}
