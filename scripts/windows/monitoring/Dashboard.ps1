<#
.SYNOPSIS
    Shared dashboard rendering helpers for all Watch-* scripts.
.DESCRIPTION
    Provides consistent table-style output with:
    - Fixed-width column header
    - Color-coded rows
    - Running totals status bar (overwrites last line)
    - Automatic CSV logging
    Dot-source this from any Watch-* script.
#>

# --- State ---
$script:DashCounters = @{ Total = 0; OK = 0; WARN = 0; FAIL = 0; NEW = 0; KILL = 0 }
$script:DashLogFile = $null
$script:DashStartTime = Get-Date
$script:DashHostname = $env:COMPUTERNAME
$script:DashScriptName = ""
$script:DashPollInterval = 0
$script:DashFilter = "All"
$script:DashColumns = @()
$script:DashWidths = @()
$script:DashHeaderDrawn = $false

function Initialize-Dashboard {
    param(
        [string]$ScriptName,
        [int]$PollSeconds,
        [string]$Filter = "All",
        [string[]]$Columns,
        [int[]]$Widths,
        [string]$LogDir = "."
    )
    $script:DashScriptName = $ScriptName
    $script:DashPollInterval = $PollSeconds
    $script:DashFilter = $Filter
    $script:DashColumns = $Columns
    $script:DashWidths = $Widths
    $script:DashStartTime = Get-Date

    # CSV log file
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:DashLogFile = Join-Path $LogDir "${ScriptName}_${ts}.csv"
    $header = ($Columns -join ",")
    $header | Set-Content $script:DashLogFile -Encoding ascii
}

function Write-DashHeader {
    if ($script:DashHeaderDrawn) { return }
    $script:DashHeaderDrawn = $true

    $now = Get-Date -Format "HH:mm:ss"
    $titleLine = "$($script:DashScriptName)  |  $now  |  $($script:DashHostname)  |  Poll:$($script:DashPollInterval)s  |  Filter:$($script:DashFilter)"
    Write-Host $titleLine -ForegroundColor White
    Write-Host ""

    # Column header
    $headerLine = ""
    for ($i = 0; $i -lt $script:DashColumns.Count; $i++) {
        $col = $script:DashColumns[$i]
        $w = $script:DashWidths[$i]
        if ($i -eq $script:DashColumns.Count - 1) {
            $headerLine += $col
        } else {
            $headerLine += $col.PadRight($w)
        }
    }
    Write-Host $headerLine -ForegroundColor Gray
    Write-Host ("-" * 140) -ForegroundColor DarkGray
}

function Write-DashRow {
    param(
        [string[]]$Values,
        [string]$Color = "White",
        [string]$ResultType = "OK"  # OK, FAIL, WARN, NEW, KILL
    )

    Write-DashHeader

    # Update counters
    $script:DashCounters.Total++
    if ($script:DashCounters.ContainsKey($ResultType)) {
        $script:DashCounters[$ResultType]++
    }

    # Build formatted line
    $line = ""
    for ($i = 0; $i -lt $Values.Count; $i++) {
        $val = if ($Values[$i]) { $Values[$i] } else { "" }
        $w = if ($i -lt $script:DashWidths.Count) { $script:DashWidths[$i] } else { 0 }
        if ($i -eq $Values.Count - 1) {
            $line += $val
        } else {
            # Truncate if too long
            if ($val.Length -gt ($w - 1)) { $val = $val.Substring(0, $w - 2) + "~" }
            $line += $val.PadRight($w)
        }
    }
    Write-Host $line -ForegroundColor $Color

    # CSV log
    if ($script:DashLogFile) {
        $escaped = $Values | ForEach-Object { if ($_ -match ',') { "`"$_`"" } else { $_ } }
        ($escaped -join ",") | Add-Content $script:DashLogFile -Encoding ascii
    }
}

function Write-DashStatus {
    param(
        [hashtable]$ExtraLabels = @{}  # e.g. @{ "Kerberos" = "Green"; "NTLM" = "Yellow" }
    )

    $c = $script:DashCounters
    $parts = @()

    # Write status bar
    Write-Host ""
    Write-Host -NoNewline "Total:$($c.Total) "
    Write-Host -NoNewline "[OK]:$($c.OK) " -ForegroundColor Green
    Write-Host -NoNewline "[FAIL]:$($c.FAIL) " -ForegroundColor Red
    if ($c.WARN -gt 0) { Write-Host -NoNewline "[WARN]:$($c.WARN) " -ForegroundColor Yellow }
    if ($c.NEW -gt 0) { Write-Host -NoNewline "[NEW]:$($c.NEW) " -ForegroundColor Yellow }
    if ($c.KILL -gt 0) { Write-Host -NoNewline "[KILL]:$($c.KILL) " -ForegroundColor Magenta }

    Write-Host -NoNewline " | "

    foreach ($label in $ExtraLabels.Keys) {
        Write-Host -NoNewline "$label " -ForegroundColor $ExtraLabels[$label]
    }

    Write-Host -NoNewline " | Ctrl+C exit | Log: $(Split-Path $script:DashLogFile -Leaf)"
    Write-Host ""
}
