<#
.SYNOPSIS
    Monitors for new processes with dashboard output, CSV logging, and optional auto-kill.
.DESCRIPTION
    Takes a process baseline at startup, then polls for new process names.
    Dashboard output with fixed columns, color-coded alerts, running totals.
    Known transient system processes are whitelisted.

.PARAMETER AutoKill
    Forcibly terminate any process not in the baseline or whitelist.
.PARAMETER PollSeconds
    Polling interval in seconds. Default: 5.
.PARAMETER LogDir
    Directory for CSV log output. Default: current directory.
#>
param(
    [switch]$AutoKill,
    [int]$PollSeconds = 5,
    [string]$LogDir = "."
)

. "$PSScriptRoot\..\monitoring\Dashboard.ps1"

$TransientWhitelist = @(
    "conhost","WmiPrvSE","SearchProtocolHost","RuntimeBroker","backgroundTaskHost",
    "WUDFHost","SearchFilterHost","SearchIndexer","ShellExperienceHost",
    "ApplicationFrameHost","SystemSettings","MicrosoftEdgeUpdate","MpCmdRun",
    "WMIADAP","WmiApSrv","TiWorker","TrustedInstaller","MsMpEng","NisSrv",
    "dllhost","sihost","taskhostw","smartscreen","svchost"
) | ForEach-Object { $_.ToLower() }

Initialize-Dashboard `
    -ScriptName "Watch-Processes v1.0.0" `
    -PollSeconds $PollSeconds `
    -Columns @("DateTime", "Result", "PID", "ProcessName", "Path", "Parent") `
    -Widths  @(20,          8,        8,     22,            40,     0) `
    -LogDir $LogDir

function Get-ProcessBaseline {
    $bl = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $bl[$_.ProcessName.ToLower()] = $true
    }
    return $bl
}

$baseline = Get-ProcessBaseline
Write-Host "Baseline: $($baseline.Count) processes$(if ($AutoKill) { ' | AutoKill ON' } else { '' })" -ForegroundColor Cyan
Write-Host ""

while ($true) {
    Start-Sleep -Seconds $PollSeconds
    $seen = @{}

    foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
        $name = $proc.ProcessName.ToLower()
        if ($seen.ContainsKey($name)) { continue }
        $seen[$name] = $true
        if ($baseline.ContainsKey($name)) { continue }
        if ($name -in $TransientWhitelist) { continue }

        $path = if ($proc.Path) { $proc.Path } else { "N/A" }
        $parentInfo = "unknown"
        try {
            $wmi = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
            if ($wmi -and $wmi.ParentProcessId) {
                $parent = Get-Process -Id $wmi.ParentProcessId -ErrorAction SilentlyContinue
                if ($parent) { $parentInfo = "$($parent.ProcessName) ($($parent.Id))" }
            }
        } catch {}

        $result = "[NEW]"
        $resultType = "NEW"
        $color = "Red"

        if ($AutoKill) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                $result = "[KILL]"
                $resultType = "KILL"
                $color = "Magenta"
            } catch {}
        }

        Write-DashRow -Values @(
            (Get-Date -Format "yyyy-MM-dd HH:mm:ss"),
            $result,
            $proc.Id.ToString(),
            $proc.ProcessName,
            $path,
            $parentInfo
        ) -Color $color -ResultType $resultType
    }

    Start-Sleep -Seconds $PollSeconds
}
