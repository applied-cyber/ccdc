<#
.SYNOPSIS
    Monitors for new persistence mechanisms with dashboard output and CSV logging.
.DESCRIPTION
    Baselines scheduled tasks, services, and Run/RunOnce registry keys at startup,
    then polls for new entries. Dashboard output with fixed columns, color-coded
    alerts, running totals, CSV logging.

    With -AutoRemove, new items are deleted automatically.

.PARAMETER AutoRemove
    Automatically remove newly detected persistence items.
.PARAMETER PollSeconds
    Polling interval in seconds. Default: 10.
.PARAMETER LogDir
    Directory for CSV log output. Default: current directory.
#>
param(
    [switch]$AutoRemove,
    [int]$PollSeconds = 10,
    [string]$LogDir = "."
)

. "$PSScriptRoot\..\monitoring\Dashboard.ps1"

$RunKeyPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

Initialize-Dashboard `
    -ScriptName "Watch-Persistence v1.0.0" `
    -PollSeconds $PollSeconds `
    -Columns @("DateTime", "Result", "Type", "Name", "Detail") `
    -Widths  @(20,          8,        10,     35,     0) `
    -LogDir $LogDir

function Get-TaskBaseline {
    $t = @{}
    try { Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { $t["$($_.TaskPath)$($_.TaskName)"] = $_ } } catch {}
    return $t
}

function Get-ServiceBaseline {
    $s = @{}
    Get-Service -ErrorAction SilentlyContinue | ForEach-Object { $s[$_.Name] = $_ }
    return $s
}

function Get-RegistryBaseline {
    $e = @{}
    foreach ($path in $RunKeyPaths) {
        if (-not (Test-Path $path)) { continue }
        try {
            $props = Get-ItemProperty $path -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            $props.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } |
                ForEach-Object { $e["${path}\$($_.Name)"] = $_.Value }
        } catch {}
    }
    return $e
}

$baselineTasks    = Get-TaskBaseline
$baselineServices = Get-ServiceBaseline
$baselineRegistry = Get-RegistryBaseline

Write-Host "Baseline: $($baselineTasks.Count) tasks, $($baselineServices.Count) services, $($baselineRegistry.Count) reg keys$(if ($AutoRemove) { ' | AutoRemove ON' } else { '' })" -ForegroundColor Cyan
Write-Host ""

while ($true) {
    Start-Sleep -Seconds $PollSeconds
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Tasks
    $currentTasks = Get-TaskBaseline
    foreach ($key in $currentTasks.Keys) {
        if ($baselineTasks.ContainsKey($key)) { continue }
        $task = $currentTasks[$key]
        $cmd = ""
        try {
            $xmlDoc = [xml](Export-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName -ErrorAction SilentlyContinue)
            $exec = $xmlDoc.Task.Actions.Exec
            if ($exec) { $cmd = "$($exec.Command) $($exec.Arguments)" }
        } catch {}

        $result = "[NEW]"; $resultType = "NEW"; $color = "Red"
        if ($AutoRemove) {
            try { Unregister-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop
                $result = "[KILL]"; $resultType = "KILL"; $color = "Magenta"
            } catch {}
        }

        Write-DashRow -Values @($ts, $result, "TASK", $key, $cmd) -Color $color -ResultType $resultType
    }

    # Services
    $currentServices = Get-ServiceBaseline
    foreach ($name in $currentServices.Keys) {
        if ($baselineServices.ContainsKey($name)) { continue }
        $svc = $currentServices[$name]
        $binPath = "unknown"
        try { $wmi = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue; if ($wmi) { $binPath = $wmi.PathName } } catch {}

        $result = "[NEW]"; $resultType = "NEW"; $color = "Red"
        if ($AutoRemove) {
            try { Stop-Service $name -Force -ErrorAction SilentlyContinue; sc.exe delete $name 2>&1 | Out-Null
                $result = "[KILL]"; $resultType = "KILL"; $color = "Magenta"
            } catch {}
        }

        Write-DashRow -Values @($ts, $result, "SERVICE", "$name ($($svc.DisplayName))", $binPath) -Color $color -ResultType $resultType
    }

    # Registry
    $currentRegistry = Get-RegistryBaseline
    foreach ($key in $currentRegistry.Keys) {
        if ($baselineRegistry.ContainsKey($key)) { continue }

        $result = "[NEW]"; $resultType = "NEW"; $color = "Red"
        if ($AutoRemove) {
            try {
                $lastBS = $key.LastIndexOf('\'); $regPath = $key.Substring(0, $lastBS); $propName = $key.Substring($lastBS + 1)
                Remove-ItemProperty $regPath -Name $propName -Force -ErrorAction Stop
                $result = "[KILL]"; $resultType = "KILL"; $color = "Magenta"
            } catch {}
        }

        Write-DashRow -Values @($ts, $result, "REGKEY", (Split-Path $key -Leaf), $currentRegistry[$key]) -Color $color -ResultType $resultType
    }

    # Update baselines
    if ($AutoRemove) {
        $baselineTasks = Get-TaskBaseline; $baselineServices = Get-ServiceBaseline; $baselineRegistry = Get-RegistryBaseline
    } else {
        $baselineTasks = $currentTasks; $baselineServices = $currentServices; $baselineRegistry = $currentRegistry
    }
}
