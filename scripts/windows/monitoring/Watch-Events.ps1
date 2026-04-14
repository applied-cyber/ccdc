<#
.SYNOPSIS
    Monitors suspicious security events with dashboard output and CSV logging.
.DESCRIPTION
    Polls the Security event log for:
      - 4688: Process Creation
      - 4697: Service Installation
      - 4672: Special Privilege Assignment
      - 4720: User Account Creation
      - 4726: User Account Deletion
      - 4732: Local Group Member Added
      - 4740: Account Lockout
      - 4719: Audit Policy Change

    Dashboard output with fixed columns, color-coded by event type,
    running totals, automatic CSV logging.

.PARAMETER PollSeconds
    Polling interval in seconds. Default: 3.
.PARAMETER LogDir
    Directory for CSV log output. Default: current directory.
#>
param(
    [int]$PollSeconds = 3,
    [string]$LogDir = "."
)

. "$PSScriptRoot\Dashboard.ps1"

$FailureCodes = @{
    '0xc000006d'='Bad username or password'; '0xc000006e'='Account restriction'
    '0xc0000064'='User does not exist'; '0xc000006a'='Wrong password'
    '0xc0000234'='Account locked out'; '0xc000015b'='Logon type not granted'
    '0xc0000072'='Account disabled'; '0xc0000193'='Account expired'
}

$eventDefs = @{
    4688 = @{ Tag = "PROC";    Color = "Yellow" }
    4697 = @{ Tag = "SVC";     Color = "Red" }
    4672 = @{ Tag = "PRIV";    Color = "Magenta" }
    4720 = @{ Tag = "USERADD"; Color = "Cyan" }
    4726 = @{ Tag = "USERDEL"; Color = "DarkCyan" }
    4732 = @{ Tag = "GRPADD";  Color = "Blue" }
    4740 = @{ Tag = "LOCKOUT"; Color = "Red" }
    4719 = @{ Tag = "AUDIT";   Color = "Gray" }
}

Initialize-Dashboard `
    -ScriptName "Watch-Events v1.0.0" `
    -PollSeconds $PollSeconds `
    -Columns @("DateTime", "Result", "Type", "User", "Source", "Detail") `
    -Widths  @(20,          8,        10,     25,     20,       0) `
    -LogDir $LogDir

function Get-XmlField {
    param([System.Xml.XmlElement[]]$DataItems, [string]$Name)
    $node = $DataItems | Where-Object { $_.Name -eq $Name }
    if ($node) { return $node.'#text' }
    return $null
}

$allIds = @(4688, 4697, 4672, 4720, 4726, 4732, 4740, 4719)

while ($true) {
    $startTime = (Get-Date).AddSeconds(-$PollSeconds)

    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Security'; Id = $allIds; StartTime = $startTime
        } -ErrorAction SilentlyContinue)
    } catch { $events = @() }

    $events | Sort-Object TimeCreated | ForEach-Object {
        $evt = $_
        $xml = [xml]$evt.ToXml()
        $data = $xml.Event.EventData.Data
        $def = $eventDefs[$evt.Id]
        if (-not $def) { return }

        $ts = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        $user = ""; $source = ""; $detail = ""

        switch ($evt.Id) {
            4688 {
                $user = Get-XmlField $data 'SubjectUserName'
                $proc = Get-XmlField $data 'NewProcessName'
                $cmdLine = Get-XmlField $data 'CommandLine'
                $source = if ($proc) { Split-Path $proc -Leaf } else { "" }
                $detail = "[EID:4688] $proc $(if ($cmdLine) { $cmdLine })"
            }
            4697 {
                $svcName = Get-XmlField $data 'ServiceName'
                $svcFile = Get-XmlField $data 'ServiceFileName'
                $user = Get-XmlField $data 'SubjectUserName'
                $source = $svcName
                $detail = "[EID:4697] Binary=$svcFile"
            }
            4672 {
                $user = Get-XmlField $data 'SubjectUserName'
                $privs = (Get-XmlField $data 'PrivilegeList') -replace '\s+', ' '
                $detail = "[EID:4672] $privs"
            }
            4720 {
                $user = Get-XmlField $data 'SubjectUserName'
                $target = Get-XmlField $data 'TargetUserName'
                $source = $target
                $detail = "[EID:4720] Created by $user"
            }
            4726 {
                $user = Get-XmlField $data 'SubjectUserName'
                $target = Get-XmlField $data 'TargetUserName'
                $source = $target
                $detail = "[EID:4726] Deleted by $user"
            }
            4732 {
                $target = Get-XmlField $data 'TargetUserName'
                $member = Get-XmlField $data 'MemberName'
                $user = Get-XmlField $data 'SubjectUserName'
                $source = $target
                $detail = "[EID:4732] Member=$member AddedBy=$user"
            }
            4740 {
                $target = Get-XmlField $data 'TargetUserName'
                $ip = Get-XmlField $data 'IpAddress'
                $user = $target
                $source = $ip
                $detail = "[EID:4740] Account locked out"
            }
            4719 {
                $user = Get-XmlField $data 'SubjectUserName'
                $subcat = Get-XmlField $data 'SubcategoryName'
                $detail = "[EID:4719] Subcategory=$subcat"
            }
        }

        $resultType = if ($evt.Id -in @(4697, 4740)) { "WARN" } else { "OK" }
        $result = if ($resultType -eq "WARN") { "[WARN]" } else { "[OK]" }

        Write-DashRow -Values @($ts, $result, $def.Tag, $user, $source, $detail) `
            -Color $def.Color -ResultType $resultType
    }

    Start-Sleep -Seconds $PollSeconds
}
