<#
.SYNOPSIS
    Monitors all authentication events with protocol detection and dashboard output.
.DESCRIPTION
    Polls Security event log for authentication events across all protocols:
      - 4624/4625: Logon success/failure (NTLM, Kerberos, Negotiate)
      - 4768: Kerberos TGT request
      - 4769: Kerberos service ticket
      - 4776: NTLM credential validation
      - 4648: Explicit credential logon
      - 2889: LDAP unsigned bind (Directory Service log)

    Dashboard output with fixed columns, color-coded by protocol and result,
    running totals in status bar, automatic CSV logging.

.PARAMETER PollSeconds
    Polling interval in seconds. Default: 3.
.PARAMETER ShowAll
    Include Service (type 5) and System (type 0) logon events.
.PARAMETER Filter
    Filter to a specific protocol: All, NTLM, Kerberos, LDAP. Default: All.
.PARAMETER LogDir
    Directory for CSV log output. Default: current directory.
#>
param(
    [int]$PollSeconds = 3,
    [switch]$ShowAll,
    [ValidateSet("All","NTLM","Kerberos","LDAP")]
    [string]$Filter = "All",
    [string]$LogDir = "."
)

. "$PSScriptRoot\Dashboard.ps1"

$version = "v1.0.0"
$hostname = $env:COMPUTERNAME

# --- Protocol colors ---
$ProtocolColors = @{
    "Kerberos"     = "Green"
    "NTLM"         = "Yellow"
    "NTLM-Local"   = "Cyan"
    "LDAP"         = "DarkYellow"
    "ExplicitCred" = "Magenta"
    "WinRM"        = "Blue"
    "NegotiateExt" = "DarkCyan"
    "Unknown"      = "Gray"
}

$LogonTypes = @{
    '0'='System'; '2'='Interactive'; '3'='Network'; '4'='Batch'
    '5'='Service'; '7'='Unlock'; '8'='NetworkCleartext'
    '9'='NewCredentials'; '10'='RemoteDesktop'; '11'='CachedInteractive'
}

$FailureCodes = @{
    '0xc000006d'='Bad username or password'; '0xc000006e'='Account restriction'
    '0xc0000064'='User does not exist'; '0xc000006a'='Wrong password'
    '0xc0000234'='Account locked out'; '0xc000015b'='Logon type not granted'
    '0xc0000072'='Account disabled'; '0xc0000193'='Account expired'
    '0xc0000070'='Workstation restriction'; '0xc0000133'='Clock skew too great'
}

$FilteredLogonTypes = @('0', '5')

Initialize-Dashboard `
    -ScriptName "Watch-AuthEvents $version" `
    -PollSeconds $PollSeconds `
    -Filter $Filter `
    -Columns @("DateTime", "Result", "Protocol", "Username", "SourceIP", "LogonType", "Detail") `
    -Widths  @(20,         8,        14,         30,          18,         12,          0) `
    -LogDir $LogDir

function Get-XmlField {
    param([System.Xml.XmlElement[]]$DataItems, [string]$Name)
    $node = $DataItems | Where-Object { $_.Name -eq $Name }
    if ($node) { return $node.'#text' }
    return $null
}

function Classify-Protocol {
    param($EventId, $XmlData)

    switch ($EventId) {
        4768 { return "Kerberos" }
        4769 { return "Kerberos" }
        4776 {
            $workstation = Get-XmlField $XmlData 'Workstation'
            if (-not $workstation -or $workstation -eq $env:COMPUTERNAME) {
                return "NTLM-Local"
            }
            return "NTLM"
        }
        4648 { return "ExplicitCred" }
        2889 { return "LDAP" }
        { $_ -in 4624, 4625 } {
            $authPkg = Get-XmlField $XmlData 'AuthenticationPackageName'
            $logonProcess = Get-XmlField $XmlData 'LogonProcessName'
            $logonType = Get-XmlField $XmlData 'LogonType'

            if ($authPkg -match 'Kerberos') { return "Kerberos" }
            if ($logonProcess -match 'WinRM') { return "WinRM" }
            if ($authPkg -match 'NTLM|NtLmSsp') {
                if ($logonType -eq '3') { return "NTLM" }
                return "NTLM-Local"
            }
            if ($authPkg -match 'Negotiate') { return "NegotiateExt" }
            return "Unknown"
        }
        default { return "Unknown" }
    }
}

function Process-4624 {
    param($Event)
    $xml = [xml]$Event.ToXml()
    $data = $xml.Event.EventData.Data

    $user = Get-XmlField $data 'TargetUserName'
    $domain = Get-XmlField $data 'TargetDomainName'
    $ip = Get-XmlField $data 'IpAddress'
    $typeCode = Get-XmlField $data 'LogonType'
    $authPkg = Get-XmlField $data 'AuthenticationPackageName'
    $logonProcess = Get-XmlField $data 'LogonProcessName'

    if (-not $ShowAll -and $typeCode -in $FilteredLogonTypes) { return }

    $protocol = Classify-Protocol -EventId 4624 -XmlData $data
    if ($Filter -ne "All" -and $protocol -notmatch $Filter) { return }

    if (-not $ip -or $ip -eq '-') { $ip = "local" }
    $typeName = if ($LogonTypes.ContainsKey($typeCode)) { $LogonTypes[$typeCode] } else { "Type$typeCode" }
    $username = if ($domain -and $domain -ne '-') { "$domain\$user" } else { $user }
    $detail = "[EID:4624] LogonType=$typeName AuthPkg=$authPkg LogonProc=$($logonProcess.Trim())"

    $color = if ($ProtocolColors.ContainsKey($protocol)) { $ProtocolColors[$protocol] } else { "White" }

    Write-DashRow -Values @(
        $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"),
        "[OK]",
        $protocol,
        $username,
        $ip,
        $typeName,
        $detail
    ) -Color $color -ResultType "OK"
}

function Process-4625 {
    param($Event)
    $xml = [xml]$Event.ToXml()
    $data = $xml.Event.EventData.Data

    $user = Get-XmlField $data 'TargetUserName'
    $domain = Get-XmlField $data 'TargetDomainName'
    $ip = Get-XmlField $data 'IpAddress'
    $typeCode = Get-XmlField $data 'LogonType'
    $status = Get-XmlField $data 'Status'
    $subStatus = Get-XmlField $data 'SubStatus'

    if (-not $ShowAll -and $typeCode -in $FilteredLogonTypes) { return }

    $protocol = Classify-Protocol -EventId 4625 -XmlData $data
    if ($Filter -ne "All" -and $protocol -notmatch $Filter) { return }

    if (-not $ip -or $ip -eq '-') { $ip = "local" }
    $typeName = if ($LogonTypes.ContainsKey($typeCode)) { $LogonTypes[$typeCode] } else { "Type$typeCode" }
    $username = if ($domain -and $domain -ne '-') { "$domain\$user" } else { $user }

    $reasonCode = if ($subStatus -and $subStatus -ne '0x0') { $subStatus.ToLower() } else { $status.ToLower() }
    $reason = if ($FailureCodes.ContainsKey($reasonCode)) { $FailureCodes[$reasonCode] } else { $reasonCode }
    $detail = "[EID:4625] $reason"

    Write-DashRow -Values @(
        $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"),
        "[FAIL]",
        $protocol,
        $username,
        $ip,
        $typeName,
        $detail
    ) -Color "Red" -ResultType "FAIL"
}

function Process-4768 {
    param($Event)
    $xml = [xml]$Event.ToXml()
    $data = $xml.Event.EventData.Data

    $user = Get-XmlField $data 'TargetUserName'
    $ip = Get-XmlField $data 'IpAddress'
    $svc = Get-XmlField $data 'ServiceName'
    $encType = Get-XmlField $data 'TicketEncryptionType'
    $status = Get-XmlField $data 'Status'

    if ($Filter -ne "All" -and $Filter -ne "Kerberos") { return }
    if (-not $ip -or $ip -eq '::1') { $ip = "local" }
    # Strip IPv6 prefix
    $ip = $ip -replace '^::ffff:', ''

    $result = if ($status -eq '0x0') { "[OK]" } else { "[FAIL]" }
    $resultType = if ($status -eq '0x0') { "OK" } else { "FAIL" }
    $color = if ($status -eq '0x0') { "Green" } else { "Red" }
    $detail = "[EID:4768] Service=$svc EncType=$encType"

    Write-DashRow -Values @(
        $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"),
        $result,
        "Kerberos",
        $user,
        $ip,
        "0",
        $detail
    ) -Color $color -ResultType $resultType
}

function Process-4769 {
    param($Event)
    $xml = [xml]$Event.ToXml()
    $data = $xml.Event.EventData.Data

    $user = Get-XmlField $data 'TargetUserName'
    $ip = Get-XmlField $data 'IpAddress'
    $svc = Get-XmlField $data 'ServiceName'
    $encType = Get-XmlField $data 'TicketEncryptionType'
    $status = Get-XmlField $data 'Status'

    if ($Filter -ne "All" -and $Filter -ne "Kerberos") { return }
    if (-not $ip -or $ip -eq '::1') { $ip = "local" }
    $ip = $ip -replace '^::ffff:', ''

    $result = if ($status -eq '0x0') { "[OK]" } else { "[FAIL]" }
    $resultType = if ($status -eq '0x0') { "OK" } else { "FAIL" }
    $color = if ($status -eq '0x0') { "Green" } else { "Red" }
    $detail = "[EID:4769] Service=$svc EncType=$encType"

    Write-DashRow -Values @(
        $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"),
        $result,
        "Kerberos",
        $user,
        $ip,
        "0",
        $detail
    ) -Color $color -ResultType $resultType
}

function Process-4776 {
    param($Event)
    $xml = [xml]$Event.ToXml()
    $data = $xml.Event.EventData.Data

    $user = Get-XmlField $data 'TargetUserName'
    $workstation = Get-XmlField $data 'Workstation'
    $status = Get-XmlField $data 'Status'

    if ($Filter -ne "All" -and $Filter -ne "NTLM") { return }

    $protocol = if (-not $workstation -or $workstation -eq $env:COMPUTERNAME) { "NTLM-Local" } else { "NTLM" }
    $result = if ($status -eq '0x0') { "[OK]" } else { "[FAIL]" }
    $resultType = if ($status -eq '0x0') { "OK" } else { "FAIL" }
    $color = if ($status -eq '0x0') { $ProtocolColors[$protocol] } else { "Red" }
    $detail = "[EID:4776] NTLM-Validate $(if ($status -eq '0x0') { 'OK' } else { "FAIL $status" })"

    Write-DashRow -Values @(
        $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"),
        $result,
        $protocol,
        "$user@-",
        $workstation,
        "local",
        $detail
    ) -Color $color -ResultType $resultType
}

function Process-4648 {
    param($Event)
    $xml = [xml]$Event.ToXml()
    $data = $xml.Event.EventData.Data

    $subject = Get-XmlField $data 'SubjectUserName'
    $target = Get-XmlField $data 'TargetUserName'
    $targetServer = Get-XmlField $data 'TargetServerName'
    $process = Get-XmlField $data 'ProcessName'

    $detail = "[EID:4648] Target=$targetServer Process=$process"

    Write-DashRow -Values @(
        $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"),
        "[OK]",
        "ExplicitCred",
        "$subject->$target",
        $targetServer,
        "0",
        $detail
    ) -Color "Magenta" -ResultType "OK"
}

function Process-2889 {
    param($Event)
    $xml = [xml]$Event.ToXml()
    $data = $xml.Event.EventData.Data

    $ip = Get-XmlField $data 'IPAddress'
    $dn = Get-XmlField $data 'BindDN'
    $bindType = Get-XmlField $data 'BindType'

    if ($Filter -ne "All" -and $Filter -ne "LDAP") { return }

    $detail = "[EID:2889] BindType=$bindType Identity=$dn"

    Write-DashRow -Values @(
        $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"),
        "[WARN]",
        "LDAP",
        $dn,
        $ip,
        "Network",
        $detail
    ) -Color "DarkYellow" -ResultType "WARN"
}

# --- Main loop ---

# Security log event IDs
$securityIds = @(4624, 4625, 4768, 4769, 4776, 4648)

while ($true) {
    $startTime = (Get-Date).AddSeconds(-$PollSeconds)

    # Security log events
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = $securityIds
            StartTime = $startTime
        } -ErrorAction SilentlyContinue)
    } catch { $events = @() }

    # LDAP unsigned bind events (Directory Service log, event 2889)
    try {
        $ldapEvents = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Directory Service'
            Id        = 2889
            StartTime = $startTime
        } -ErrorAction SilentlyContinue)
        $events += $ldapEvents
    } catch {}

    # Sort by time and process
    $events | Sort-Object TimeCreated | ForEach-Object {
        switch ($_.Id) {
            4624 { Process-4624 $_ }
            4625 { Process-4625 $_ }
            4768 { Process-4768 $_ }
            4769 { Process-4769 $_ }
            4776 { Process-4776 $_ }
            4648 { Process-4648 $_ }
            2889 { Process-2889 $_ }
        }
    }

    Start-Sleep -Seconds $PollSeconds
}
