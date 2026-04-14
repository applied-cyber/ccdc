#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Real-time authentication event monitor for Windows hosts and Domain Controllers.

.DESCRIPTION
    Monitors and logs authentication attempts across NTLM, Kerberos, LDAP, WinRM,
    and other protocols by tailing Windows event logs in near real-time.
    Displays a fixed-header TUI with protocol color-coding.

.PARAMETER PollInterval
    Seconds between event log polls. Default: 3

.PARAMETER LogPath
    Path to CSV log file. Default: .\AuthEvents_<date>.csv

.PARAMETER LookbackMinutes
    How far back to pull events on first run. Default: 5

.PARAMETER Protocol
    Filter by protocol: All, NTLM, Kerberos, WinRM, LDAP, Negotiate. Default: All

.PARAMETER IncludeSuccesses
    Include successful authentications. Default: true

.PARAMETER IncludeFailures
    Include failed authentications. Default: true

.PARAMETER UserFilter
    Only show events matching this username (wildcards supported).

.PARAMETER IPFilter
    Only show events matching this source IP (wildcards supported).

.PARAMETER NoLog
    Disable CSV file logging (console only).

.EXAMPLE
    .\Watch-AuthEvents.ps1
    .\Watch-AuthEvents.ps1 -Protocol NTLM -IncludeSuccesses:$false
    .\Watch-AuthEvents.ps1 -UserFilter "jsmith" -LogPath C:\Logs\auth.csv
    .\Watch-AuthEvents.ps1 -PollInterval 1 -LookbackMinutes 60
#>

[CmdletBinding()]
param(
    [int]$PollInterval       = 3,
    [string]$LogPath         = ".\AuthEvents_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [int]$LookbackMinutes    = 5,
    [ValidateSet('All','NTLM','Kerberos','WinRM','LDAP','Negotiate','RDP')]
    [string]$Protocol        = 'All',
    [bool]$IncludeSuccesses  = $true,
    [bool]$IncludeFailures   = $true,
    [string]$UserFilter      = '*',
    [string]$IPFilter        = '*',
    [switch]$NoLog
)

$ErrorActionPreference = 'SilentlyContinue'

#region ── Constants ──────────────────────────────────────────────────────────

$VERSION = '1.2.0'

# TUI layout: 5 header rows (0-4) + N event rows + 2 footer rows
$HEADER_ROWS = 5
$FOOTER_ROWS = 2

# Protocol -> console color mapping (applied to SUCCESS event lines)
$PROTOCOL_COLORS = @{
    'NTLM'         = [ConsoleColor]::Yellow      # Network NTLM (4624 with NTLM pkg, or 4776 with SourceIP)
    'NTLM-Local'   = [ConsoleColor]::DarkYellow  # 4776 with no SourceIP = LDAP/local validation, NOT network NTLM
    'Kerberos'     = [ConsoleColor]::Cyan
    'WinRM'        = [ConsoleColor]::Magenta
    'Negotiate'    = [ConsoleColor]::White
    'ExplicitCred' = [ConsoleColor]::DarkYellow
    'LDAP'         = [ConsoleColor]::Green
    'RDP'          = [ConsoleColor]::DarkGreen
    'Logon'        = [ConsoleColor]::Gray
}

# Event log sources to monitor
$LOG_SOURCES = @{
    Security = @{
        LogName  = 'Security'
        EventIDs = @(4624, 4625, 4648, 4768, 4769, 4770, 4771, 4772, 4776)
    }
    NTLM = @{
        LogName  = 'Microsoft-Windows-NTLM/Operational'
        EventIDs = @(8001, 8002, 8003, 8004)
    }
    WinRM = @{
        LogName  = 'Microsoft-Windows-WinRM/Operational'
        EventIDs = @(169, 166, 61)
    }
    KDC = @{
        LogName  = 'Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational'
        EventIDs = @(306, 307)
    }
    DirectoryService = @{
        LogName  = 'Directory Service'
        EventIDs = @(2886, 2887, 2888, 2889)
    }
    RDPRemote = @{
        LogName  = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
        EventIDs = @(1149)
    }
    RDPLocal = @{
        LogName  = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
        EventIDs = @(21, 23, 24, 25)
    }
}

# Security log: Logon type descriptions
$LOGON_TYPE = @{
    2  = 'Interactive'
    3  = 'Network'
    4  = 'Batch'
    5  = 'Service'
    7  = 'Unlock'
    8  = 'NetworkCleartext'
    9  = 'NewCredentials'
    10 = 'RemoteInteractive'
    11 = 'CachedInteractive'
    12 = 'CachedRemoteInteractive'
    13 = 'CachedUnlock'
}

# Map EventID to protocol hint (used when auth package is not explicit)
$EVENTID_PROTOCOL = @{
    4624 = 'Logon'
    4625 = 'Logon'
    4648 = 'ExplicitCred'
    4768 = 'Kerberos'
    4769 = 'Kerberos'
    4770 = 'Kerberos'
    4771 = 'Kerberos'
    4772 = 'Kerberos'
    4776 = 'NTLM'
    8001 = 'NTLM'
    8002 = 'NTLM'
    8003 = 'NTLM'
    8004 = 'NTLM'
    169  = 'WinRM'
    166  = 'WinRM'
    61   = 'WinRM'
    306  = 'Kerberos'
    307  = 'Kerberos'
    1149 = 'RDP'
    21   = 'RDP'
    23   = 'RDP'
    24   = 'RDP'
    25   = 'RDP'
}

# Failure sub-status codes for 4625/4768/4771/4776
$FAILURE_CODES = @{
    '0xC000005E' = 'No logon servers available'
    '0xC0000064' = 'User does not exist'
    '0xC000006A' = 'Wrong password'
    '0xC000006D' = 'Bad username or auth info'
    '0xC000006E' = 'Account restriction'
    '0xC000006F' = 'Outside logon hours'
    '0xC0000070' = 'Unauthorized workstation'
    '0xC0000071' = 'Password expired'
    '0xC0000072' = 'Account disabled'
    '0xC0000193' = 'Account expired'
    '0xC0000224' = 'Password must change'
    '0xC0000234' = 'Account locked out'
    '0x6'        = 'Bad username'
    '0x7'        = 'Bad integrity (ticket expired/tampered)'
    '0x12'       = 'Account disabled/expired/locked'
    '0x17'       = 'Password expired'
    '0x18'       = 'Wrong password'
    '0x20'       = 'Ticket expired'
    '0x25'       = 'Clock skew too great'
    '0x32'       = 'Not supported'
    '0x33'       = 'No suitable keys'
    '0x34'       = 'No PA data'
    '0x37'       = 'Wrong realm'
    '0x3C'       = 'Generic Kerberos failure'
}

#endregion

#region ── Helpers ────────────────────────────────────────────────────────────

# PS 5.1 compatibility: replacement for the ?? null-coalescing operator
function Nvl {
    foreach ($arg in $args) {
        if ($null -ne $arg) { return $arg }
    }
    return $null
}

function Fit {
    # Truncate/pad a string to exactly $width characters
    param([string]$Text, [int]$Width)
    if ($Text.Length -ge $Width) { return $Text.Substring(0, $Width) }
    return $Text.PadRight($Width)
}

function Get-ProtocolColor {
    param([string]$Protocol, [string]$Result)
    if ($PROTOCOL_COLORS.ContainsKey($Protocol)) { return $PROTOCOL_COLORS[$Protocol] }
    return [ConsoleColor]::White
}

# Write a single console line at the given row, padded to fill console width.
# Does NOT write a newline - caller positions the cursor explicitly.
function Write-TUIRow {
    param(
        [int]$Row,
        [string]$Text = '',
        [ConsoleColor]$Color = [ConsoleColor]::White
    )
    $w    = [Math]::Max(1, [Console]::WindowWidth - 1)
    $line = Fit -Text $Text -Width $w
    [Console]::SetCursorPosition(0, $Row)
    $prev = [Console]::ForegroundColor
    [Console]::ForegroundColor = $Color
    [Console]::Write($line)
    [Console]::ForegroundColor = $prev
}

# Write a single event line at $Row with per-segment color coding.
# Layout (0-based positions):
#   2  + DateTime(21) + 1 + Result(6) + 1 + Protocol(12) + 1
#   + Username(20) + 1 + SourceIP(16) + 1 + LogonType(13) + 1 + Detail(rest)
function Write-EventRow {
    param([int]$Row, [PSCustomObject]$Evt)

    $w = [Math]::Max(1, [Console]::WindowWidth - 1)
    [Console]::SetCursorPosition(0, $Row)

    $resultTag  = switch ($Evt.Result) {
                      'SUCCESS' { '[OK]  ' }
                      'FAILURE' { '[FAIL]' }
                      'WARNING' { '[WARN]' }
                      default   { '[INFO]' }
                  }
    $userStr    = ($Evt.Username + '@' + $Evt.Domain).TrimEnd('@')
    $ipStr      = if ($Evt.SourceIP -in @('-','::1','127.0.0.1','')) { 'local' } else { $Evt.SourceIP }
    $detailMax  = $w - (2 + 21 + 1 + 6 + 1 + 12 + 1 + 20 + 1 + 16 + 1 + 13 + 1)
    $detailStr  = if ($detailMax -gt 0 -and $Evt.Detail.Length -gt $detailMax) {
                      $Evt.Detail.Substring(0, $detailMax)
                  } else { $Evt.Detail }

    $protoColor  = Get-ProtocolColor -Protocol $Evt.Protocol -Result $Evt.Result
    $resultColor = switch ($Evt.Result) {
                       'SUCCESS' { [ConsoleColor]::Green  }
                       'FAILURE' { [ConsoleColor]::Red    }
                       'WARNING' { [ConsoleColor]::Yellow }
                       default   { [ConsoleColor]::Gray   }
                   }
    $dimColor  = [ConsoleColor]::DarkGray
    $textColor = [ConsoleColor]::Gray
    $prev        = [Console]::ForegroundColor

    # Indent + DateTime
    [Console]::ForegroundColor = $dimColor
    [Console]::Write('  ' + (Fit $Evt.DateTime 21) + ' ')

    # Result tag
    [Console]::ForegroundColor = $resultColor
    [Console]::Write((Fit $resultTag 6) + ' ')

    # Protocol (color-coded)
    [Console]::ForegroundColor = $protoColor
    [Console]::Write((Fit $Evt.Protocol 12) + ' ')

    # Username, SourceIP, LogonType, Detail
    [Console]::ForegroundColor = $textColor
    [Console]::Write((Fit $userStr 20) + ' ')
    [Console]::Write((Fit $ipStr   16) + ' ')
    [Console]::Write((Fit $Evt.LogonType 13) + ' ')
    [Console]::Write($detailStr)

    # Pad remainder to erase any leftover chars from previous longer line
    $written = 2 + 21 + 1 + 6 + 1 + 12 + 1 + 20 + 1 + 16 + 1 + 13 + 1 + $detailStr.Length
    $pad = $w - $written
    if ($pad -gt 0) { [Console]::Write(' ' * $pad) }

    [Console]::ForegroundColor = $prev
}

# Render the complete TUI: header + events + footer.
# Called after every poll cycle.
function Render-TUI {
    param(
        [System.Collections.Generic.List[PSCustomObject]]$Buffer,
        [hashtable]$Stats,
        [string[]]$ActiveLogs
    )

    $w          = [Math]::Max(1, [Console]::WindowWidth - 1)
    $h          = [Console]::WindowHeight
    $border     = '-' * $w
    $eventRows  = [Math]::Max(0, $h - $HEADER_ROWS - $FOOTER_ROWS)

    [Console]::CursorVisible = $false

    # ── Header (rows 0-4) ──────────────────────────────────────────────────
    Write-TUIRow 0 $border ([ConsoleColor]::DarkCyan)

    $title = "  Watch-AuthEvents v$VERSION  |  $(Get-Date -Format 'HH:mm:ss')  |  $env:COMPUTERNAME  |  Poll:${PollInterval}s  |  Filter:$Protocol"
    Write-TUIRow 1 $title ([ConsoleColor]::Cyan)

    Write-TUIRow 2 $border ([ConsoleColor]::DarkCyan)

    $colHdr = "  {0,-21} {1,-6} {2,-12} {3,-20} {4,-16} {5,-13} {6}" -f `
              'DateTime','Result','Protocol','Username','SourceIP','LogonType','Detail'
    Write-TUIRow 3 $colHdr ([ConsoleColor]::White)

    Write-TUIRow 4 $border ([ConsoleColor]::DarkCyan)

    # ── Events ────────────────────────────────────────────────────────────
    $startIdx = [Math]::Max(0, $Buffer.Count - $eventRows)
    $toShow   = $Buffer.Count - $startIdx

    for ($i = 0; $i -lt $eventRows; $i++) {
        $row = $HEADER_ROWS + $i
        if ($i -lt $toShow) {
            Write-EventRow -Row $row -Evt $Buffer[$startIdx + $i]
        } else {
            Write-TUIRow $row '' ([ConsoleColor]::Black)
        }
    }

    # ── Footer (last 2 rows) ───────────────────────────────────────────────
    $footerRow = $h - $FOOTER_ROWS
    Write-TUIRow $footerRow $border ([ConsoleColor]::DarkCyan)

    # Stats + color legend (written segment by segment for inline coloring)
    [Console]::SetCursorPosition(0, $h - 1)
    $prev = [Console]::ForegroundColor

    [Console]::ForegroundColor = [ConsoleColor]::White
    [Console]::Write("  Total:$($Stats.Total) ")

    [Console]::ForegroundColor = [ConsoleColor]::Green
    [Console]::Write("[OK]:$($Stats.Success) ")

    [Console]::ForegroundColor = [ConsoleColor]::Red
    [Console]::Write("[FAIL]:$($Stats.Failure) ")

    [Console]::ForegroundColor = [ConsoleColor]::DarkGray
    [Console]::Write(' | ')

    foreach ($entry in @(
        @{ Name = 'NTLM';         Color = [ConsoleColor]::Yellow      },
        @{ Name = 'NTLM-Local';   Color = [ConsoleColor]::DarkYellow },
        @{ Name = 'Kerberos';     Color = [ConsoleColor]::Cyan       },
        @{ Name = 'WinRM';        Color = [ConsoleColor]::Magenta    },
        @{ Name = 'RDP';          Color = [ConsoleColor]::DarkGreen},
        @{ Name = 'ExplicitCred'; Color = [ConsoleColor]::DarkYellow },
        @{ Name = 'LDAP';         Color = [ConsoleColor]::Green      }
    )) {
        [Console]::ForegroundColor = $entry.Color
        [Console]::Write($entry.Name + '  ')
    }

    [Console]::ForegroundColor = [ConsoleColor]::DarkGray
    $logMsg = if ($NoLog) { '' } else { " | Log: $(Split-Path $LogPath -Leaf)" }
    [Console]::Write("| Ctrl+C exit$logMsg")

    # Pad to end of line
    $curX = [Console]::CursorLeft
    if ($curX -lt $w) { [Console]::Write(' ' * ($w - $curX)) }

    [Console]::ForegroundColor = $prev
}

function Resolve-Protocol {
    param([string]$AuthPackage, [int]$EventID)
    switch -Regex ($AuthPackage) {
        'Kerberos'                          { return 'Kerberos' }
        'NTLM|MICROSOFT_AUTHENTICATION'     { return 'NTLM' }
        'Negotiate'                         { return 'Negotiate' }
        'WDigest|CloudAP|LiveSSP'           { return $AuthPackage }
        default {
            if ($EVENTID_PROTOCOL.ContainsKey($EventID)) {
                return $EVENTID_PROTOCOL[$EventID]
            }
            return $AuthPackage
        }
    }
}

function Get-FailureReason {
    param([string]$StatusCode, [string]$SubStatusCode)
    $code = if ($SubStatusCode -and $SubStatusCode -notin @('0x0','0x00000000','-')) {
        $SubStatusCode
    } else {
        $StatusCode
    }
    if ($code -and $FAILURE_CODES.ContainsKey($code)) {
        return "$code ($($FAILURE_CODES[$code]))"
    }
    return $code
}

function Test-LogExists {
    param([string]$LogName)
    $result = Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue
    return ($null -ne $result)
}

function Initialize-CsvLog {
    param([string]$Path)
    if (-not $NoLog) {
        $header = 'DateTime,Result,Protocol,EventID,Username,Domain,SourceIP,WorkstationName,LogonType,Detail,RawMessage'
        $header | Out-File -FilePath $Path -Encoding UTF8 -Force
    }
}

function Write-CsvLine {
    param([PSCustomObject]$evt, [string]$Path)
    if ($NoLog) { return }
    $line = '"{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}","{9}","{10}"' -f `
        $evt.DateTime, $evt.Result, $evt.Protocol, $evt.EventID,
        $evt.Username, $evt.Domain, $evt.SourceIP, $evt.WorkstationName,
        $evt.LogonType, $evt.Detail, ($evt.RawMessage -replace '"',"'")
    $line | Out-File -FilePath $Path -Append -Encoding UTF8
}

#endregion

#region ── Event Parsers ──────────────────────────────────────────────────────

function Parse-SecurityEvent {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)

    $xml  = [xml]$Event.ToXml()
    $data = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        if ($node.Name) { $data[$node.Name] = $node.'#text' }
    }

    $eventId = $Event.Id
    $result  = if ($eventId -in @(4624,4648,4768,4769,4770)) { 'SUCCESS' } else { 'FAILURE' }

    if ($eventId -eq 4624) {
        $logonType = [int](Nvl $data['LogonType'] 0)
        if ($logonType -in @(0)) { return $null }
        $un = Nvl $data['TargetUserName'] ''
        if ($un -in @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE') -or $un -match '\$$') { return $null }
    }

    $username    = Nvl $data['TargetUserName']   $data['ClientName']    '-'
    $domain      = Nvl $data['TargetDomainName'] $data['ClientRealm']   '-'
    $sourceIP    = Nvl $data['IpAddress']        $data['ClientAddress'] '-'
    $workstation = Nvl $data['WorkstationName']  $data['ClientName']    '-'
    $authPkg     = Nvl $data['AuthenticationPackageName'] $data['PackageName'] ''
    $logonProcess = (Nvl $data['LogonProcessName'] '').Trim()
    $logonTypeN  = Nvl $data['LogonType'] '0'
    $logonTypeS  = Nvl $LOGON_TYPE[[int]$logonTypeN] $logonTypeN

    $sourceIP = $sourceIP -replace '^::ffff:',''

    $protocol = Resolve-Protocol -AuthPackage $authPkg -EventID $eventId

    # For 4624 with NTLM auth package: distinguish real network NTLM from
    # LDAP simple bind / LogonUser() API calls that also use NTLM internally.
    #   LogonProcessName = 'NtLmSsp'  -> NTLM Security Support Provider, real network NTLM
    #   LogonProcessName = 'Advapi'   -> Windows Advanced API — confirmed signature of LDAP
    #                                    simple binds (AuthPkg=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0)
    # Using -ne 'NtLmSsp' is more robust: any NTLM-package 4624 that did NOT come
    # through the actual NTLM SSP is internal/local regardless of the exact process name.
    if ($eventId -eq 4624 -and $protocol -eq 'NTLM' -and $logonProcess -ne 'NtLmSsp') {
        $protocol = 'NTLM-Local'
    }

    # For 4776: three cases based on SourceIP and WorkstationName:
    #   1. Has SourceIP                          -> network NTLM direct to DC        -> NTLM
    #   2. No SourceIP, real WorkstationName     -> NTLM pass-through via member srv -> NTLM
    #   3. No SourceIP, no WorkstationName       -> LDAP simple bind / local svc     -> NTLM-Local
    $is4776NoIP = ($eventId -eq 4776) -and ($sourceIP -in @('-','','127.0.0.1','::1') -or $null -eq $sourceIP)
    $ws4776     = ($workstation).Trim() -replace '^-$',''
    $is4776PassThrough = $is4776NoIP -and ($ws4776 -and $ws4776 -notin @('','localhost','127.0.0.1'))
    $is4776Local       = $is4776NoIP -and (-not $is4776PassThrough)
    if ($is4776Local) { $protocol = 'NTLM-Local' }

    # LogonType 10 = RemoteInteractive = RDP session
    # LogonType 7 from a non-local IP = RDP reconnect/session unlock
    if ($eventId -in @(4624, 4625) -and $logonTypeN -eq '10') { $protocol = 'RDP' }
    if ($eventId -in @(4624, 4625) -and $logonTypeN -eq '7' -and $sourceIP -notin @('-','','127.0.0.1','::1')) { $protocol = 'RDP' }

    # 4769 SPN-based reclassification: detect service from Kerberos ticket SPN
    $serviceName = (Nvl $data['ServiceName'] '').Trim()
    if ($eventId -eq 4769) {
        if     ($serviceName -match '^(HTTP|WSMAN)/')   { $protocol = 'WinRM' }
        elseif ($serviceName -match '^TERMSRV/')        { $protocol = 'RDP'   }
        elseif ($serviceName -match '^(cifs|host|rpc)/' -or $serviceName -match '\$$') { $protocol = 'Kerberos' }
    }

    $detail = switch ($eventId) {
        4624 { "LogonType=$logonTypeS AuthPkg=$authPkg LogonProc=$logonProcess" }
        4625 { Get-FailureReason -StatusCode (Nvl $data['Status'] '') -SubStatusCode (Nvl $data['SubStatus'] '') }
        4648 { "Target=$(Nvl $data['TargetServerName'] '-') Process=$(Nvl $data['ProcessName'] '-')" }
        4768 { "Ticket=$(Nvl $data['TicketOptions'] '-') EncType=$(Nvl $data['TicketEncryptionType'] '-')" }
        4769 { "Service=$serviceName EncType=$(Nvl $data['TicketEncryptionType'] '-')" }
        4770 { "Service=$(Nvl $data['ServiceName'] '-')" }
        4771 { Get-FailureReason -StatusCode (Nvl $data['Status'] '') -SubStatusCode '' }
        4772 { Get-FailureReason -StatusCode (Nvl $data['Status'] '') -SubStatusCode '' }
        4776 {
            $err = Nvl $data['Status'] ''
            $valResult = if ($err -ne '0x0') { Get-FailureReason -StatusCode $err -SubStatusCode '' } else { 'OK' }
            if ($is4776PassThrough) {
                "NTLM-Validate $valResult [pass-through via $ws4776]"
            } elseif ($is4776Local) {
                "NTLM-Validate $valResult [LDAP simple bind or local svc]"
            } else {
                "NTLM-Validate $valResult [direct from $sourceIP]"
            }
        }
        default { "EventID=$eventId" }
    }

    if ($eventId -eq 4776) {
        $result = if ((Nvl $data['Status'] '0x0') -eq '0x0') { 'SUCCESS' } else { 'FAILURE' }
    }

    return [PSCustomObject]@{
        DateTime        = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        Result          = $result
        Protocol        = $protocol
        EventID         = $eventId
        Username        = $username
        Domain          = $domain
        SourceIP        = $sourceIP
        WorkstationName = $workstation
        LogonType       = $logonTypeS
        Detail          = $detail
        RawMessage      = ''
    }
}

function Parse-NTLMEvent {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)

    $xml  = [xml]$Event.ToXml()
    $data = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        if ($node.Name) { $data[$node.Name] = $node.'#text' }
    }

    $result = switch ($Event.Id) {
        8001    { 'SUCCESS' }
        8002    { 'FAILURE' }
        8003    { 'FAILURE' }
        default { 'FAILURE' }
    }
    $detail = switch ($Event.Id) {
        8001    { 'NTLM auth succeeded' }
        8002    { 'NTLM BLOCKED (domain policy - RestrictNTLMInDomain)' }
        8003    { 'NTLM BLOCKED (server policy - RestrictNTLMToRemoteServer)' }
        8004    { 'NTLM auth attempted on DC' }
        default { "NTLM EventID=$($Event.Id)" }
    }
    if ($data['WorkstationName']) { $detail += " Workstation=$($data['WorkstationName'])" }

    return [PSCustomObject]@{
        DateTime        = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        Result          = $result
        Protocol        = 'NTLM'
        EventID         = $Event.Id
        Username        = Nvl $data['UserName'] $data['TargetUserName'] '-'
        Domain          = Nvl $data['DomainName'] '-'
        SourceIP        = Nvl $data['ClientAddress'] '-'
        WorkstationName = Nvl $data['WorkstationName'] '-'
        LogonType       = '-'
        Detail          = $detail
        RawMessage      = ''
    }
}

function Parse-WinRMEvent {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)

    $msg      = $Event.FormatDescription()
    $username = '-'
    $domain   = '-'

    if ($msg -match 'User\s+(\S+)\\(\S+)') {
        $domain   = $Matches[1]
        $username = $Matches[2]
    } elseif ($msg -match 'User\s+(\S+@\S+)') {
        $parts    = $Matches[1] -split '@'
        $username = $parts[0]
        $domain   = $parts[1]
    }

    $result = if ($Event.Id -eq 169) { 'SUCCESS' } else { 'FAILURE' }

    return [PSCustomObject]@{
        DateTime        = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        Result          = $result
        Protocol        = 'WinRM'
        EventID         = $Event.Id
        Username        = $username
        Domain          = $domain
        SourceIP        = '-'
        WorkstationName = '-'
        LogonType       = 'Network'
        Detail          = "WinRM EventID=$($Event.Id)"
        RawMessage      = (Nvl $msg '') -replace "`r`n",' '
    }
}

function Parse-KDCEvent {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)

    $xml  = [xml]$Event.ToXml()
    $data = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        if ($node.Name) { $data[$node.Name] = $node.'#text' }
    }

    return [PSCustomObject]@{
        DateTime        = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        Result          = 'INFO'
        Protocol        = 'Kerberos'
        EventID         = $Event.Id
        Username        = Nvl $data['TargetUserName'] '-'
        Domain          = Nvl $data['TargetDomainName'] '-'
        SourceIP        = Nvl $data['ClientAddress'] '-'
        WorkstationName = '-'
        LogonType       = '-'
        Detail          = "KDC EventID=$($Event.Id)"
        RawMessage      = ''
    }
}

function Parse-LDAPEvent {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)

    # Event 2889 message layout (values appear on the line AFTER the label, tab-indented):
    #   Client IP address:
    #       172.16.201.24:49152
    #   Identity the client attempted to authenticate as:
    #       Administrator@asgard.local   (or full DN: CN=...,DC=...)
    #   Binding Type:
    #       0   (0=SimpleBind/cleartext  3=SASL-without-signing)
    #
    # NOTE: Passwords are NOT present in any Windows event log, even for cleartext
    # simple binds. Password content is only recoverable from a packet capture.
    # LDAP search queries/filters are also not logged by standard Windows events.

    $msg        = $Event.FormatDescription()
    $sourceIP   = '-'
    $clientPort = '-'
    $identity   = '-'
    $bindType   = '-'
    $detail     = ''

    # Helper: extract the value that appears on the line after a given label
    # Handles \r\n\t and \n\t indentation, and inline "label: value" as fallback
    function Get-EventField {
        param([string]$Text, [string]$Label)
        # Value on next line (tab-indented) — primary format for NTDS events
        if ($Text -match "$Label[^:]*:\s*\r?\n\t([^\r\n]+)") { return $Matches[1].Trim() }
        # Value inline after colon — fallback
        if ($Text -match "$Label[^:]*:\s*([^\r\n]+)")         { return $Matches[1].Trim() }
        return $null
    }

    switch ($Event.Id) {
        { $_ -in @(2889, 2888) } {
            $ipPort = Get-EventField $msg 'Client IP address'
            if ($ipPort) {
                # Split "172.16.201.24:49152" into IP and port
                if ($ipPort -match '^(.+):(\d+)$') {
                    $sourceIP   = $Matches[1]
                    $clientPort = $Matches[2]
                } else {
                    $sourceIP = $ipPort
                }
            }

            $identity = Get-EventField $msg 'Identity the client attempted to authenticate as'
            if (-not $identity) { $identity = '-' }

            $bindTypeRaw = Get-EventField $msg 'Binding Type'
            $bindType    = switch ($bindTypeRaw) {
                '0'     { 'SimpleBind/Cleartext' }
                '3'     { 'SASL-NoSigning' }
                default { "BindType=$bindTypeRaw" }
            }

            # Full DN goes in Detail since Username column truncates at 20 chars
            $detail = "$bindType Port=$clientPort Identity=$identity"
        }
        2887 {
            $count = if ($msg -match '(\d+)\s+such bind') { $Matches[1] } else { '-' }
            $detail = "Unsigned/weak binds in last 24h: $count"
        }
        2886 {
            $detail = 'LDAP signing not enforced on this DC'
        }
        default { $detail = "LDAP EventID=$($Event.Id)" }
    }

    # Shorten DN to a readable username for the Username column
    # "CN=KELDA_ICEBORN,OU=..." -> "KELDA_ICEBORN"  |  "user@domain" stays as-is
    $displayName = $identity
    if ($identity -match '^CN=([^,]+),') { $displayName = $Matches[1] }

    $result = if ($Event.Id -in @(2888, 2889)) { 'WARNING' } else { 'INFO' }

    return [PSCustomObject]@{
        DateTime        = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        Result          = $result
        Protocol        = 'LDAP'
        EventID         = $Event.Id
        Username        = $displayName
        Domain          = '-'
        SourceIP        = $sourceIP
        WorkstationName = '-'
        LogonType       = 'Network'
        Detail          = $detail
        RawMessage      = (Nvl $msg '') -replace "`r`n",' '
    }
}

function Parse-RDPEvent {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)

    $xml  = [xml]$Event.ToXml()
    $data = @{}
    # Event 1149 uses EventData; events 21/23/24/25 use UserData
    foreach ($node in $xml.Event.EventData.Data) {
        if ($node.Name) { $data[$node.Name] = $node.'#text' }
    }
    $udNode = $xml.Event.UserData
    if ($udNode -and $udNode.HasChildNodes) {
        foreach ($child in $udNode.FirstChild.ChildNodes) {
            $data[$child.LocalName] = $child.'#text'
        }
    }

    $username = '-'
    $domain   = '-'
    $sourceIP = '-'
    $result   = 'SUCCESS'
    $detail   = ''

    switch ($Event.Id) {
        1149 {
            # RemoteConnectionManager: User authentication succeeded (has source IP)
            $username = (Nvl $data['Param1'] '-').Trim()
            $domain   = (Nvl $data['Param2'] '-').Trim()
            $sourceIP = (Nvl $data['Param3'] '-').Trim()
            $detail   = 'RDP auth succeeded'
        }
        21 {
            $userRaw  = (Nvl $data['User'] '-').Trim()
            if ($userRaw -match '^(.+)\\(.+)$') { $domain = $Matches[1]; $username = $Matches[2] }
            else { $username = $userRaw }
            $sourceIP = (Nvl $data['Address'] '-').Trim()
            $detail   = "Session logon SessionID=$(Nvl $data['SessionID'] '-')"
        }
        23 {
            $userRaw  = (Nvl $data['User'] '-').Trim()
            if ($userRaw -match '^(.+)\\(.+)$') { $domain = $Matches[1]; $username = $Matches[2] }
            else { $username = $userRaw }
            $sourceIP = (Nvl $data['Address'] '-').Trim()
            $result   = 'INFO'
            $detail   = "Session logoff SessionID=$(Nvl $data['SessionID'] '-')"
        }
        24 {
            $userRaw  = (Nvl $data['User'] '-').Trim()
            if ($userRaw -match '^(.+)\\(.+)$') { $domain = $Matches[1]; $username = $Matches[2] }
            else { $username = $userRaw }
            $sourceIP = (Nvl $data['Address'] '-').Trim()
            $result   = 'INFO'
            $detail   = "Session disconnect SessionID=$(Nvl $data['SessionID'] '-')"
        }
        25 {
            $userRaw  = (Nvl $data['User'] '-').Trim()
            if ($userRaw -match '^(.+)\\(.+)$') { $domain = $Matches[1]; $username = $Matches[2] }
            else { $username = $userRaw }
            $sourceIP = (Nvl $data['Address'] '-').Trim()
            $detail   = "Session reconnect SessionID=$(Nvl $data['SessionID'] '-')"
        }
    }

    $sourceIP = $sourceIP -replace '^::ffff:',''

    return [PSCustomObject]@{
        DateTime        = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        Result          = $result
        Protocol        = 'RDP'
        EventID         = $Event.Id
        Username        = $username
        Domain          = $domain
        SourceIP        = $sourceIP
        WorkstationName = '-'
        LogonType       = 'RemoteInteractive'
        Detail          = $detail
        RawMessage      = ''
    }
}

#endregion

#region ── Filter ─────────────────────────────────────────────────────────────

function Test-EventFilter {
    param([PSCustomObject]$evt)

    if (-not $IncludeSuccesses -and $evt.Result -eq 'SUCCESS') { return $false }
    if (-not $IncludeFailures  -and $evt.Result -eq 'FAILURE') { return $false }

    if ($Protocol -ne 'All') {
        if ($evt.Protocol -notmatch $Protocol) { return $false }
    }

    if ($UserFilter -ne '*') {
        if ($evt.Username -notlike $UserFilter) { return $false }
    }

    if ($IPFilter -ne '*') {
        if ($evt.SourceIP -notlike $IPFilter) { return $false }
    }

    return $true
}

#endregion

#region ── Poll Engine ────────────────────────────────────────────────────────

function Get-NewEvents {
    param(
        [string]$LogName,
        [int[]]$EventIDs,
        [datetime]$Since,
        [string]$SourceKey
    )

    if (-not (Test-LogExists -LogName $LogName)) { return @() }

    $filter = @{
        LogName   = $LogName
        Id        = $EventIDs
        StartTime = $Since
    }

    try {
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
        return $events
    } catch [System.Exception] {
        if ($_.Exception.Message -notmatch 'No events were found') {
            Write-Verbose "[$SourceKey] Query error: $($_.Exception.Message)"
        }
        return @()
    }
}

function Process-Event {
    param(
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event,
        [string]$SourceKey
    )

    $parsed = switch ($SourceKey) {
        'Security' { Parse-SecurityEvent -Event $Event }
        'NTLM'     { Parse-NTLMEvent     -Event $Event }
        'WinRM'    { Parse-WinRMEvent    -Event $Event }
        'KDC'              { Parse-KDCEvent   -Event $Event }
        'DirectoryService' { Parse-LDAPEvent  -Event $Event }
        'RDPRemote'        { Parse-RDPEvent   -Event $Event }
        'RDPLocal'         { Parse-RDPEvent   -Event $Event }
        default            { $null }
    }

    if ($null -ne $parsed) {
        $parsed.Detail = "[EID:$($Event.Id)] " + $parsed.Detail
    }

    return $parsed
}

#endregion

#region ── Main ───────────────────────────────────────────────────────────────

function Main {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script requires Administrator privileges."
        exit 1
    }

    # ── Startup probe (before clearing screen) ────────────────────────────
    $activeSources = @{}
    $activeLogs    = @()
    foreach ($key in $LOG_SOURCES.Keys) {
        $src = $LOG_SOURCES[$key]
        if (Test-LogExists -LogName $src.LogName) {
            $activeSources[$key] = $src
            $activeLogs += $key
        }
    }

    if ($activeSources.Count -eq 0) {
        Write-Error "No usable event logs found. Check permissions."
        exit 1
    }

    if (-not $NoLog) { Initialize-CsvLog -Path $LogPath }

    # ── Switch to TUI mode ────────────────────────────────────────────────
    $savedCursorVisible = [Console]::CursorVisible
    [Console]::CursorVisible = $false
    Clear-Host

    # Rolling event buffer - keep last 500 for display/scroll
    $buffer  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $maxBuf  = 500

    $seenIds = @{}
    foreach ($key in $activeSources.Keys) {
        $seenIds[$key] = [System.Collections.Generic.HashSet[long]]::new()
    }

    $lastPoll = (Get-Date).AddMinutes(-$LookbackMinutes)
    $stats    = @{ Total = 0; Success = 0; Failure = 0 }

    # Initial render (empty event area)
    Render-TUI -Buffer $buffer -Stats $stats -ActiveLogs $activeLogs

    try {
        while ($true) {
            $pollStart  = Get-Date
            $since      = $lastPoll.AddSeconds(-2)
            $newEvents  = 0

            foreach ($key in $activeSources.Keys) {
                $src    = $activeSources[$key]
                $events = Get-NewEvents -LogName $src.LogName -EventIDs $src.EventIDs -Since $since -SourceKey $key

                foreach ($event in $events) {
                    try {
                        $rid = [long]$event.RecordId
                        if ($seenIds[$key].Contains($rid)) { continue }
                        [void]$seenIds[$key].Add($rid)

                        $parsed = Process-Event -Event $event -SourceKey $key
                        if ($null -eq $parsed) { continue }
                        if (-not (Test-EventFilter -evt $parsed)) { continue }

                        $buffer.Add($parsed)
                        if ($buffer.Count -gt $maxBuf) { $buffer.RemoveAt(0) }

                        Write-CsvLine -evt $parsed -Path $LogPath

                        $stats['Total']++
                        if ($parsed.Result -eq 'SUCCESS') { $stats['Success']++ } else { $stats['Failure']++ }
                        $newEvents++
                    } catch {
                        Write-Verbose "[$key] Skipped event $($event.Id): $($_.Exception.Message)"
                    }
                }

                if ($seenIds[$key].Count -gt 5000) {
                    $seenIds[$key] = [System.Collections.Generic.HashSet[long]]::new()
                }
            }

            # Redraw every poll (always refreshes the clock and stats)
            Render-TUI -Buffer $buffer -Stats $stats -ActiveLogs $activeLogs

            $lastPoll = $pollStart
            Start-Sleep -Seconds $PollInterval
        }
    } finally {
        # Restore terminal state
        [Console]::CursorVisible = $savedCursorVisible
        [Console]::SetCursorPosition(0, [Console]::WindowHeight - 1)
        [Console]::ResetColor()
        Write-Host ""
        Write-Host "Session ended $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  Total:$($stats['Total'])  OK:$($stats['Success'])  FAIL:$($stats['Failure'])" -ForegroundColor Cyan
        if (-not $NoLog) {
            Write-Host "Log: $LogPath" -ForegroundColor DarkGray
        }
    }
}

Main
