<#
.SYNOPSIS
    Monitors authentication events (logon success and failure) with human-readable output.

.DESCRIPTION
    Polls the Security event log every 15 seconds for:
      - Event 4624: Successful logon
      - Event 4625: Failed logon
    Translates logon type codes and failure status codes into readable strings.
    Filters out Service (5) and System (0) logon types by default.

    Output is color-coded: green for success, red for failure. Each event is
    printed as a single line with timestamp, user, source IP, logon type, and
    (for failures) the reason.

.PARAMETER ShowAll
    Include Service (type 5) and System (type 0) logon events, which are
    filtered out by default to reduce noise.

.EXAMPLE
    .\Watch-Logons.ps1
    Monitor logons, hiding Service/System noise.

.EXAMPLE
    .\Watch-Logons.ps1 -ShowAll
    Monitor all logon types including Service and System.

.NOTES
    Requires an elevated (Administrator) PowerShell session.
    Dot-sources Common.ps1 for Write-Banner and Assert-Role.
#>

param(
    [switch]$ShowAll
)

. "$PSScriptRoot\..\Common.ps1"

Write-Banner -ScriptName "Watch-Logons"
Assert-Role -Required @("DomainController", "MemberServer", "Workstation")
Assert-Dependencies -Commands @("Get-WinEvent")

# --- Translation tables ---

$LogonTypes = @{
    '0'  = 'System'; '2'  = 'Interactive'; '3'  = 'Network'; '4'  = 'Batch'
    '5'  = 'Service'; '7'  = 'Unlock'; '8'  = 'NetworkCleartext'
    '9'  = 'NewCredentials'; '10' = 'RemoteDesktop'; '11' = 'CachedInteractive'
}

$FailureCodes = @{
    '0xc000006d' = 'Bad username or password'; '0xc000006e' = 'Account restriction'
    '0xc0000064' = 'User does not exist'; '0xc000006a' = 'Wrong password'
    '0xc0000234' = 'Account locked out'; '0xc000015b' = 'Logon type not granted'
    '0xc0000072' = 'Account disabled'; '0xc0000193' = 'Account expired'
    '0xc0000070' = 'Workstation restriction'; '0xc0000133' = 'Clock skew too great'
}

# Logon types to filter out by default
$FilteredTypes = @('0', '5')

function Get-XmlField {
    param([System.Xml.XmlElement[]]$DataItems, [string]$Name)
    $node = $DataItems | Where-Object { $_.Name -eq $Name }
    if ($node) { return $node.'#text' }
    return $null
}

Write-Host "Monitoring logon events every 15 seconds... (Ctrl+C to stop)" -ForegroundColor Cyan
if (-not $ShowAll) {
    Write-Host "Filtering out System (0) and Service (5) logon types. Use -ShowAll to include them." -ForegroundColor Yellow
}
Write-Host ""

while ($true) {
    $startTime = (Get-Date).AddSeconds(-15)

    # --- Successful logons (4624) ---
    try {
        $successes = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4624
            StartTime = $startTime
        } -ErrorAction SilentlyContinue)
    } catch {
        $successes = @()
    }

    foreach ($evt in $successes) {
        $xml = [xml]$evt.ToXml()
        $data = $xml.Event.EventData.Data

        $user      = Get-XmlField $data 'TargetUserName'
        $ip        = Get-XmlField $data 'IpAddress'
        $typeCode  = Get-XmlField $data 'LogonType'

        # Filter noise
        if (-not $ShowAll -and $typeCode -in $FilteredTypes) { continue }

        $typeName = if ($LogonTypes.ContainsKey($typeCode)) { $LogonTypes[$typeCode] } else { "Type$typeCode" }
        if (-not $ip -or $ip -eq '-') { $ip = 'local' }

        $ts = $evt.TimeCreated.ToString("HH:mm:ss")
        Write-Host "[$ts] LOGIN   user=$user  from=$ip  type=$typeName" -ForegroundColor Green
    }

    # --- Failed logons (4625) ---
    try {
        $failures = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = $startTime
        } -ErrorAction SilentlyContinue)
    } catch {
        $failures = @()
    }

    foreach ($evt in $failures) {
        $xml = [xml]$evt.ToXml()
        $data = $xml.Event.EventData.Data

        $user      = Get-XmlField $data 'TargetUserName'
        $ip        = Get-XmlField $data 'IpAddress'
        $typeCode  = Get-XmlField $data 'LogonType'
        $status    = Get-XmlField $data 'Status'
        $subStatus = Get-XmlField $data 'SubStatus'

        # Filter noise
        if (-not $ShowAll -and $typeCode -in $FilteredTypes) { continue }

        $typeName = if ($LogonTypes.ContainsKey($typeCode)) { $LogonTypes[$typeCode] } else { "Type$typeCode" }
        if (-not $ip -or $ip -eq '-') { $ip = 'local' }

        # Prefer SubStatus for reason, fall back to Status
        $reasonCode = if ($subStatus -and $subStatus -ne '0x0') { $subStatus.ToLower() } else { $status.ToLower() }
        $reason = if ($FailureCodes.ContainsKey($reasonCode)) { $FailureCodes[$reasonCode] } else { $reasonCode }

        $ts = $evt.TimeCreated.ToString("HH:mm:ss")
        Write-Host "[$ts] FAILED  user=$user  from=$ip  type=$typeName  reason=$reason" -ForegroundColor Red
    }

    Start-Sleep -Seconds 15
}
