<#
.SYNOPSIS
    Backs up all DNS zones to CSV, JSON, and console output.

.DESCRIPTION
    Enumerates all DNS zones on the target server, retrieves every resource
    record, and produces three outputs:
      - Console: formatted table (Zone, Name, Type, Data)
      - CSV:  human-readable dns-chart-YYYY-MM-DD-HHmmss.csv
      - JSON: machine-readable dns-backup-YYYY-MM-DD-HHmmss.json (for Restore-DNS.ps1)

.PARAMETER DnsServer
    DNS server to query. Defaults to localhost.

.PARAMETER OutputDir
    Directory for CSV and JSON files. Defaults to current directory.

.EXAMPLE
    .\Backup-DNS.ps1 -DnsServer dc01 -OutputDir C:\Backups
#>

[CmdletBinding()]
param(
    [string]$DnsServer = "localhost",
    [string]$OutputDir = "."
)

# --- Bootstrap ---------------------------------------------------------------
. "$PSScriptRoot\..\Common.ps1"
Write-Banner -ScriptName "Backup-DNS"
Assert-Role -Required "DomainController"
Assert-Dependencies -Modules @("DnsServer")

# --- Helpers -----------------------------------------------------------------

function Get-RecordDataString {
    <#
    .SYNOPSIS
        Returns a single human-readable string for a DNS resource record.
    #>
    param(
        [Parameter(Mandatory)]
        $Record
    )

    switch ($Record.RecordType) {
        "A"     { return $Record.RecordData.IPv4Address.ToString() }
        "AAAA"  { return $Record.RecordData.IPv6Address.ToString() }
        "CNAME" { return $Record.RecordData.HostNameAlias }
        "MX"    { return "$($Record.RecordData.Preference) $($Record.RecordData.MailExchange)" }
        "NS"    { return $Record.RecordData.NameServer }
        "PTR"   { return $Record.RecordData.PtrDomainName }
        "SRV"   {
            $d = $Record.RecordData
            return "$($d.Priority) $($d.Weight) $($d.Port) $($d.DomainName)"
        }
        "SOA"   {
            $d = $Record.RecordData
            return "$($d.PrimaryServer) $($d.ResponsiblePerson) $($d.SerialNumber)"
        }
        "TXT"   { return ($Record.RecordData.DescriptiveText -join " ") }
        default { return $Record.RecordData.ToString() }
    }
}

# --- Main --------------------------------------------------------------------

$timestamp = Get-Date -Format "yyyy-MM-dd-HHmmss"
$csvPath   = Join-Path $OutputDir "dns-chart-$timestamp.csv"
$jsonPath  = Join-Path $OutputDir "dns-backup-$timestamp.json"

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Enumerate zones, skip TrustAnchors and _msdcs auto-created zones
$zones = Get-DnsServerZone -ComputerName $DnsServer |
    Where-Object {
        $_.ZoneType -ne "TrustAnchors" -and
        $_.ZoneName -notlike "_msdcs.*"
    }

$chartRows  = [System.Collections.ArrayList]::new()
$backupData = [System.Collections.ArrayList]::new()

foreach ($zone in $zones) {
    Write-Host "Processing zone: $($zone.ZoneName)" -ForegroundColor Cyan

    $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ComputerName $DnsServer

    foreach ($rec in $records) {
        # Human-readable row for console + CSV
        $row = [PSCustomObject]@{
            Zone = $zone.ZoneName
            Name = $rec.HostName
            Type = $rec.RecordType
            Data = Get-RecordDataString -Record $rec
        }
        [void]$chartRows.Add($row)

        # Full-fidelity object for JSON restore
        $backupEntry = [PSCustomObject]@{
            ZoneName       = $zone.ZoneName
            HostName       = $rec.HostName
            RecordType     = $rec.RecordType
            TimeToLive     = $rec.TimeToLive.ToString()
            RecordData     = @{}
        }

        # Capture type-specific RecordData properties
        switch ($rec.RecordType) {
            "A"     { $backupEntry.RecordData = @{ IPv4Address = $rec.RecordData.IPv4Address.ToString() } }
            "AAAA"  { $backupEntry.RecordData = @{ IPv6Address = $rec.RecordData.IPv6Address.ToString() } }
            "CNAME" { $backupEntry.RecordData = @{ HostNameAlias = $rec.RecordData.HostNameAlias } }
            "MX"    { $backupEntry.RecordData = @{ Preference = $rec.RecordData.Preference; MailExchange = $rec.RecordData.MailExchange } }
            "NS"    { $backupEntry.RecordData = @{ NameServer = $rec.RecordData.NameServer } }
            "PTR"   { $backupEntry.RecordData = @{ PtrDomainName = $rec.RecordData.PtrDomainName } }
            "SRV"   { $backupEntry.RecordData = @{ Priority = $rec.RecordData.Priority; Weight = $rec.RecordData.Weight; Port = $rec.RecordData.Port; DomainName = $rec.RecordData.DomainName } }
            "SOA"   { $backupEntry.RecordData = @{ PrimaryServer = $rec.RecordData.PrimaryServer; ResponsiblePerson = $rec.RecordData.ResponsiblePerson; SerialNumber = $rec.RecordData.SerialNumber; RefreshInterval = $rec.RecordData.RefreshInterval.ToString(); RetryDelay = $rec.RecordData.RetryDelay.ToString(); ExpireLimit = $rec.RecordData.ExpireLimit.ToString(); MinimumTimeToLive = $rec.RecordData.MinimumTimeToLive.ToString() } }
            "TXT"   { $backupEntry.RecordData = @{ DescriptiveText = $rec.RecordData.DescriptiveText } }
            default { $backupEntry.RecordData = @{ Raw = $rec.RecordData.ToString() } }
        }

        [void]$backupData.Add($backupEntry)
    }
}

# --- Output: Console ---------------------------------------------------------
Write-Host "`n--- DNS Record Chart ---" -ForegroundColor Green
$chartRows | Format-Table -AutoSize

# --- Output: CSV (unquoted) --------------------------------------------------
$csvLines = [System.Collections.ArrayList]::new()
[void]$csvLines.Add("zone,name,type,data")
foreach ($r in $chartRows) {
    [void]$csvLines.Add("$($r.Zone),$($r.Name),$($r.Type),$($r.Data)")
}
$csvLines -join "`n" | Set-Content -Path $csvPath -Encoding UTF8 -NoNewline
Write-Host "CSV saved to: $csvPath" -ForegroundColor Green

# --- Output: JSON -------------------------------------------------------------
$backupData | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
Write-Host "JSON backup saved to: $jsonPath" -ForegroundColor Green

Write-Host "`nTotal records backed up: $($chartRows.Count)" -ForegroundColor Yellow
