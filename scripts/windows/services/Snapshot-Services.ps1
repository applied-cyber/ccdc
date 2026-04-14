<#
.SYNOPSIS
    Captures full state of every Windows service for baselining and comparison.
.DESCRIPTION
    Snapshots each service's name, display name, SDDL (security descriptor), binary path,
    startup type, running state, and logon account. Outputs JSON for machine use and a
    console summary table for quick review.

    Used as a baseline by Lock-Services.ps1 and Watch-Services.ps1.

.PARAMETER OutputFile
    Path for the JSON snapshot. Default: services-snapshot.json in the script directory.
#>
param(
    [string]$OutputFile = (Join-Path $PSScriptRoot "services-snapshot.json")
)

. "$PSScriptRoot\..\Common.ps1"
Write-Banner -ScriptName "Snapshot-Services"

$services = Get-Service | ForEach-Object {
    $svc = $_
    $name = $svc.Name

    # Get SDDL via sc.exe
    $sddl = ""
    try {
        $sdOutput = sc.exe sdshow $name 2>&1
        # sc sdshow returns the SDDL string on its own line
        $sddlLine = ($sdOutput | Where-Object { $_ -match '^D:' -or $_ -match '^O:' }) | Select-Object -First 1
        if ($sddlLine) { $sddl = $sddlLine.Trim() }
    } catch {}

    # Get binary path and logon account from registry
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    $imagePath = ""
    $logonAs = ""
    try {
        $regKey = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        if ($regKey) {
            $imagePath = $regKey.ImagePath
            $logonAs = $regKey.ObjectName
        }
    } catch {}

    [PSCustomObject]@{
        Name        = $name
        DisplayName = $svc.DisplayName
        Status      = $svc.Status.ToString()
        StartType   = $svc.StartType.ToString()
        SDDL        = $sddl
        ImagePath   = $imagePath
        LogonAs     = $logonAs
    }
}

# Write JSON
$services | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputFile -Encoding UTF8
Write-Host "Snapshot saved to: $OutputFile" -ForegroundColor Green
Write-Host "$($services.Count) services captured."

# Console summary
$services | Sort-Object Name |
    Format-Table Name, Status, StartType, LogonAs, @{L='BinaryPath';E={
        if ($_.ImagePath.Length -gt 60) { $_.ImagePath.Substring(0,57) + "..." } else { $_.ImagePath }
    }} -AutoSize
