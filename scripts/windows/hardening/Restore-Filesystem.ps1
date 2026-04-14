<#
.SYNOPSIS
    Restores filesystem ACLs from a Lock-Filesystem.ps1 snapshot.
.DESCRIPTION
    Reads the JSON snapshot created by Lock-Filesystem.ps1 and restores each file/directory's
    original SDDL and owner. Use this to undo filesystem lockdown if it causes issues.

.PARAMETER SnapshotFile
    Path to the ACL snapshot JSON. Default: filesystem-snapshot.json in the hardening directory.
#>
param(
    [string]$SnapshotFile = (Join-Path $PSScriptRoot "filesystem-snapshot.json")
)

. "$PSScriptRoot\..\Common.ps1"
Write-Banner -ScriptName "Restore-Filesystem"

if (-not (Test-Path $SnapshotFile)) {
    Write-Host "Snapshot file not found: $SnapshotFile" -ForegroundColor Red
    exit 1
}

$snapshot = Get-Content $SnapshotFile -Raw | ConvertFrom-Json

Write-Host "Restoring $($snapshot.Count) ACL entries from: $SnapshotFile"

$success = 0
$failed = 0
foreach ($entry in $snapshot) {
    if (-not (Test-Path $entry.Path)) {
        Write-Host "  Skip: $($entry.Path) (not found)" -ForegroundColor Yellow
        continue
    }

    try {
        $acl = Get-Acl -Path $entry.Path
        $acl.SetSecurityDescriptorSddlForm($entry.SDDL)
        if ($entry.Owner) {
            try {
                $owner = New-Object System.Security.Principal.NTAccount($entry.Owner)
                $acl.SetOwner($owner)
            } catch {
                Write-Host "  Warning: Could not set owner on $($entry.Path)" -ForegroundColor Yellow
            }
        }
        Set-Acl -Path $entry.Path -AclObject $acl
        $success++
    } catch {
        Write-Host "  Failed: $($entry.Path) — $_" -ForegroundColor Red
        $failed++
    }
}

Write-Host "`nRestored $success entries. Failed: $failed." -ForegroundColor $(if ($failed -gt 0) { "Yellow" } else { "Green" })
