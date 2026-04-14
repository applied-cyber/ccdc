<#
.SYNOPSIS
    Locks down filesystem ACLs on staging directories and critical system binaries.
.DESCRIPTION
    Protects two categories of files:

    1. Staging directories (where admin scripts live): removes write access for
       everyone except a specified admin account. Prevents attackers from modifying
       admin tools.

    2. Critical binaries (cmd.exe, powershell.exe, net.exe, sc.exe, reg.exe, etc.):
       takes ownership, removes execute permissions for non-admin users. Makes it
       harder for attackers to use LOLBins from compromised service accounts.

    Creates a snapshot of original ACLs before modification so Restore-Filesystem.ps1
    can undo changes.

.PARAMETER AdminAccount
    The account that retains full access. Format: DOMAIN\username or .\username.
.PARAMETER StagingDirs
    Directories to lock down. Default: $PSScriptRoot (the toolkit root).
.PARAMETER LockBinaries
    Also lock down critical system binaries. Default: false.
.PARAMETER SnapshotFile
    Path to save the ACL snapshot. Default: filesystem-snapshot.json in script directory.
#>
param(
    [Parameter(Mandatory)]
    [string]$AdminAccount,

    [string[]]$StagingDirs = @((Split-Path $PSScriptRoot -Parent)),

    [switch]$LockBinaries,

    [string]$SnapshotFile = (Join-Path $PSScriptRoot "filesystem-snapshot.json")
)

. "$PSScriptRoot\..\Common.ps1"
Write-Banner -ScriptName "Lock-Filesystem"

$CriticalBinaries = @(
    "$env:SystemRoot\System32\cmd.exe",
    "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
    "$env:SystemRoot\System32\net.exe",
    "$env:SystemRoot\System32\net1.exe",
    "$env:SystemRoot\System32\sc.exe",
    "$env:SystemRoot\System32\reg.exe",
    "$env:SystemRoot\System32\wmic.exe",
    "$env:SystemRoot\System32\certutil.exe",
    "$env:SystemRoot\System32\bitsadmin.exe",
    "$env:SystemRoot\System32\mshta.exe",
    "$env:SystemRoot\System32\regsvr32.exe",
    "$env:SystemRoot\System32\rundll32.exe",
    "$env:SystemRoot\System32\cscript.exe",
    "$env:SystemRoot\System32\wscript.exe"
)

# Snapshot current ACLs
$snapshot = @()

function Save-ACL {
    param([string]$Path)
    if (Test-Path $Path) {
        try {
            $acl = Get-Acl -Path $Path
            $script:snapshot += [PSCustomObject]@{
                Path = $Path
                SDDL = $acl.Sddl
                Owner = $acl.Owner
            }
        } catch {
            Write-Host "Warning: Could not read ACL for $Path" -ForegroundColor Yellow
        }
    }
}

# Snapshot staging dirs
foreach ($dir in $StagingDirs) {
    if (Test-Path $dir) {
        Save-ACL -Path $dir
        Get-ChildItem -Path $dir -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            Save-ACL -Path $_.FullName
        }
    }
}

# Snapshot binaries if requested
if ($LockBinaries) {
    foreach ($bin in $CriticalBinaries) {
        Save-ACL -Path $bin
    }
}

# Save snapshot
$snapshot | ConvertTo-Json -Depth 5 | Set-Content -Path $SnapshotFile -Encoding UTF8
Write-Host "ACL snapshot saved to: $SnapshotFile ($($snapshot.Count) entries)" -ForegroundColor Green

# Lock staging directories
Write-Host "`nLocking staging directories..." -ForegroundColor Cyan
foreach ($dir in $StagingDirs) {
    if (-not (Test-Path $dir)) {
        Write-Host "  Skip: $dir (not found)" -ForegroundColor Yellow
        continue
    }

    try {
        $acl = Get-Acl -Path $dir
        # Remove all existing access rules
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        # Add full control for admin account
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $AdminAccount, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule)
        # Add read+execute for SYSTEM (services need to read scripts)
        $sysRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($sysRule)
        Set-Acl -Path $dir -AclObject $acl
        Write-Host "  Locked: $dir" -ForegroundColor Green
    } catch {
        Write-Host "  Failed: $dir — $_" -ForegroundColor Red
    }
}

# Lock critical binaries
if ($LockBinaries) {
    Write-Host "`nLocking critical binaries..." -ForegroundColor Cyan
    foreach ($bin in $CriticalBinaries) {
        if (-not (Test-Path $bin)) {
            Write-Host "  Skip: $bin (not found)" -ForegroundColor Yellow
            continue
        }

        try {
            # Take ownership
            $acl = Get-Acl -Path $bin
            $admin = New-Object System.Security.Principal.NTAccount($AdminAccount)
            $acl.SetOwner($admin)
            Set-Acl -Path $bin -AclObject $acl

            # Reset ACL: admin full control, no execute for others
            $acl = Get-Acl -Path $bin
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $AdminAccount, "FullControl", "Allow")
            $acl.AddAccessRule($rule)
            Set-Acl -Path $bin -AclObject $acl
            Write-Host "  Locked: $bin" -ForegroundColor Green
        } catch {
            Write-Host "  Failed: $bin — $_" -ForegroundColor Red
        }
    }
}

Write-Host "`nFilesystem lockdown complete." -ForegroundColor Green
Write-Host "To restore: .\Restore-Filesystem.ps1 -SnapshotFile `"$SnapshotFile`""
