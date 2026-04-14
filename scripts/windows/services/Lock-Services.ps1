<#
.SYNOPSIS
    Locks down service DACLs so only a specified admin account retains control.
.DESCRIPTION
    Replaces each service's DACL so only the specified admin account has full control.
    SYSTEM retains start/stop/query rights so SCM can auto-start services at boot
    (without this, a reboot kills the domain). All other principals are removed.

    This prevents SYSTEM-level shells (e.g., from PsExec) from using sc.exe to
    reconfigure, delete, or change service binary paths — but they can still
    start/stop services (same as SYSTEM). The key protection is blocking
    SERVICE_CHANGE_CONFIG and DELETE, which are the dangerous persistence vectors.

    An attacker would need direct registry edits to modify service binaries
    (different attack surface, easier to detect with Watch-Services.ps1).

    Takes a baseline snapshot first (calls Snapshot-Services.ps1 if no snapshot exists).
    Requires confirmation before applying.

.PARAMETER AdminAccount
    The one account that keeps full control. Format: DOMAIN\username or .\username.
.PARAMETER SnapshotFile
    Path to existing services snapshot. If not provided, runs Snapshot-Services.ps1.
.PARAMETER Include
    Lock only these specific services. If not specified, locks all services.
.PARAMETER Exclude
    Service names to skip (e.g., critical services you don't want to touch).
.NOTES
    SYSTEM retains SERVICE_START/STOP so services auto-start after reboot.
    An attacker with a SYSTEM shell can still stop services, but cannot reconfigure
    or delete them — that's the tradeoff vs. bricking the domain on reboot.
#>
param(
    [Parameter(Mandatory)]
    [string]$AdminAccount,

    [string]$SnapshotFile = (Join-Path $PSScriptRoot "services-snapshot.json"),

    [string[]]$Include = @(),

    [string[]]$Exclude = @()
)

. "$PSScriptRoot\..\Common.ps1"
Write-Banner -ScriptName "Lock-Services"

# Ensure we have a snapshot
if (-not (Test-Path $SnapshotFile)) {
    Write-Host "No snapshot found. Taking baseline snapshot first..." -ForegroundColor Yellow
    & "$PSScriptRoot\Snapshot-Services.ps1" -OutputFile $SnapshotFile
}

$snapshot = [string]::Join("", (Get-Content $SnapshotFile)) | ConvertFrom-Json

# Build the locked-down SDDL: only the admin account with full control
# SC_MANAGER_ALL_ACCESS for service = 0xF01FF = CCDCLCSWRPWPDTLOCRSDRCWDWO
# We need to resolve the admin account to a SID
try {
    $account = New-Object System.Security.Principal.NTAccount($AdminAccount)
    $sid = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
} catch {
    Write-Host "Error: Could not resolve account '$AdminAccount' to SID: $_" -ForegroundColor Red
    exit 1
}

# DACL: full control to admin, and SYSTEM keeps start/stop/query so SCM can
# auto-start services at boot. Without the SY ACE, a reboot kills the domain.
# SY rights: RP (SERVICE_START) + WP (SERVICE_STOP) + LC (SERVICE_QUERY_STATUS)
#            + RC (READ_CONTROL) + LO (SERVICE_INTERROGATE) + CR (SERVICE_USER_DEFINED_CONTROL)
$lockedSDDL = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)(A;;RPWPLCRCLOCR;;;SY)"

Write-Host "`nWill lock $($snapshot.Count) services to only allow access by: $AdminAccount ($sid)"
Write-Host "Excluding: $($Exclude -join ', ')" -ForegroundColor Yellow

$changes = @()
foreach ($svc in $snapshot) {
    if ($Include.Count -gt 0 -and $Include -notcontains $svc.Name) { continue }
    if ($Exclude -contains $svc.Name) { continue }
    if ($svc.SDDL -eq $lockedSDDL) { continue }
    $changes += [PSCustomObject]@{
        Name    = $svc.Name
        OldSDDL = $svc.SDDL
        NewSDDL = $lockedSDDL
    }
}

Write-Host "`n$($changes.Count) services will be modified."
if ($changes.Count -eq 0) {
    Write-Host "Nothing to do." -ForegroundColor Green
    exit 0
}

$confirm = Read-Host "Apply DACL lockdown? [y/N]"
if ($confirm -ne 'y') {
    Write-Host "Aborted." -ForegroundColor Yellow
    exit 0
}

$success = 0
$failed = 0
foreach ($change in $changes) {
    try {
        $result = sc.exe sdset $change.Name $lockedSDDL 2>&1
        if ($LASTEXITCODE -eq 0) {
            $success++
        } else {
            Write-Host "Failed to lock $($change.Name): $result" -ForegroundColor Red
            $failed++
        }
    } catch {
        Write-Host "Error locking $($change.Name): $_" -ForegroundColor Red
        $failed++
    }
}

Write-Host "`nLocked $success services. Failed: $failed." -ForegroundColor $(if ($failed -gt 0) { "Yellow" } else { "Green" })
Write-Host "Old SDDLs preserved in snapshot: $SnapshotFile"
Write-Host "To restore: use the snapshot with sc.exe sdset <service> <original-sddl>"
