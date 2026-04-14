<#
.SYNOPSIS
    Rolls passwords for domain users with preview, confirmation, and safe output.
.DESCRIPTION
    Generates new random passwords for domain users using a safe character set
    (a-z, A-Z, 0-9, hyphen only — no quotes, no shell metacharacters). Default length: 16.

    Flow:
    1. Generate all new passwords
    2. Print preview table to console (User -> NewPassword)
    3. Write preview CSV (unquoted: user,password)
    4. Prompt: "Apply these passwords? [y/N]"
    5. On confirm: apply via Set-ADAccountPassword, dump hashes, finalize CSV
    6. On decline: delete preview, exit

    CSV output is unquoted, in CSV format: username,password

    Before rolling, dumps current hashes (if not already dumped) so rollback is possible.

.PARAMETER UsersInclude
    Roll passwords only for these specific users.
.PARAMETER UsersExclude
    Roll passwords for all domain users except these.
.PARAMETER Length
    Password length. Default: 16.
#>

[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Include')]
    [string[]]$UsersInclude,

    [Parameter(Mandatory = $true, ParameterSetName = 'Exclude')]
    [string[]]$UsersExclude,

    [int]$Length = 16
)

. "$PSScriptRoot\Password-Utils.ps1"

$DefaultExcludedUsers = @('Administrator', 'krbtgt', 'Guest', 'DefaultAccount')

# Safe charset: letters, digits, hyphens only. No quotes, no shell metacharacters.
$Charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"

function Get-DomainUsers {
    param(
        [string[]]$UsersInclude = @(),
        [string[]]$UsersExclude = @()
    )

    if ($UsersInclude.Count -gt 0) {
        $users = foreach ($u in $UsersInclude) {
            if ($null -eq $u) { continue }
            $t = $u.Trim()
            if ($t.Length -eq 0) { continue }

            if ($DefaultExcludedUsers -contains $t) {
                Write-Warning "Skipping excluded default user: $t"
                continue
            }

            try {
                Get-ADUser -Identity $t -ErrorAction Stop
            } catch {
                Write-Warning "User not found: $t"
            }
        }

        return $users | Where-Object { $_ -and $_.SamAccountName }
    }

    $excludeAll = @($DefaultExcludedUsers + $UsersExclude) |
        ForEach-Object { "$_".Trim() } |
        Where-Object { $_ }

    $filterParts = @("objectClass -eq 'user'")
    foreach ($name in $excludeAll) {
        $n = $name -replace "'", "''"
        $filterParts += "SamAccountName -ne '$n'"
    }

    $filter = $filterParts -join " -and "
    Get-ADUser -Filter $filter
}

function New-RandomPassword {
    param ([int]$Length = 16)
    return -join (1..$Length | ForEach-Object {
        $Charset[(Get-Random -Maximum $Charset.Length)]
    })
}

# Dump hashes before rolling if no current dump exists
if (-not (Test-Path $CurrentHashOutFile)) {
    Write-Host "Current hash state not found. Dumping current password hashes before rolling passwords"
    . "$PSScriptRoot\Dump-Hashes.ps1"
}

# Get target users
if ($PSCmdlet.ParameterSetName -eq 'Include') {
    $users = Get-DomainUsers -UsersInclude $UsersInclude
} elseif ($PSCmdlet.ParameterSetName -eq 'Exclude') {
    $users = Get-DomainUsers -UsersExclude $UsersExclude
} else {
    $users = Get-DomainUsers
}

if ($users.Count -eq 0) {
    Write-Host "No users found to roll passwords for." -ForegroundColor Yellow
    exit 0
}

# Initialize results with latest known state so full state is preserved for partial rolls
$resultsByUser = Get-PasswordState -Path $CurrentPasswordOutFile

# Generate all passwords first (don't apply yet)
$pendingChanges = @{}
foreach ($user in $users) {
    $pendingChanges[$user.SamAccountName] = New-RandomPassword -Length $Length
}

# Preview
Write-Host "`nPassword Roll Preview:" -ForegroundColor Cyan
Write-Host ("-" * 60)
Write-Host ("{0,-30} {1}" -f "User", "New Password")
Write-Host ("-" * 60)
foreach ($entry in ($pendingChanges.GetEnumerator() | Sort-Object Key)) {
    Write-Host ("{0,-30} {1}" -f $entry.Key, $entry.Value)
}
Write-Host ("-" * 60)
Write-Host "$($pendingChanges.Count) accounts will be changed.`n"

# Write preview CSV (unquoted)
$previewPath = Join-Path $PSScriptRoot "roll-preview.csv"
"user,password" | Set-Content $previewPath
$pendingChanges.GetEnumerator() | Sort-Object Key | ForEach-Object {
    "$($_.Key),$($_.Value)"
} | Add-Content $previewPath
Write-Host "Preview CSV written to: $previewPath"

$confirm = Read-Host "Apply these passwords? [y/N]"
if ($confirm -ne 'y') {
    Remove-Item $previewPath -Force -ErrorAction SilentlyContinue
    Write-Host "Aborted." -ForegroundColor Yellow
    exit 0
}

# Apply passwords
Write-Host "`nRolling passwords for $($pendingChanges.Count) users..."
foreach ($entry in $pendingChanges.GetEnumerator()) {
    $secure = ConvertTo-SecureString $entry.Value -AsPlainText -Force
    Set-ADAccountPassword -Identity $entry.Key -Reset -NewPassword $secure
    $resultsByUser[$entry.Key] = $entry.Value
}

# Write final CSV (unquoted, CSV format: user,password)
$userPasswordCSV = Rotate-OutputFiles -BasePath $PasswordOutFile
"user,password" | Set-Content $userPasswordCSV
$resultsByUser.GetEnumerator() | Sort-Object Key | ForEach-Object {
    "$($_.Key),$($_.Value)"
} | Add-Content $userPasswordCSV
Write-Host "Rolled passwords for $($pendingChanges.Count) users. Output saved to: $userPasswordCSV"

# Clean up preview
Remove-Item $previewPath -Force -ErrorAction SilentlyContinue

Write-Host "Dumping current password hash state after roll"
. "$PSScriptRoot\Dump-Hashes.ps1"
