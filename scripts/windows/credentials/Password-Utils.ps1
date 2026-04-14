<#
.SYNOPSIS
    Shared helpers for credential management scripts (Roll-Passwords, Dump-Hashes, Rollback-Users).
.DESCRIPTION
    Provides path constants for hash/password output files, a function to load password state
    from CSV, and a file rotation function that shifts numbered backups (user_passwords_0.csv ->
    user_passwords_1.csv, etc.) so the most recent output is always _0.
#>

$HashOutFile             = Join-Path $PSScriptRoot 'user_hashes.csv'
$PasswordOutFile         = Join-Path $PSScriptRoot 'user_passwords.csv'
$CurrentHashOutFile      = Join-Path $PSScriptRoot 'user_hashes_0.csv'
$CurrentPasswordOutFile  = Join-Path $PSScriptRoot 'user_passwords_0.csv'

# Get the password state from the given path, returning an empty state if the
# file doesn't exist or fails to load
function Get-PasswordState {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $state = @{}
    if (-not (Test-Path $Path)) {
        return $state
    }

    try {
        foreach ($row in (Import-Csv -Path $Path)) {
            if ($null -eq $row.SamAccountName) { continue }
            $name = ("$($row.SamAccountName)").Trim()
            if ($name.Length -eq 0) { continue }
            $state[$name] = $row.Password
        }
    } catch {
        Write-Warning "Failed to load password state from $Path; using empty state"
        return @{}
    }

    return $state
}

# Rotate existing output files by renaming them with an incremented suffix, and
# return the path for the caller to write the new output to
function Rotate-OutputFiles {
    param(
        # Base path without suffix
        [Parameter(Mandatory)]
        [string] $BasePath
    )

    $dir  = Split-Path -Parent $BasePath
    if (-not $dir) { $dir = "." }

    # Create if the directory doesn't exist
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }

    $name = [IO.Path]::GetFileNameWithoutExtension($BasePath)
    $ext  = [IO.Path]::GetExtension($BasePath)

    # Find existing rotated files: name_<number>.ext
    $pattern = "^" + [Regex]::Escape($name) + "_(\d+)" + [Regex]::Escape($ext) + "$"

    $existing = Get-ChildItem -Path $dir -File |
        Where-Object { $_.Name -match $pattern } |
        ForEach-Object {
            [PSCustomObject]@{
                Path  = $_.FullName
                Index = [int]$matches[1]
            }
        } |
        Sort-Object Index -Descending

    # Shift highest -> highest+1 (descending prevents overwrite)
    foreach ($file in $existing) {
        $newIndex = $file.Index + 1
        $newName  = "{0}_{1}{2}" -f $name, $newIndex, $ext
        Rename-Item -Path $file.Path -NewName $newName
    }

    # Path caller should write as newest
    return (Join-Path $dir ("{0}_0{1}" -f $name, $ext))
}
