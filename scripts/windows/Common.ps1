<#
.SYNOPSIS
    Shared helper functions for all toolkit scripts. Dot-source this at the top of each script.
.DESCRIPTION
    Provides:
    - Get-MachineRole: returns "DomainController", "MemberServer", or "Workstation"
    - Assert-Dependencies: checks for required modules/commands, exits with clear error if missing
    - Assert-Role: exits with message if machine role doesn't match requirement
    - Write-Banner: prints script name + detected role at startup
#>

function Get-MachineRole {
    try {
        $pt = (Get-CimInstance Win32_OperatingSystem).ProductType
    } catch {
        $pt = (Get-WmiObject Win32_OperatingSystem).ProductType
    }
    switch ($pt) {
        2 { "DomainController" }
        3 { "MemberServer" }
        default { "Workstation" }
    }
}

function Assert-Dependencies {
    param(
        [string[]]$Modules,
        [string[]]$Commands
    )
    $missing = @()
    foreach ($mod in $Modules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            $missing += "Module: $mod"
        }
    }
    foreach ($cmd in $Commands) {
        if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
            $missing += "Command: $cmd"
        }
    }
    if ($missing.Count -gt 0) {
        Write-Host "Missing dependencies:" -ForegroundColor Red
        $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        Write-Host "`nRun Install-Dependencies.ps1 first, or install manually." -ForegroundColor Yellow
        exit 1
    }
}

function Assert-Role {
    param(
        [ValidateSet("DomainController","MemberServer","Workstation","Any")]
        [string[]]$Required
    )
    if ($Required -contains "Any") { return }
    $role = Get-MachineRole
    if ($role -notin $Required) {
        Write-Host "This script requires role: $($Required -join ' or ')" -ForegroundColor Yellow
        Write-Host "Detected role: $role" -ForegroundColor Yellow
        Write-Host "Exiting." -ForegroundColor Yellow
        exit 0
    }
}

function Write-Banner {
    param(
        [string]$ScriptName
    )
    $role = Get-MachineRole
    Write-Host "[$ScriptName] Running on $env:COMPUTERNAME ($role)" -ForegroundColor Cyan
    Write-Host ("-" * 60)
}
