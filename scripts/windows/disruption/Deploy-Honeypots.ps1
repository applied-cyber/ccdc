<#
.SYNOPSIS
    Deploys, monitors, and removes honeypot artifacts to detect unauthorized activity.

.DESCRIPTION
    All-in-one honeypot deployment with three operational modes:

    -Deploy: Creates four honeypot artifacts:
      - Honey User (svc_backup): AD or local account with logon-hours denied
      - Honey Service (BlueTeamMonitor): Enticing service name, logs to file
      - Honey Share (BlueTeam-Docs): SMB share with canary credentials file
      - Honey Task (Blue-Credential-Sync): Scheduled task as detection tripwire

    -Monitor: Watches Windows event logs for interaction with any honeypot:
      - Event 4624 for honey user authentication
      - Service start/stop events for honey service
      - Event 5145 for honey share access
      - Events 4698/4699/4702 for honey task modification

    -Remove: Tears down all honeypot artifacts cleanly.

    On a domain controller, the honey user is created as an AD account.
    On member servers/workstations, a local account is used instead.

    All alerts log to honeypot-alerts.log with timestamps and source IPs.

.PARAMETER Deploy
    Create all honeypot artifacts.

.PARAMETER Monitor
    Monitor event logs for honeypot interactions.

.PARAMETER Remove
    Remove all honeypot artifacts.

.EXAMPLE
    .\Deploy-Honeypots.ps1 -Deploy
    Create all four honeypot artifacts.

.EXAMPLE
    .\Deploy-Honeypots.ps1 -Monitor
    Watch for unauthorized interaction with honeypots.

.EXAMPLE
    .\Deploy-Honeypots.ps1 -Remove
    Clean up all honeypot artifacts.

.NOTES
    Requires an elevated (Administrator) PowerShell session.
    On domain controllers, requires the ActiveDirectory module for honey user creation.
    Dot-sources Common.ps1 for Write-Banner, Get-MachineRole, and Assert-Dependencies.
#>

param(
    [switch]$Deploy,
    [switch]$Monitor,
    [switch]$Remove
)

. "$PSScriptRoot\..\Common.ps1"

Write-Banner -ScriptName "Deploy-Honeypots"

if (-not $Deploy -and -not $Monitor -and -not $Remove) {
    Write-Host "Specify one of: -Deploy, -Monitor, or -Remove" -ForegroundColor Yellow
    exit 1
}

$role = Get-MachineRole
$isDC = ($role -eq "DomainController")

# --- Honeypot configuration ---
$HoneyUser       = "svc_backup"
$HoneyPassword   = 'B!ue_T3am_2025$ecur3'
$HoneyService    = "BlueTeamMonitor"
$HoneyShareName  = "BlueTeam-Docs"
$HoneySharePath  = "C:\BlueTeam-Docs"
$HoneyCanaryFile = "credentials-backup.txt"
$HoneyTask       = "Blue-Credential-Sync"
$LogFile         = Join-Path $PSScriptRoot "honeypot-alerts.log"

function Write-Alert {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry -ForegroundColor Red
    $entry | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

function Write-Info {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor Cyan
}

# ================================================================
#  DEPLOY
# ================================================================

function Deploy-HoneyUser {
    Write-Info "Creating honey user: $HoneyUser"

    $securePass = ConvertTo-SecureString $HoneyPassword -AsPlainText -Force

    if ($isDC) {
        Assert-Dependencies -Modules @("ActiveDirectory")
        try {
            # Create AD user
            New-ADUser -Name $HoneyUser `
                -SamAccountName $HoneyUser `
                -AccountPassword $securePass `
                -Enabled $true `
                -Description "Service account for backup operations" `
                -PasswordNeverExpires $true `
                -CannotChangePassword $true `
                -ErrorAction Stop

            # Deny all logon hours (any successful auth = unauthorized access)
            # Set logonHours to all zeros (168 bits = 21 bytes, all 0x00)
            $denyHours = New-Object byte[] 21
            Set-ADUser -Identity $HoneyUser -Replace @{logonHours = $denyHours} -ErrorAction Stop

            Write-Info "AD honey user '$HoneyUser' created with all logon hours denied"
        } catch {
            if ($_.Exception.Message -match 'already exists') {
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Honey user '$HoneyUser' already exists" -ForegroundColor Yellow
            } else {
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Failed to create AD honey user: $_" -ForegroundColor Red
            }
        }
    } else {
        try {
            New-LocalUser -Name $HoneyUser `
                -Password $securePass `
                -Description "Service account for backup operations" `
                -PasswordNeverExpires `
                -UserMayNotChangePassword `
                -ErrorAction Stop | Out-Null

            # Disable the account (any successful auth = an attacker enabled it)
            Disable-LocalUser -Name $HoneyUser -ErrorAction SilentlyContinue

            Write-Info "Local honey user '$HoneyUser' created and disabled"
        } catch {
            if ($_.Exception.Message -match 'already exists') {
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Honey user '$HoneyUser' already exists" -ForegroundColor Yellow
            } else {
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Failed to create local honey user: $_" -ForegroundColor Red
            }
        }
    }
}

function Deploy-HoneyService {
    Write-Info "Creating honey service: $HoneyService"

    $svcLogPath = "C:\Windows\Temp\BlueTeamMonitor.log"
    $binPath = "cmd.exe /c echo BlueTeamMonitor started at %DATE% %TIME% >> `"$svcLogPath`""

    try {
        sc.exe create $HoneyService binPath= $binPath start= demand displayname= "Security Posture Monitor" 2>&1 | Out-Null
        sc.exe description $HoneyService "Monitors system security posture and compliance status" 2>&1 | Out-Null
        Write-Info "Honey service '$HoneyService' created (manual start)"
    } catch {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Failed to create honey service: $_" -ForegroundColor Red
    }
}

function Deploy-HoneyShare {
    Write-Info "Creating honey share: $HoneyShareName"

    try {
        # Create share directory and canary file
        if (-not (Test-Path $HoneySharePath)) {
            New-Item -Path $HoneySharePath -ItemType Directory -Force | Out-Null
        }

        $canaryContent = @"
# Backup Credentials - DO NOT DELETE
# Last updated: $(Get-Date -Format 'yyyy-MM-dd')

Domain Admin:
  Username: da_backup
  Password: W1nt3r2025!Adm1n

Service Account:
  Username: svc_sql_prod
  Password: Pr0d_SQL#2025!!

VPN Gateway:
  IP: 10.0.1.1
  Username: vpnadmin
  Password: VPN@ccess2025

NOTE: These are FAKE credentials planted as a honeypot canary.
If you see alerts from these, an unauthorized user accessed this file.
"@
        Set-Content -Path (Join-Path $HoneySharePath $HoneyCanaryFile) -Value $canaryContent -Force

        # Create SMB share
        $existingShare = Get-SmbShare -Name $HoneyShareName -ErrorAction SilentlyContinue
        if ($existingShare) {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Share '$HoneyShareName' already exists" -ForegroundColor Yellow
        } else {
            New-SmbShare -Name $HoneyShareName -Path $HoneySharePath `
                -ReadAccess "Everyone" -Description "Security documentation" `
                -ErrorAction Stop | Out-Null
        }

        # Enable object access auditing on the folder
        $acl = Get-Acl $HoneySharePath
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone",
            "ReadData",
            "ContainerInherit,ObjectInherit",
            "None",
            "Success"
        )
        $acl.AddAuditRule($auditRule)
        Set-Acl -Path $HoneySharePath -AclObject $acl

        Write-Info "Honey share '\\$env:COMPUTERNAME\$HoneyShareName' created with canary file"
        Write-Info "Audit rule set for read access on $HoneySharePath"
    } catch {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Failed to create honey share: $_" -ForegroundColor Red
    }
}

function Deploy-HoneyTask {
    Write-Info "Creating honey task: $HoneyTask"

    try {
        $taskAction = New-ScheduledTaskAction -Execute "cmd.exe" `
            -Argument "/c echo Blue-Credential-Sync ran at %DATE% %TIME% >> C:\Windows\Temp\CredSync.log"

        $taskTrigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"

        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

        $taskSettings = New-ScheduledTaskSettingsSet -Hidden

        Register-ScheduledTask -TaskName $HoneyTask `
            -Action $taskAction `
            -Trigger $taskTrigger `
            -Principal $taskPrincipal `
            -Settings $taskSettings `
            -Description "Synchronizes credential store with backup domain controller" `
            -ErrorAction Stop | Out-Null

        Write-Info "Honey task '$HoneyTask' created (daily at 02:00)"
    } catch {
        if ($_.Exception.Message -match 'already exists') {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Honey task '$HoneyTask' already exists" -ForegroundColor Yellow
        } else {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Failed to create honey task: $_" -ForegroundColor Red
        }
    }
}

# ================================================================
#  MONITOR
# ================================================================

function Start-HoneypotMonitor {
    Write-Info "Starting honeypot monitor..."
    Write-Info "Log file: $LogFile"
    Write-Host "Polling every 15 seconds... (Ctrl+C to stop)" -ForegroundColor Cyan
    Write-Host ""

    while ($true) {
        $startTime = (Get-Date).AddSeconds(-15)
        $alertFound = $false

        # --- Honey User: Event 4624 (successful logon) ---
        try {
            $logonEvents = @(Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = 4624
                StartTime = $startTime
            } -ErrorAction SilentlyContinue)

            foreach ($evt in $logonEvents) {
                $xml = [xml]$evt.ToXml()
                $data = $xml.Event.EventData.Data
                $user = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                $ip   = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'

                if ($user -eq $HoneyUser) {
                    $alertFound = $true
                    Write-Alert "HONEY USER AUTH: user=$user source=$ip event=4624"
                }
            }
        } catch {}

        # --- Honey Service: service start/stop events (7036 in System log) ---
        try {
            $svcEvents = @(Get-WinEvent -FilterHashtable @{
                LogName   = 'System'
                Id        = 7036
                StartTime = $startTime
            } -ErrorAction SilentlyContinue)

            foreach ($evt in $svcEvents) {
                if ($evt.Message -match $HoneyService) {
                    $alertFound = $true
                    Write-Alert "HONEY SERVICE EVENT: $($evt.Message.Trim())"
                }
            }
        } catch {}

        # --- Honey Share: Event 5145 (share object access) ---
        try {
            $shareEvents = @(Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = 5145
                StartTime = $startTime
            } -ErrorAction SilentlyContinue)

            foreach ($evt in $shareEvents) {
                $xml = [xml]$evt.ToXml()
                $data = $xml.Event.EventData.Data
                $shareName = ($data | Where-Object { $_.Name -eq 'ShareName' }).'#text'
                $ip        = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                $user      = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
                $filePath  = ($data | Where-Object { $_.Name -eq 'RelativeTargetName' }).'#text'

                if ($shareName -match $HoneyShareName) {
                    $alertFound = $true
                    Write-Alert "HONEY SHARE ACCESS: user=$user source=$ip share=$shareName file=$filePath"
                }
            }
        } catch {}

        # --- Honey Task: Events 4698 (created), 4699 (deleted), 4702 (updated) ---
        try {
            $taskEvents = @(Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = @(4698, 4699, 4702)
                StartTime = $startTime
            } -ErrorAction SilentlyContinue)

            foreach ($evt in $taskEvents) {
                $xml = [xml]$evt.ToXml()
                $data = $xml.Event.EventData.Data
                $taskName = ($data | Where-Object { $_.Name -eq 'TaskName' }).'#text'
                $user     = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'

                if ($taskName -match $HoneyTask) {
                    $alertFound = $true
                    $action = switch ($evt.Id) {
                        4698 { "CREATED" }
                        4699 { "DELETED" }
                        4702 { "MODIFIED" }
                    }
                    Write-Alert "HONEY TASK $action task=$taskName by=$user eventId=$($evt.Id)"
                }
            }
        } catch {}

        if (-not $alertFound) {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] No honeypot triggers detected" -ForegroundColor Green
        }

        Start-Sleep -Seconds 15
    }
}

# ================================================================
#  REMOVE
# ================================================================

function Remove-HoneyUser {
    Write-Info "Removing honey user: $HoneyUser"
    if ($isDC) {
        try {
            Remove-ADUser -Identity $HoneyUser -Confirm:$false -ErrorAction Stop
            Write-Info "AD user '$HoneyUser' removed"
        } catch {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Could not remove AD user: $_" -ForegroundColor Yellow
        }
    } else {
        try {
            Remove-LocalUser -Name $HoneyUser -ErrorAction Stop
            Write-Info "Local user '$HoneyUser' removed"
        } catch {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Could not remove local user: $_" -ForegroundColor Yellow
        }
    }
}

function Remove-HoneyService {
    Write-Info "Removing honey service: $HoneyService"
    try {
        Stop-Service -Name $HoneyService -Force -ErrorAction SilentlyContinue
        sc.exe delete $HoneyService 2>&1 | Out-Null
        Write-Info "Service '$HoneyService' removed"
    } catch {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Could not remove service: $_" -ForegroundColor Yellow
    }
}

function Remove-HoneyShare {
    Write-Info "Removing honey share: $HoneyShareName"
    try {
        Remove-SmbShare -Name $HoneyShareName -Force -ErrorAction SilentlyContinue
        if (Test-Path $HoneySharePath) {
            Remove-Item -Path $HoneySharePath -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Info "Share '$HoneyShareName' and directory removed"
    } catch {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Could not remove share: $_" -ForegroundColor Yellow
    }
}

function Remove-HoneyTask {
    Write-Info "Removing honey task: $HoneyTask"
    try {
        Unregister-ScheduledTask -TaskName $HoneyTask -Confirm:$false -ErrorAction Stop
        Write-Info "Task '$HoneyTask' removed"
    } catch {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Could not remove task: $_" -ForegroundColor Yellow
    }
}

# ================================================================
#  MAIN
# ================================================================

if ($Deploy) {
    Write-Host ""
    Write-Host "Deploying honeypots on $env:COMPUTERNAME ($role)..." -ForegroundColor Cyan
    Write-Host ("-" * 60)

    Deploy-HoneyUser
    Deploy-HoneyService
    Deploy-HoneyShare
    Deploy-HoneyTask

    Write-Host ""
    Write-Host ("-" * 60)
    Write-Host "Deployment complete. Run with -Monitor to watch for triggers." -ForegroundColor Green
}

if ($Monitor) {
    Start-HoneypotMonitor
}

if ($Remove) {
    Write-Host ""
    Write-Host "Removing honeypots from $env:COMPUTERNAME ($role)..." -ForegroundColor Cyan
    Write-Host ("-" * 60)

    Remove-HoneyUser
    Remove-HoneyService
    Remove-HoneyShare
    Remove-HoneyTask

    Write-Host ""
    Write-Host ("-" * 60)
    Write-Host "All honeypot artifacts removed." -ForegroundColor Green
}
