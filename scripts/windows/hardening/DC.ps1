<#
.SYNOPSIS
    Standalone Domain Controller hardening script for CCDC.
.DESCRIPTION
    Self-contained, no external dependencies. Two modes:
      - Default: safe hardening that won't break services
      - -Aggressive: adds NTLM/LDAP restrictions that may break legacy auth

    Always run -AuditOnly first to see what would change.

.PARAMETER AuditOnly
    Report what would change without modifying anything.
.PARAMETER Aggressive
    Enable NTLM blocking, LDAP signing enforcement, and delegation cleanup.
    TEST FIRST -- these broke WinRM/NTLM on our lab VM (Mar 12).
.NOTES
    Run as Domain Admin on a Domain Controller.
    Complements the team spray (windows.ps1) which handles: password rolls,
    SSH setup, firewall, and basic CVE mitigations. This script handles
    DC-specific AD hardening that the spray doesn't touch.
#>
[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [switch]$Aggressive
)

$ErrorActionPreference = "Continue"

# --- Preflight ---
$pt = (Get-CimInstance Win32_OperatingSystem).ProductType
if ($pt -ne 2) {
    Write-Host "NOT a Domain Controller (ProductType=$pt). Exiting." -ForegroundColor Red
    exit 1
}

if (-not ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Host "Must run as Administrator." -ForegroundColor Red
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

$mode = if ($AuditOnly) { "AUDIT" } else { "ENFORCE" }
Write-Host "=== DC Hardening [$mode] on $env:COMPUTERNAME ===" -ForegroundColor Cyan
if ($Aggressive) { Write-Host "  Aggressive mode ON" -ForegroundColor Yellow }
Write-Host ("-" * 60)

function Log($msg) {
    $prefix = if ($AuditOnly) { "[AUDIT]" } else { "[SET]" }
    Write-Host "$prefix $msg"
}

function Set-RegValue($Path, $Name, $Value, $Type = "DWORD") {
    $current = $null
    try { $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch {}
    if ($current -eq $Value) {
        Log "$Name already $Value (at $Path)"
        return
    }
    if ($AuditOnly) {
        Log "WOULD set $Name=$Value (currently $(if ($null -eq $current) { 'unset' } else { $current })) at $Path"
    } else {
        New-Item -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Log "Set $Name=$Value at $Path"
    }
}

# ============================================================
#  SECTION 1: SAFE HARDENING (won't break services)
# ============================================================
Write-Host "`n--- Safe Hardening ---" -ForegroundColor Green

# 1a. SMB signing (server side -- prevents relay attacks)
Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature" 1
Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" 1

# 1b. Disable SMBv1 (EternalBlue) -- server and client
Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" 0
Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" 4

# 1c. SMBGhost
Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "DisableCompression" 1

# 1d. BlueKeep NLA
Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" 1

# 1e. No LM hash storage
Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash" 1

# 1f. WDigest disable (no plaintext creds in memory)
Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" 0

# 1g. LSA protection (RunAsPPL=1, NOT 2 which is UEFI-locked and irreversible)
Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" 1

# 1h. UAC enforce
Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1
Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 2

# 1i. Disable LLMNR
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0

# 1j. Disable NetBIOS on all interfaces
$nbInterfaces = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
foreach ($iface in $nbInterfaces) {
    Set-RegValue $iface.PSPath "NetbiosOptions" 2
}

# 1k. Defender re-enable
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" 0
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableAntiVirus" 0
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" 0

# 1l. PowerShell script block logging
Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" 1

# 1m. Full audit policy
if ($AuditOnly) {
    Log "WOULD enable full audit policy (success+failure on all categories)"
} else {
    auditpol /set /category:* /failure:enable /success:enable 2>$null | Out-Null
    Log "Enabled full audit policy"
}

# 1n. Disable Guest
if ($AuditOnly) {
    $guest = Get-ADUser -Filter "SamAccountName -eq 'Guest'" -Properties Enabled
    if ($guest.Enabled) { Log "WOULD disable Guest account" }
} else {
    net user Guest /active:no 2>$null | Out-Null
    Log "Disabled Guest account"
}

# 1o. Clear Run/RunOnce persistence keys
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $values = Get-ItemProperty $key -ErrorAction SilentlyContinue
        $names = $values.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | Select-Object -ExpandProperty Name
        if ($names.Count -gt 0) {
            if ($AuditOnly) {
                Log "WOULD clear $($names.Count) value(s) from $key"
            } else {
                Remove-Item $key -Force -ErrorAction SilentlyContinue
                Log "Cleared $key"
            }
        }
    }
}

# 1p. Disable Print Spooler (PrintNightmare)
$spooler = Get-Service Spooler -ErrorAction SilentlyContinue
if ($spooler -and ($spooler.Status -ne 'Stopped' -or $spooler.StartType -ne 'Disabled')) {
    if ($AuditOnly) {
        Log "WOULD disable Print Spooler"
    } else {
        Stop-Service Spooler -Force -ErrorAction SilentlyContinue
        Set-Service Spooler -StartupType Disabled
        Log "Disabled Print Spooler"
    }
}

# 1q. Disable CertSvc (Certifried)
$certsvc = Get-Service CertSvc -ErrorAction SilentlyContinue
if ($certsvc -and ($certsvc.Status -ne 'Stopped' -or $certsvc.StartType -ne 'Disabled')) {
    if ($AuditOnly) {
        Log "WOULD disable CertSvc"
    } else {
        Stop-Service CertSvc -Force -ErrorAction SilentlyContinue
        Set-Service CertSvc -StartupType Disabled
        Log "Disabled CertSvc"
    }
}

# 1r. Zerologon enforcement
Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "FullSecureChannelProtection" 1

# 1s. SIGRed
Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" "TcpReceivePacketSize" 0xFF00

# 1t. noPac mitigation
$domain = Get-ADDomain
$maq = $domain."ms-DS-MachineAccountQuota"
if ($maq -gt 0) {
    if ($AuditOnly) {
        Log "WOULD set MachineAccountQuota from $maq to 0"
    } else {
        Set-ADDomain -Identity $domain.DNSRoot -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }
        Log "Set MachineAccountQuota from $maq to 0"
    }
} else {
    Log "MachineAccountQuota already 0"
}
Set-RegValue "HKLM:\System\CurrentControlSet\Services\Kdc" "PacRequestorEnforcement" 2

# 1u. AdminSDHolder propagation delay (slows attacker auto-restore of protected groups)
Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "AdminSDProtectFrequency" 7200

# ============================================================
#  SECTION 2: AD OBJECT HARDENING (safe, audits before changing)
# ============================================================
Write-Host "`n--- AD Object Hardening ---" -ForegroundColor Green

# 2a. AS-REP Roasting fix -- remove DoNotRequirePreAuth
$noPreAuth = Get-ADUser -Filter "UserAccountControl -band 4194304" -Properties UserAccountControl
foreach ($u in $noPreAuth) {
    if ($AuditOnly) {
        Log "User '$($u.SamAccountName)' has DoNotRequirePreAuth (AS-REP roastable)"
    } else {
        $newUAC = $u.UserAccountControl -band (-1 -bxor 4194304)
        Set-ADUser $u -Replace @{UserAccountControl=$newUAC}
        Log "Removed DoNotRequirePreAuth from '$($u.SamAccountName)'"
    }
}

# 2b. Protected Users group -- add Domain/Enterprise Admins
$protMembers = @()
try { $protMembers = (Get-ADGroupMember "Protected Users" -ErrorAction Stop).SamAccountName } catch {}
foreach ($grp in @("Domain Admins","Enterprise Admins")) {
    try {
        $members = Get-ADGroupMember $grp -ErrorAction Stop | Where-Object ObjectClass -eq 'user'
    } catch { continue }
    foreach ($m in $members) {
        if ($protMembers -notcontains $m.SamAccountName) {
            if ($AuditOnly) {
                Log "Privileged user '$($m.SamAccountName)' NOT in Protected Users"
            } else {
                Add-ADGroupMember "Protected Users" -Members $m -ErrorAction SilentlyContinue
                Log "Added '$($m.SamAccountName)' to Protected Users"
            }
        }
    }
}

# 2c. Mark privileged accounts as "sensitive, cannot be delegated"
foreach ($grp in @("Domain Admins","Enterprise Admins","Schema Admins")) {
    try { $members = Get-ADGroupMember $grp -ErrorAction Stop | Where-Object ObjectClass -eq 'user' } catch { continue }
    foreach ($m in $members) {
        $user = Get-ADUser $m -Properties UserAccountControl
        $notDelegated = ($user.UserAccountControl -band 0x100000) -ne 0
        if (-not $notDelegated) {
            if ($AuditOnly) {
                Log "Privileged user '$($user.SamAccountName)' can be delegated"
            } else {
                Set-ADUser $user -CannotBeDelegated $true
                Log "Set 'cannot be delegated' on '$($user.SamAccountName)'"
            }
        }
    }
}

# 2d. DNSAdmins group -- empty it (DNS plugin DLL abuse vector)
try {
    $dnsMembers = Get-ADGroupMember "DNSAdmins" -ErrorAction Stop
    foreach ($m in $dnsMembers) {
        if ($AuditOnly) {
            Log "DNSAdmins contains '$($m.SamAccountName)' -- should remove"
        } else {
            Remove-ADGroupMember "DNSAdmins" -Members $m -Confirm:$false -ErrorAction SilentlyContinue
            Log "Removed '$($m.SamAccountName)' from DNSAdmins"
        }
    }
} catch {}

# 2e. GPP cpassword cleanup (credential leak in SYSVOL)
$sysvolPath = "$env:SystemRoot\SYSVOL\domain\Policies"
if (Test-Path $sysvolPath) {
    $hits = Get-ChildItem $sysvolPath -Recurse -Include '*.xml' -ErrorAction SilentlyContinue |
        Select-String -Pattern 'cpassword' -SimpleMatch
    foreach ($h in $hits) {
        if ($AuditOnly) {
            Log "GPP cpassword found: $($h.Path)"
        } else {
            Rename-Item $h.Path "$($h.Path).bak" -ErrorAction SilentlyContinue
            Log "Renamed GPP file: $($h.Path) -> .bak"
        }
    }
}

# 2f. DCSync ACL audit -- find unauthorized replication rights
$domainDN = (Get-ADDomain).DistinguishedName
$domainACL = Get-ACL "AD:$domainDN"
$repGuids = @(
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # Get-Changes-All
    "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2",  # Get-Changes-Filtered
    "89e95b76-444d-4c62-991a-0facbeda640c"   # Get-Changes-In-Filtered-Set
)
$safeSIDs = @()
foreach ($g in @("Domain Controllers","Administrators","Domain Admins","Enterprise Admins","Enterprise Read-only Domain Controllers")) {
    try { $safeSIDs += (Get-ADGroup $g).SID.Value } catch {}
}
# NT AUTHORITY well-known SIDs that legitimately have replication rights
$safeSIDs += "S-1-5-9"   # Enterprise Domain Controllers (NT AUTHORITY)

$removed = 0
foreach ($ace in $domainACL.Access) {
    if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
        $objType = $ace.ObjectType.ToString()
        if ($repGuids -contains $objType) {
            try {
                $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch { continue }
            if ($safeSIDs -notcontains $sid) {
                if ($AuditOnly) {
                    Log "UNAUTHORIZED replication right for '$($ace.IdentityReference)' -- potential DCSync backdoor"
                } else {
                    [void]$domainACL.RemoveAccessRule($ace)
                    $removed++
                }
            }
        }
    }
}
if (-not $AuditOnly -and $removed -gt 0) {
    Set-ACL "AD:$domainDN" $domainACL
    Log "Removed $removed unauthorized replication ACE(s)"
}

# 2g. AdminSDHolder ACL cleanup
$adminSDDN = "CN=AdminSDHolder,CN=System,$domainDN"
try {
    $sdACL = Get-ACL "AD:$adminSDDN"
    $domNB = (Get-ADDomain).NetBIOSName
    # Default AdminSDHolder ACEs include BUILTIN\Administrators, SELF (change-password), Everyone (change-password)
    $safePrincipals = @("$domNB\Domain Admins","$domNB\Enterprise Admins","$domNB\Administrators",
        "NT AUTHORITY\SYSTEM","BUILTIN\Administrators","NT AUTHORITY\SELF","Everyone")
    $highRights = @("WriteOwner","WriteDacl","GenericAll","GenericWrite","ExtendedRight")
    $sdRemoved = 0
    foreach ($ace in $sdACL.Access) {
        $trustee = $ace.IdentityReference.Value
        $rights = $ace.ActiveDirectoryRights.ToString()
        $hasHigh = $highRights | Where-Object { $rights.Contains($_) }
        if ($hasHigh -and $safePrincipals -notcontains $trustee) {
            if ($AuditOnly) {
                Log "AdminSDHolder: '$trustee' has [$rights] -- unauthorized"
            } else {
                [void]$sdACL.RemoveAccessRule($ace)
                $sdRemoved++
            }
        }
    }
    if (-not $AuditOnly -and $sdRemoved -gt 0) {
        Set-ACL "AD:$adminSDDN" $sdACL
        Log "Removed $sdRemoved unauthorized ACE(s) from AdminSDHolder"
    }
} catch {
    Log "Could not read AdminSDHolder ACL: $_"
}

# 2h. KRBTGT password age check
try {
    $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
    $ageDays = ((Get-Date) - $krbtgt.PasswordLastSet).Days
    if ($ageDays -ge 1) {
        Log "KRBTGT password age: $ageDays days -- consider rolling (spray handles this)"
    }
} catch {}

# 2i. Kerberoastable SPN accounts with old passwords
$spnAccts = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires
foreach ($a in $spnAccts) {
    $old = $a.PasswordLastSet -and $a.PasswordLastSet -lt (Get-Date).AddDays(-90)
    if ($a.PasswordNeverExpires -or $old) {
        Log "SPN account '$($a.SamAccountName)' has old/never-expiring password -- Kerberoastable"
    }
}

# 2j. SIDHistory detection
try {
    $sidHistUsers = Get-ADUser -Filter {SIDHistory -ne "$null"} -Properties SIDHistory, SamAccountName
    foreach ($u in $sidHistUsers) {
        Log "User '$($u.SamAccountName)' has SIDHistory entries -- potential abuse vector"
    }
} catch {}

# ============================================================
#  SECTION 3: AGGRESSIVE (opt-in, may break things)
# ============================================================
if ($Aggressive) {
    Write-Host "`n--- Aggressive Hardening (may break legacy auth) ---" -ForegroundColor Yellow

    # 3a. NTLMv2 only (LmCompatibilityLevel=5) -- breaks NTLMv1 clients
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" 5

    # 3b. Block outgoing NTLM -- THIS BROKE OUR TEST VM (Mar 12)
    # Services relying on NTLM to other boxes will fail
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "RestrictSendingNTLMTraffic" 2

    # 3c. LDAP signing enforcement -- may break unsigned LDAP clients (scored service?)
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LDAPServerIntegrity" 2

    # 3d. LDAP channel binding
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LdapEnforceChannelBinding" 1

    # 3e. Block domain credential storage
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "DisableDomainCreds" 1

    # 3f. Unconstrained delegation removal
    $delegated = Get-ADObject -Filter 'UserAccountControl -band 524288' -Properties SamAccountName, UserAccountControl, ObjectClass
    foreach ($obj in $delegated) {
        if ($obj.ObjectClass -eq 'computer' -and $obj.SamAccountName -match '\$$') { continue } # skip DCs
        if ($AuditOnly) {
            Log "Account '$($obj.SamAccountName)' has unconstrained delegation"
        } else {
            Set-ADAccountControl $obj -TrustedForDelegation:$false -ErrorAction SilentlyContinue
            Log "Removed unconstrained delegation from '$($obj.SamAccountName)'"
        }
    }

    # 3g. RBCD cleanup
    $rbcd = Get-ADObject -LDAPFilter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" -Properties SamAccountName
    foreach ($obj in $rbcd) {
        if ($AuditOnly) {
            Log "Account '$($obj.SamAccountName)' has RBCD set"
        } else {
            Set-ADObject $obj -Clear msDS-AllowedToActOnBehalfOfOtherIdentity -ErrorAction SilentlyContinue
            Log "Cleared RBCD on '$($obj.SamAccountName)'"
        }
    }

    # 3h. Trust SID filtering
    try {
        $trusts = Get-ADTrust -Filter *
        foreach ($t in $trusts) {
            if (-not $t.SIDFilteringQuarantined) {
                if ($AuditOnly) {
                    Log "Trust '$($t.Name)' lacks SID filtering"
                } else {
                    Set-ADTrust $t.Name -EnableSIDHistory $false -Confirm:$false -ErrorAction SilentlyContinue
                    Log "Enabled SID filtering on trust '$($t.Name)'"
                }
            }
        }
    } catch {}
}

# ============================================================
#  SUMMARY
# ============================================================
Write-Host "`n$("-" * 60)" -ForegroundColor Cyan
if ($AuditOnly) {
    Write-Host "AUDIT COMPLETE -- no changes made. Re-run without -AuditOnly to apply." -ForegroundColor Yellow
} else {
    Write-Host "HARDENING COMPLETE on $env:COMPUTERNAME" -ForegroundColor Green
    Write-Host "Reboot recommended for LSA protection and some registry changes to take effect." -ForegroundColor Yellow
}
if (-not $Aggressive) {
    Write-Host "Tip: run with -Aggressive for NTLM/LDAP restrictions (test first!)." -ForegroundColor Cyan
}
