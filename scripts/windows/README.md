# Windows Defensive Toolkit — File Manifest

## Shared Libraries

**`Common.ps1`**
Shared utility library that detects machine role (Domain Controller, Member Server, or Workstation) and validates module/command dependencies before scripts run. Dot-sourced automatically by most other scripts in the toolkit.

**`monitoring/Dashboard.ps1`**
Shared rendering library that provides fixed-width column output, color-coded rows, running totals, and automatic CSV logging. Dot-sourced by all Watch-* scripts to produce consistent dashboard-style console output.

## Credential Management

**`credentials/Password-Utils.ps1`**
Helper library for credential scripts that manages CSV output file paths and rotates numbered backups so previous states are always preserved. Required by Roll-Passwords for state tracking and recovery.

**`credentials/Roll-Passwords.ps1`**
Generates random passwords for domain users, previews all changes in a table, and requires confirmation before applying. Writes plaintext CSV for recovery and excludes Administrator, krbtgt, Guest, and DefaultAccount by default.

## Monitoring

**`monitoring/Watch-AuthEvents.ps1`**
Monitors all authentication protocols (Kerberos, NTLM, LDAP, ExplicitCred, WinRM) across event IDs 4624, 4625, 4768, 4769, 4776, 4648, and 2889 with protocol classification and source IP tracking. Dashboard output with color-coded protocol columns, failure reason translation, and automatic CSV logging.

**`monitoring/Watch-Events.ps1`**
Monitors 8 suspicious security event types including process creation, service installs, user account changes, group membership modifications, account lockouts, and audit policy changes. Dashboard output with per-event-type color coding and automatic CSV logging.

**`monitoring/Watch-Logons.ps1`**
Lightweight authentication monitor for logon successes and failures with logon type and failure reason translation. Simpler alternative to Watch-AuthEvents when full protocol breakdown is not needed.

## Disruption / Active Defense

**`disruption/Watch-Persistence.ps1`**
Baselines scheduled tasks, services, and registry Run/RunOnce keys at startup, then alerts when new persistence mechanisms appear. Optional `-AutoRemove` flag automatically deletes unauthorized persistence items.

**`disruption/Watch-Processes.ps1`**
Alerts on new processes not present in a baseline snapshot taken at startup, showing PID, path, and parent process info. Optional `-AutoKill` flag terminates unknown processes, with a built-in whitelist for transient system processes.

**`disruption/Deploy-Honeypots.ps1`**
Creates tripwire artifacts — a decoy service account with denied logon hours, a canary SMB share with fake credentials, and a bait scheduled task — then monitors event logs for interaction. Alerts in real-time when red team touches any honeypot artifact.

## Service Protection

**`services/Snapshot-Services.ps1`**
Captures a read-only baseline of every Windows service including binary path, SDDL permissions, startup type, and logon account. Used as the reference point for Watch-Services and Lock-Services.

**`services/Watch-Services.ps1`**
Compares live service state against a Snapshot-Services baseline every 15 seconds, alerting on binary path changes, SDDL permission modifications, startup type changes, new services, and deleted services. Optional `-AutoRevert` flag restores tampered services from the snapshot automatically.

**`services/Lock-Services.ps1`**
Restricts service DACLs so only a specified admin account can reconfigure or delete services, blocking sc.exe-based persistence from SYSTEM shells. Supports `-Include` to target specific services or `-Exclude` to skip critical ones.

## Filesystem Protection

**`hardening/Lock-Filesystem.ps1`**
Restricts execute permissions on critical system binaries (cmd.exe, powershell.exe, net.exe, reg.exe) to administrator-only access. Takes an ACL snapshot before changes so Restore-Filesystem can roll back if needed.

**`hardening/Restore-Filesystem.ps1`**
Restores filesystem ACLs from a snapshot created by Lock-Filesystem. Use this to undo binary permission lockdowns if they break something.

## DNS

**`dns/Backup-DNS.ps1`**
Exports all DNS zones to CSV and JSON format for disaster recovery on Domain Controllers. Run once at minute 0 before touching any DNS configuration.
