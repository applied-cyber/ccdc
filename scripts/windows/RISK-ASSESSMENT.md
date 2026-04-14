# Windows Defensive Toolkit Risk Assessment

## Shared Libraries

**`Common.ps1`:** Shared helper library that detects machine role, checks dependencies, and prints startup banners for the other scripts. It is not a direct tool by itself.

**`monitoring/Dashboard.ps1`:** Shared dashboard library that handles the common screen layout, counters, and CSV logging used by the `Watch-*` scripts. It is not a standalone tool by itself.

**`credentials/Password-Utils.ps1`:** Shared helper for credential scripts that handles password and hash file paths, state loading, and rotated backup output. It is not a direct tool by itself.

## `credentials/Roll-Passwords.ps1`

**Tool to be used:** Generates random passwords for domain users, previews all changes, and asks for confirmation before applying them. Writes a plaintext CSV for recovery and skips Administrator, `krbtgt`, Guest, and DefaultAccount by default.

**Actions:** Generates replacement passwords, previews them, writes a recovery CSV, and then resets selected AD account passwords after confirmation. It also triggers password-hash dumping before and after the roll to preserve rollback state.

**Rationale:** This is a fast way to shut off stolen or reused passwords. The preview and backup files make it easier to avoid changing accounts blindly.

**Risk:** Medium risk. Rotating passwords can break services, scheduled tasks, scripts, or admin access if those accounts are still being used somewhere. The plaintext password CSV is also sensitive and needs to be protected.

**Recovery:** Use the generated password CSV and saved hash state to restore access for anything that broke. If systems start failing, fix admin and service accounts first and then rerun the roll more narrowly.

## `disruption/Deploy-Honeypots.ps1`

**Tool to be used:** Creates tripwire artifacts like a decoy service account, canary SMB share, and bait scheduled task, then watches for anyone touching them. Alerts in real time when those honeypot artifacts are used.

**Actions:** Deploys decoy artifacts including a honey user, service, SMB share, and scheduled task, then monitors logs for interaction or removes them on request. It writes alert output to a dedicated log for follow-up triage.

**Rationale:** Normal admins should not be touching these artifacts, so alerts from them are useful signs that someone is poking around. It adds detection without changing much in day-to-day operations.

**Risk:** Low risk. The bait objects and fake credentials can confuse admins or create false positives if people do not know they are there. Bad share or audit settings can also create noise or expose more than intended.

**Recovery:** Remove the honeypots with the cleanup mode and make sure the share, account, task, and service are actually gone. If the names are now obvious, redeploy later with different ones.

## `disruption/Watch-Processes.ps1`

**Tool to be used:** Alerts on new processes that were not present in the startup baseline and shows the PID, path, and parent process. Optional `-AutoKill` will terminate unknown processes.

**Actions:** Takes a startup baseline of process names, polls for new processes, and logs details including PID, path, and parent context. With `-AutoKill`, it forcibly terminates processes not seen in the baseline or whitelist.

**Rationale:** This gives you a simple way to spot new or unexpected processes after startup. On a stable server, a new process is often worth looking at quickly.

**Risk:** Medium risk. The baseline is only based on process names, so normal software, admin tools, or recovery actions can get flagged or killed. `-AutoKill` can easily stop something important by mistake.

**Recovery:** Check the log, figure out what was legitimate, and restart anything important that got killed. If the box is too noisy, run it without `-AutoKill` or rebuild the baseline at a better time.

## `disruption/Watch-Persistence.ps1`

**Tool to be used:** Baselines scheduled tasks, services, and Run/RunOnce registry keys, then alerts when new persistence shows up. Optional `-AutoRemove` deletes new items automatically.

**Actions:** Baselines scheduled tasks, services, and Run/RunOnce registry entries, then alerts on newly created persistence items. In auto-remove mode it deletes newly detected items as they appear.

**Rationale:** Attackers often add tasks, services, or autoruns to keep access, so these are good places to watch. This gives you quick visibility into common persistence tricks.

**Risk:** Medium risk. Legitimate installers, admin fixes, or business software can get removed if they show up after the baseline is taken. That can break startup behavior or interrupt recovery work.

**Recovery:** Recreate any legitimate task, service, or autorun entry that got removed by mistake. If the system is changing a lot, turn off `-AutoRemove`, take a new baseline, and just alert on changes.

## `monitoring/Watch-Events.ps1`

**Tool to be used:** Monitors key Security event IDs like process creation, service installs, account changes, group changes, lockouts, and audit-policy changes. Shows them in a dashboard and writes a CSV log.

**Actions:** Polls the Security log for selected high-value event IDs such as process creation, service installs, account changes, group modifications, lockouts, and audit-policy changes. It renders the activity in a dashboard and writes a CSV trail.

**Rationale:** These event IDs cover a lot of the changes you usually care about during an incident. It gives you a quick stream of useful activity without changing the system.

**Risk:** Very low risk. If audit policy is weak or the host is noisy, the output may be incomplete or hard to use. Too many events can bury the ones that actually matter.

**Recovery:** If it is too noisy, use it on fewer systems or tighten the filtering and audit settings. If events are missing, fix logging first and then rerun it.

## `monitoring/Watch-AuthEvents.ps1`

**Tool to be used:** Monitors authentication activity across NTLM, Kerberos, LDAP, ExplicitCred, and WinRM with protocol detection and source IP tracking. Dashboard output is color-coded and written to CSV automatically.

**Actions:** Polls multiple authentication-related event IDs, classifies protocol usage, captures usernames and source IPs, and logs the results to a dashboard and CSV. It can optionally filter by protocol or include noisier service/system logons.

**Rationale:** Authentication events are one of the best ways to spot lateral movement, bad logons, and protocol abuse. This gives more detail than a simple success/failure logon watcher.

**Risk:** Very low risk. Busy systems can produce a lot of output, and important activity can get lost in the noise. It also depends on the right event logging being enabled.

**Recovery:** Cut the noise by using protocol filters or only running it on important hosts. If it is too much to watch live, keep the CSV logs and switch to a narrower monitor.

## `monitoring/Watch-Logons.ps1`

**Tool to be used:** Lightweight logon monitor for successful and failed logons with readable logon types and failure reasons. Simpler than `Watch-AuthEvents.ps1` when you do not need the full protocol breakdown.

**Actions:** Polls Security events 4624 and 4625, translates logon types and common failure codes, and prints readable success/failure lines. By default it suppresses service and system logon noise.

**Rationale:** This gives a quick view of successful and failed logons without a lot of extra detail. It is easier to watch live than the full authentication dashboard.

**Risk:** Very low risk. Because it is simpler, it misses other auth events and some useful context. Hiding service and system logons can also hide service-account abuse.

**Recovery:** If you need more detail, switch to `Watch-AuthEvents.ps1` or rerun with `-ShowAll`. Keep the times and source IPs so you can pivot into deeper investigation.

## `services/Snapshot-Services.ps1`

**Tool to be used:** Captures a read-only baseline of Windows services including binary path, SDDL, startup type, and logon account. Used as the baseline for `Watch-Services.ps1` and `Lock-Services.ps1`.

**Actions:** Enumerates services and records their names, startup state, binary path, SDDL, and logon account into JSON, while also printing a summary table. The snapshot becomes the baseline for service comparison and restoration decisions.

**Rationale:** You need a known-good baseline before you can tell whether services were changed or tampered with. It also gives you something to restore from later.

**Risk:** Low risk. If the host is already tampered with when you take the snapshot, you may end up treating bad service state as normal. The output file can also expose service accounts and paths.

**Recovery:** If the baseline looks bad, throw it out and take a new one from a cleaner point in time. Keep the snapshot file protected and refresh it after major service changes.

## `services/Watch-Services.ps1`

**Tool to be used:** Compares live service state to a `Snapshot-Services.ps1` baseline and alerts on binary path changes, SDDL changes, startup changes, new services, and deleted services. Optional `-AutoRevert` restores tampered services from the snapshot.

**Actions:** Compares live service state against the snapshot and alerts on new services, deleted services, binary-path changes, SDDL changes, and startup-type changes. In auto-revert mode it attempts to restore original paths and permissions automatically.

**Rationale:** Services are a common place for persistence and tampering, so they are worth watching closely. Auto-revert can quickly undo obvious service changes.

**Risk:** Medium risk. A bad or outdated baseline can cause it to revert normal changes or keep bad ones. `-AutoRevert` can also break approved maintenance or business software.

**Recovery:** If it starts reverting good changes, stop auto-revert and check the service state with whoever owns the system. Then update the baseline and restore the correct path, ACL, or startup type as needed.

## `services/Lock-Services.ps1`

**Tool to be used:** Restricts service DACLs so only a chosen admin account can reconfigure or delete services. Supports `-Include` and `-Exclude` so you can scope which services get locked down.

**Actions:** Builds a restrictive service DACL that leaves full control only to a nominated admin account while preserving limited SYSTEM rights needed for service control and boot behavior. It snapshots existing service security first and then applies the lockdown after confirmation.

**Rationale:** Attackers often use service changes for persistence or code execution, so limiting who can change services helps block that path. The snapshot gives you a way back if the lockdown causes problems.

**Risk:** Medium risk. If you lock too many services or pick the wrong admin account, you can lock out normal admins, tools, or recovery steps. Some problems may only show up after a reboot.

**Recovery:** Use the saved snapshot SDDL values to restore the original service permissions with `sc.exe sdset`. If only a few services are a problem, roll those back and rerun with a tighter include or exclude list.

## `hardening/Lock-Filesystem.ps1`

**Tool to be used:** Locks down staging directories and optionally critical system binaries like `cmd.exe`, `powershell.exe`, `sc.exe`, and `reg.exe`. Takes an ACL snapshot first so `Restore-Filesystem.ps1` can undo it later.

**Actions:** Captures ACL and owner data, then tightens permissions on staging directories and, if requested, critical binaries such as `cmd.exe`, `powershell.exe`, `sc.exe`, and `reg.exe`. It preserves a JSON snapshot so permissions can later be restored.

**Rationale:** If attackers can change your scripts or run common admin binaries freely, it gets much harder to contain them. Locking those paths down makes that abuse harder.

**Risk:** Medium risk. Locking down system binaries can break admin work, automation, remote management, or your own response steps. Tightening staging directories too much can also block legitimate use.

**Recovery:** Restore the ACLs from the snapshot with `Restore-Filesystem.ps1` and check that admin access works again. If only the binaries caused trouble, keep the directory lockdown and skip `-LockBinaries` next time.

## `hardening/Restore-Filesystem.ps1`

**Tool to be used:** Restores filesystem ACLs from a snapshot created by `Lock-Filesystem.ps1`. Use it to undo binary or directory permission lockdowns if they break something.

**Actions:** Reads the saved ACL snapshot and attempts to restore each file or directory’s original SDDL and owner. It skips missing paths and reports which restores succeeded or failed.

**Rationale:** If you are going to lock down filesystem permissions, you need a quick way to undo it. This gives you that rollback path.

**Risk:** Low risk. If the snapshot is old or already contains bad permissions, restore can bring those back. Partial restores can also leave the system in a messy in-between state.

**Recovery:** Check that the snapshot looks right before using it, rerun restore for failures, and fix any leftovers by hand if needed. After rollback, test admin access and take a clean snapshot before locking things down again.

## `hardening/DC.ps1`

**Tool to be used:** Standalone Domain Controller hardening script with a safer default mode and an `-Aggressive` mode that adds NTLM and LDAP restrictions. `-AuditOnly` shows what would change before you enforce anything.

**Actions:** Applies broad DC-focused hardening including SMB, Netlogon, Defender, audit, spooler, CertSvc, AD account protections, and selected persistence cleanup, with audit-only and aggressive modes. It also changes some directory objects and domain-wide settings, not just the local host.

**Rationale:** A domain controller is a high-value system, and this script covers a lot of common hardening changes in one place. It is useful when you need to move quickly.

**Risk:** Medium risk. This is one of the easiest tools here to break things with if you run it blindly. It can impact auth, legacy apps, AD operations, certificate services, and other domain-wide behavior.

**Recovery:** Run `-AuditOnly` first so you know what it plans to change. If enforcement breaks something, back out the affected registry, service, or AD changes in the order that gets the business working again.

## `dns/Backup-DNS.ps1`

**Tool to be used:** Exports DNS zones and records to CSV and JSON for backup and recovery on Domain Controllers. Good to run before making DNS changes.

**Actions:** Enumerates DNS zones and records, then writes a console table plus CSV and JSON backups for later recovery. It skips trust-anchor and `_msdcs` zones according to the script’s current logic.

**Rationale:** DNS changes can break a lot at once, and DNS is also a common place for tampering. A backup gives you something to compare against and restore from.

**Risk:** Low risk. If DNS is already tampered with when you back it up, you may just be saving the bad state. The export files can also expose internal naming details, and the backup may not include every zone you care about.

**Recovery:** Store the CSV and JSON safely and use them to compare against known-good records or rebuild zones if needed. If you are not sure when DNS was changed, compare this backup to older exports or other trusted sources before restoring.
