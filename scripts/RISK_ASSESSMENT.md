# Script Risk Assessments

---

## create_backup.sh

- **Tool to be used:** Bash
- **Actions:** Copy important system configuration files to a backup location.
- **Rationale:** Preserves a known-good snapshot of critical configs before any other operations are run.
- **Risk:** Very low - read and copy only; does not modify any existing files or running services.
- **Recovery:** Delete the backup files created by the script.

---

## database_redaction.py

- **Tool to be used:** Python
- **Actions:** Scan offline database files and redact personally identifiable information (PII) found within them.
- **Rationale:** Prevents sensitive data from being exposed or exfiltrated by scrubbing PII from databases that are not actively serving traffic.
- **Risk:** Very low - operates only on offline databases that are not attached to any running service; no live systems or active connections are touched.
- **Recovery:** Restore the original database files from backup.

---

## multiple.py

- **Tool to be used:** Python
- **Actions:** Take a script and execute it across multiple target machines over SSH.
- **Rationale:** Provides a simple way to run a command or script at scale without requiring a full Ansible setup.
- **Risk:** Low - the script itself is a thin dispatch layer; risk is determined entirely by whatever script is being sent, not by multiple.py itself.
- **Recovery:** Immediately halt the script; any changes made by the dispatched script must be rolled back individually per host.

---

## scell.c

- **Tool to be used:** C (compiled binary)
- **Actions:** Launch a real, fully functional interactive shell for a user while enforcing that no unauthorized privilege escalation can occur within the session.
- **Rationale:** Ensures authorized users have shell access while preventing unauthorized privilege escalation.
- **Risk:** Low - users get a real shell with actual functionality; the security guarantee is that privilege boundaries are enforced at the session level.
- **Recovery:** Terminate the user's shell session.

---

## bsd.sh

- **Tool to be used:** Bash
- **Actions:** Back up passwd and SSH files, reset credentials for root and admin accounts, install fixed SSH keys, enable root SSH login, and replace the firewall policy with a narrow pf ruleset. Also restarts SSH and enables the firewall.
- **Rationale:** Rapidly reclaims control of a BSD host and cuts off unauthorized access in a single pass, ensuring the team has working SSH access and a basic firewall in place.
- **Risk:** Medium - directly rewrites account files, changes root access, replaces SSH trust, and loads a new firewall policy. If the host requires different users, keys, or ports this can break access or disrupt legitimate services.
- **Recovery:** Restore `/etc/master.passwd`, `/etc/passwd`, `/etc/ssh/sshd_config`, `/root/.ssh/authorized_keys`, and `/etc/pf.conf` from the `.bak` files the script creates. If network access breaks, disable or reload pf with a known-good ruleset and rebuild user access.

---

## linux.sh

- **Tool to be used:** Bash
- **Actions:** Back up passwd and shadow files, reset credentials for root and admin accounts, install a fixed SSH key for root, update sshd_config, disable existing firewall tools, and apply a new default-drop iptables policy. Also adds a hosts file entry for the CCS domain.
- **Rationale:** Rapidly pushes a Linux host into a known state for remote admin access and basic network filtering, giving the team a quick way to reset credentials and clamp down on exposure.
- **Risk:** Medium - rewrites password files, changes SSH behavior, and replaces the entire firewall policy. This can break logins, management paths, application traffic, or DNS access if the rules do not fit the host.
- **Recovery:** Restore `/etc/passwd`, `/etc/shadow`, `/etc/ssh/sshd_config`, `/root/.ssh/authorized_keys`, and the saved iptables backup. If the firewall is the issue, set policies back to accept, reload the saved rules, and rebuild a tailored ruleset for that host.

---

## Watch-AuthEvents.ps1

- **Tool to be used:** PowerShell
- **Actions:** Poll Windows event logs for NTLM, Kerberos, LDAP, WinRM, RDP, and related authentication events; display them in a live console view; and optionally write results to a CSV file. Supports filtering by protocol, username, and source IP.
- **Rationale:** Provides broad, real-time visibility into authentication activity from one place, making it easier to spot bad logons, lateral movement, and protocol misuse during an incident.
- **Risk:** Very low - read-only monitoring script; does not change system state.
- **Recovery:** Stop the script. If output is too noisy, narrow the filters or shorten the lookback window before restarting.

---

## Watch-SSHAuth.sh

- **Tool to be used:** Bash
- **Actions:** Attach strace to the running sshd process, parse write() calls, filter out normal SSH protocol noise, and print likely credential strings to the console or an output file.
- **Rationale:** Gives defenders visibility into SSH authentication attempts at the process level, useful when normal log data is limited or delayed.
- **Risk:** Medium - does not change configuration, but attaches to a live sshd process which can add overhead and may expose credentials in plain text on screen or in logs.
- **Recovery:** Stop the script and securely remove any output files. If credentials were captured, treat them as compromised, rotate them, and clear any shell history that may contain them.

---

## windows.ps1

- **Tool to be used:** PowerShell
- **Actions:** Reset the local Administrator password, add backup admin users, apply SMB/RDP/service hardening settings, install or configure OpenSSH with fixed keys and allowed users, update the hosts file, and rewrite Windows Firewall rules. On domain controllers, also rotates the krbtgt account and adds emergency users to Domain Admins.
- **Rationale:** Rapidly reclaims control of a Windows host and applies a broad set of hardening changes in one pass, ensuring the team has a known remote-access path through SSH.
- **Risk:** Medium - changes credentials, admin group membership, SSH access, services, registry settings, and firewall policy in a single operation. On a domain controller especially, incorrect assumptions about the environment can break authentication or business-critical services.
- **Recovery:** Restore firewall settings from the exported backup if networking breaks, restore sshd_config from its backup, and back out the account, group, service, and registry changes that caused the issue. On a DC, prioritize restoring domain authentication and admin access first.
