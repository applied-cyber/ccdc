# Ansible Playbook Risk Assessments

All automation in this section is driven by **Ansible**, which connects to target machines over SSH to execute tasks remotely - no additional software needs to be installed on the machines being managed.

Unless otherwise noted, recovery for all playbooks follows the same procedure:
1. Immediately halt the running Ansible playbook.
2. Push a targeted rollback of the specific task that caused the issue.
3. This is straightforward because we already have the infrastructure to run commands at scale across all machines, and Ansible's declarative model makes it easy to precisely reverse any individual change.

---

## linux_init_config

- **Actions:** Create required working directories, install vim and lsof, and deploy busybox on all Linux hosts.
- **Rationale:** Establishes a consistent baseline environment across all Linux hosts before any other automation is run.
- **Risk:** Very low - only creates directories and installs common utilities; does not modify any existing configuration or services.

---

## linux_backup

- **Actions:** Archive key system directories (configuration files, web content, cron jobs, shell history) and all home directories, then copy the archives back to the management server.
- **Rationale:** Preserves a snapshot of each host's state early in the process so there is a known-good baseline to restore from if anything goes wrong.
- **Risk:** Very low - purely a read and copy operation; nothing is modified on the target hosts.

---

## linux_graylog

- **Actions:** Install logging software (rsyslog and auditd), configure it to record all commands executed on the system, and forward those logs to a central Graylog server.
- **Rationale:** Centralizes visibility across all hosts so the team can detect and investigate suspicious activity in real time.
- **Risk:** Low - adds new logging configuration and restarts logging services, but does not touch core system functionality or access controls.

---

## linux_harden

- **Actions:** Remove elevated privileges from system binaries, relocate potentially dangerous tools out of standard paths, apply kernel-level security settings, disable unnecessary services (printing, scheduling, package snapping), and clear all scheduled tasks.
- **Rationale:** Reduces the attack surface available to an adversary who has gained a foothold on a host by eliminating common privilege escalation and persistence mechanisms.
- **Risk:** Medium - makes broad, impactful changes to system configuration. Some services are stopped and certain binaries are moved, which could affect workflows that depend on them.

---

## linux_immutable

- **Actions:** Lock the SSH daemon binary, SSH configuration, and the user account database files so they cannot be modified or deleted until explicitly unlocked.
- **Rationale:** Prevents an adversary from backdooring the SSH service or tampering with user accounts even if they gain root access.
- **Risk:** Low - does not change any configuration, only applies a protection flag. Legitimate changes to these files will require an extra unlock step.

---

## linux_sshd_harden

- **Actions:** Deploy a custom SSH server binary, restrict the SSH configuration to disallow root login, password-only authentication, and tunneling, and limit access to only authorized user accounts.
- **Rationale:** Locks down remote access to the host so that only the team's designated accounts can log in, and only with approved credentials.
- **Risk:** Low - tightens access controls without removing access for authorized users. A misconfiguration could prevent logins, but safeguards are in place to validate the configuration before applying it.

---

## linux_vulnscan

- **Actions:** Scan each host for known critical kernel vulnerabilities, unauthorized privileged accounts, improperly permissioned files, and suspicious binaries - then report findings.
- **Rationale:** Provides rapid situational awareness of the most dangerous exposures on each host without making any changes.
- **Risk:** Very low - entirely read-only; no changes are made to any host.

---

## service_linux_php_harden

- **Actions:** Locate PHP configuration files, apply a set of hardened settings (disabling dangerous functions, file uploads, remote includes, and error display), restart the web server if changes were made, and lock down the web root directory against further modification.
- **Rationale:** Removes common PHP-based attack vectors on hosted web applications without touching the application code itself.
- **Risk:** Medium - modifies live PHP configuration and restarts the web server, which could temporarily disrupt service or break applications that rely on disabled functionality.

---

## service_bsd_php_harden

- **Actions:** Same as service_linux_php_harden, applied to BSD hosts using BSD-specific paths and tools.
- **Rationale:** Applies the same PHP hardening protections to BSD-based web servers.
- **Risk:** Medium - same considerations as service_linux_php_harden; web server restart may cause brief disruption.

---

## service_windows_php_harden

- **Actions:** Locate PHP configuration files on Windows, back them up, apply hardened settings (disabling dangerous functions, file uploads, remote includes, and error display), and restart any running web services.
- **Rationale:** Applies the same PHP hardening protections to Windows-based web servers.
- **Risk:** Medium - modifies live PHP configuration and restarts web services, which could temporarily disrupt hosted applications.

---

## service_ssh_generate_passwords

- **Actions:** Read the list of user accounts with login shells on each host, generate a unique random password for each, and save the credentials to a file on the management server - without changing anything on the target hosts.
- **Rationale:** Produces a fresh set of credentials that can be reviewed and then applied in a controlled, separate step.
- **Risk:** Low - entirely read-only on the target hosts; only writes credential files locally on the management server.

---

## service_ssh_change_passwords

- **Actions:** Read the credential files generated by service_ssh_generate_passwords, back up the current user account database, and apply the new passwords to each user account.
- **Rationale:** Rotates credentials across all SSH-accessible accounts to lock out any adversary using compromised passwords.
- **Risk:** Low - changes user passwords, which could lock out legitimate users if the credential files are lost or misapplied; safeguards verify the files exist before proceeding.

---

## service_ssh_secure_shell

- **Actions:** Deploy a restricted shell binary and configure SSH to force all non-administrative login-shell users into it, preventing them from running arbitrary commands.
- **Rationale:** Limits what scored SSH users can do on the system even if their credentials are compromised, containing the blast radius of a login.
- **Risk:** Low - does not remove access for any user, only constrains what they can do after logging in; configuration is validated before the SSH service is restarted.

---

## windows_backup

- **Actions:** Export firewall rules, registry hives, scheduled tasks, IIS configuration, and user directories, then copy the archives back to the management server.
- **Rationale:** Preserves a snapshot of each Windows host's state so there is a known-good baseline to restore from if anything goes wrong.
- **Risk:** Very low - purely a read and copy operation; nothing is modified on the target hosts.

---

## windows_update

- **Actions:** Install all pending Windows security updates and reboot the host.
- **Rationale:** Closes known vulnerabilities by ensuring the host is fully patched.
- **Risk:** Low - the update process is standard and well-tested, though the required reboot will briefly take the host offline.

---

## windows_harden

- **Actions:** Remove administrative file shares, apply a broad set of registry-based security settings (disabling legacy protocols, locking down authentication, stopping unnecessary services, clearing scheduled tasks and autorun entries), and remove known attacker footholds such as sticky keys and the MSDT protocol handler.
- **Rationale:** Eliminates a wide range of common Windows attack vectors and persistence mechanisms in a single pass.
- **Risk:** Medium - makes broad, impactful changes to system configuration; some services are stopped and certain features are disabled, which could affect workflows that depend on them.

---

## windows_graylog

- **Actions:** Install Sysmon with a standard configuration and the NXLog log shipper, then configure NXLog to forward Windows event logs to the central Graylog server.
- **Rationale:** Provides deep visibility into activity on Windows hosts by shipping structured event logs to the central logging infrastructure.
- **Risk:** Low - installs two new software packages and configures log forwarding; does not touch core system settings or running services beyond restarting NXLog.

---

## windows_defender

- **Actions:** Enable and configure Windows Defender with real-time protection, behavior monitoring, network protection, and a set of Attack Surface Reduction rules; clear all existing exclusions and restrict the whitelist to a single trusted path.
- **Rationale:** Ensures the built-in antivirus is fully enabled, properly tuned, and not silently disabled or bypassed via exclusions left by an adversary.
- **Risk:** Low - configures an already-present Windows component; newly enabled ASR rules may block some legitimate software, but no core system functionality is removed.

---

## bsd_harden

- **Actions:** Remove elevated privileges from system binaries, relocate dangerous tools out of standard paths, enable BSD kernel security hardening (securelevel), disable unnecessary network services, clear scheduled tasks, and lock the SSH daemon binary.
- **Rationale:** Applies the same hardening philosophy as linux_harden to BSD hosts, reducing the attack surface and limiting persistence mechanisms available to an adversary.
- **Risk:** Medium - makes broad changes to system configuration and stops several services; some tooling may be affected by relocated binaries.
