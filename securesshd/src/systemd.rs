use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

const UNIT_PATH: &str = "/etc/systemd/system/securesshd@.service";
const INSTALLED_BINARY: &str = "/usr/bin/securesshd";

const UNIT_CONTENT: &str = "[Unit]
Description=securesshd ssh server on port %i
DefaultDependencies=no
After=network.target
Wants=network.target
Before=basic.target multi-user.target
Conflicts=shutdown.target

[Service]
Type=simple
ExecStart=/usr/bin/securesshd --foreground --port %i
Restart=always
RestartSec=30
StartLimitIntervalSec=0

[Install]
WantedBy=sysinit.target multi-user.target
";

const ENABLED_INSTANCES: &[&str] = &["securesshd@22.service", "securesshd@50000.service"];

pub fn is_systemd_available() -> bool {
    Path::new("/run/systemd/system").exists()
}

pub fn is_running_under_systemd() -> bool {
    std::env::var_os("INVOCATION_ID").is_some()
}

/// Copy the current executable to /usr/bin/securesshd if it's not already there
/// or differs from the currently running binary.
pub fn ensure_binary_installed() -> Result<()> {
    let current = std::env::current_exe().context("failed to read current exe path")?;
    let target = Path::new(INSTALLED_BINARY);

    if current == target {
        return Ok(());
    }

    let current_bytes = fs::read(&current)
        .with_context(|| format!("failed to read current exe at {}", current.display()))?;

    if let Ok(existing) = fs::read(target) {
        if existing == current_bytes {
            return Ok(());
        }
    }

    fs::write(target, &current_bytes)
        .with_context(|| format!("failed to install binary to {INSTALLED_BINARY}"))?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("failed to chmod {INSTALLED_BINARY}"))?;

    log::info!("installed securesshd binary at {INSTALLED_BINARY}");
    Ok(())
}

/// Write the unit file if it's missing or out of date, and reload systemd.
pub fn ensure_installed() -> Result<()> {
    let needs_write = match fs::read_to_string(UNIT_PATH) {
        Ok(existing) => existing != UNIT_CONTENT,
        Err(_) => true,
    };

    if !needs_write {
        return Ok(());
    }

    fs::write(UNIT_PATH, UNIT_CONTENT)
        .with_context(|| format!("failed to write systemd unit to {UNIT_PATH}"))?;

    let status = Command::new("systemctl")
        .arg("daemon-reload")
        .status()
        .context("failed to run systemctl daemon-reload")?;
    if !status.success() {
        anyhow::bail!("systemctl daemon-reload failed");
    }

    log::info!("installed systemd unit at {UNIT_PATH}");
    Ok(())
}

/// Enable and start each configured securesshd@<port>.service instance independently.
/// A failure on one instance (e.g. port 22 already taken by sshd) does not
/// prevent the others from starting. Returns Ok if at least one instance was
/// enabled successfully.
pub fn enable_and_start() -> Result<()> {
    let mut any_succeeded = false;

    for instance in ENABLED_INSTANCES {
        let status = Command::new("systemctl")
            .arg("enable")
            .arg("--now")
            .arg(instance)
            .status()
            .with_context(|| format!("failed to run systemctl enable --now {instance}"))?;

        if status.success() {
            log::info!("systemd unit {instance} enabled and started");
            any_succeeded = true;
        } else {
            log::warn!(
                "systemctl enable --now {instance} failed (port may be in use); systemd will keep retrying"
            );
        }
    }

    if !any_succeeded {
        anyhow::bail!("no securesshd systemd instances could be started");
    }
    Ok(())
}

/// Block until something is listening on `port` on localhost, or `timeout` elapses.
pub fn wait_for_listener(port: u16, timeout: Duration) -> Result<()> {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let deadline = Instant::now() + timeout;
    let mut last_err: Option<std::io::Error> = None;

    while Instant::now() < deadline {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(_) => return Ok(()),
            Err(err) => {
                last_err = Some(err);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    let msg = last_err
        .map(|e| e.to_string())
        .unwrap_or_else(|| "no connection attempt error recorded".into());
    anyhow::bail!("timed out waiting for securesshd on port {port}: {msg}")
}
