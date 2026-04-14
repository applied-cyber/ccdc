use std::time::Duration;

use anyhow::Result;
use clap::Parser;

use securesshd::cli::Cli;
use securesshd::config::{DEFAULT_PORT, RuntimeConfig};
use securesshd::daemonize::daemonize;
use securesshd::server;
use securesshd::systemd;

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    // Always re-check the binary and systemd unit file are in place. Best
    // effort — failures here (e.g. not root, no systemd) shouldn't block
    // startup.
    if systemd::is_systemd_available() {
        if let Err(err) = systemd::ensure_binary_installed() {
            log::warn!("failed to install securesshd binary: {err:#}");
        }
        if let Err(err) = systemd::ensure_installed() {
            log::warn!("failed to ensure systemd unit installed: {err:#}");
        }
    }

    // If we weren't started by systemd and aren't in foreground test mode,
    // hand off to systemd: enable + start the configured port instances,
    // then exit. Systemd takes over from here.
    if !cli.foreground && !systemd::is_running_under_systemd() {
        let mut delegated_to_systemd = false;

        if systemd::is_systemd_available() {
            match systemd::enable_and_start() {
                Ok(()) => {
                    match systemd::wait_for_listener(DEFAULT_PORT, Duration::from_secs(30)) {
                        Ok(()) => delegated_to_systemd = true,
                        Err(err) => {
                            log::warn!(
                                "systemd securesshd did not come up within 30s, falling back to in-process server: {err:#}"
                            );
                        }
                    }
                }
                Err(err) => {
                    log::warn!(
                        "systemctl enable --now failed, falling back to in-process server: {err:#}"
                    );
                }
            }
        }

        if delegated_to_systemd {
            return Ok(());
        }

        // Either systemd is unavailable or it failed to bring securesshd up in
        // time — daemonize and serve from this process instead.
        daemonize()?;
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let runtime = RuntimeConfig::production(&cli)?;
            server::run(runtime).await
        })
}
