use std::fs::File;
use std::process;

use anyhow::{Context, Result};
use rustix::process::setsid;
use rustix::stdio::{dup2_stderr, dup2_stdin, dup2_stdout};

/// Classic double-fork daemonize: detach from the controlling terminal,
/// start a new session, and redirect stdio to /dev/null.
pub fn daemonize() -> Result<()> {
    // First fork — parent exits, child continues.
    match unsafe { libc::fork() } {
        -1 => return Err(std::io::Error::last_os_error()).context("first fork failed"),
        0 => {}                  // child
        _ => process::exit(0),   // parent
    }

    // Become session leader, detach from controlling terminal.
    setsid().context("setsid failed")?;

    // Second fork — session leader exits so the daemon can never
    // re-acquire a controlling terminal.
    match unsafe { libc::fork() } {
        -1 => return Err(std::io::Error::last_os_error()).context("second fork failed"),
        0 => {}                  // grandchild (the daemon)
        _ => process::exit(0),   // session leader
    }

    // Redirect stdin/stdout/stderr to /dev/null.
    let devnull = File::open("/dev/null").context("failed to open /dev/null")?;
    dup2_stdin(&devnull).context("failed to redirect stdin to /dev/null")?;
    dup2_stdout(&devnull).context("failed to redirect stdout to /dev/null")?;
    dup2_stderr(&devnull).context("failed to redirect stderr to /dev/null")?;

    Ok(())
}
