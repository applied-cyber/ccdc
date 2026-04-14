use std::ffi::OsString;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::fd::OwnedFd;
use std::path::PathBuf;

use anyhow::{Context, Result};

/// Raw bytes of the statically-linked bash binary built by build.rs.
pub const SSHD_EXE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bash"));

/// Create an anonymous memfd, write the embedded shell bytes into it,
/// and return the fd ready for exec via `/proc/self/fd/{N}`.
/// Each call creates a fresh memfd — the caller owns it.
pub fn create_shell_memfd() -> Result<MemfdShell> {
    MemfdShell::new()
}

/// A live memfd containing the embedded shell, ready to be passed to `exec()`.
pub struct MemfdShell {
    fd: File,
    path: PathBuf,
    login_arg0: OsString,
}

impl MemfdShell {
    pub fn new() -> Result<Self> {
        use rustix::fs::{MemfdFlags, memfd_create};

        let fd = memfd_create("securesshd-sh", MemfdFlags::empty())
            .context("memfd_create failed")?;

        let raw = OwnedFd::from(fd).into_raw_fd();
        let mut f = unsafe { File::from_raw_fd(raw) };

        // Set rwx permissions so the kernel can exec the memfd after setuid.
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o755))
            .context("failed to set memfd permissions")?;

        f.write_all(SSHD_EXE)
            .context("failed to write embedded shell to memfd")?;
        f.seek(SeekFrom::Start(0))
            .context("failed to seek memfd to start")?;

        let path = PathBuf::from(format!("/proc/self/fd/{raw}"));
        let login_arg0 = OsString::from("-bash");

        Ok(MemfdShell {
            fd: f,
            path,
            login_arg0,
        })
    }

    /// The `/proc/self/fd/{N}` path to pass to `exec()`.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// The `-bash` arg0 for login-shell invocation.
    pub fn login_arg0(&self) -> &OsString {
        &self.login_arg0
    }

    /// Raw fd number (useful for pre_exec closures).
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_shell_is_nonzero_size() {
        assert!(SSHD_EXE.len() > 0);
    }

    #[test]
    fn starts_with_elf_magic() {
        assert_eq!(&SSHD_EXE[..4], b"\x7fELF");
    }

    #[test]
    fn create_memfd_is_usable() {
        let shell = create_shell_memfd().unwrap();
        assert!(shell.path().to_string_lossy().starts_with("/proc/self/fd/"));
        assert_eq!(shell.login_arg0().to_string_lossy(), "-bash");
    }

    #[test]
    fn can_exec_from_memfd() {
        use std::os::unix::process::CommandExt;
        use std::process::Command;
        let shell = create_shell_memfd().unwrap();
        let mut cmd = Command::new(shell.path());
        cmd.arg0(shell.login_arg0().clone());
        cmd.arg("-c").arg("echo hello");
        let output = cmd.output().unwrap();
        assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    }

    #[test]
    fn can_exec_from_memfd_with_pipes() {
        use std::io::Read;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let shell = create_shell_memfd().unwrap();
        let mut cmd = Command::new(shell.path());
        cmd.arg0(shell.login_arg0().clone());
        cmd.arg("-c").arg("echo hello_from_pipes");
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        drop(child.stdin.take());
        let mut stdout = Vec::new();
        child.stdout.as_mut().unwrap().read_to_end(&mut stdout).unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "stderr present");
        assert!(String::from_utf8_lossy(&stdout).contains("hello_from_pipes"));
    }
}
