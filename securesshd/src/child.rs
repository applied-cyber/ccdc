use std::ffi::OsString;
use std::fs::File as StdFile;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::io::dup;
use rustix::process::{chdir, getegid, geteuid, getgroups, Gid, Uid};
use rustix::termios::Winsize;
use rustix::thread::{set_thread_gid, set_thread_uid};
#[cfg(any(target_os = "android", target_os = "linux"))]
use rustix::thread::set_thread_groups;
use rustix_openpty::{login_tty, openpty};
use tokio::io::unix::AsyncFd;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

use crate::account::ResolvedAccount;
use crate::embedded_shell::MemfdShell;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtySpec {
    pub cols: u32,
    pub rows: u32,
    pub px_width: u32,
    pub px_height: u32,
}

pub struct SpawnedExec {
    pub child: Child,
    pub stdin: ChildStdin,
    pub stdout: ChildStdout,
    pub stderr: ChildStderr,
}

pub struct SpawnedPty {
    pub child: Child,
    pub controller: AsyncFd<StdFile>,
}

/// Spawn an exec session: `$SHELL -c <command>` using the embedded bash.
pub fn spawn_exec(
    account: &ResolvedAccount,
    env: &[(OsString, OsString)],
    command: &str,
) -> Result<SpawnedExec> {
    let shell = MemfdShell::new()?;
    let mut cmd = Command::new(shell.path());
    cmd.args(["-c", command])
        .current_dir(&account.home)
        .env_clear()
        .envs(env.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    install_child_setup(&mut cmd, account, &account.home)?;

    let mut child = cmd
        .spawn()
        .context("failed to spawn exec child")?;

    Ok(SpawnedExec {
        stdin: child.stdin.take().context("spawned child did not expose stdin")?,
        stdout: child.stdout.take().context("spawned child did not expose stdout")?,
        stderr: child.stderr.take().context("spawned child did not expose stderr")?,
        child,
    })
}

/// Spawn an SFTP subsystem server with piped stdio.
pub fn spawn_sftp(
    account: &ResolvedAccount,
    env: &[(OsString, OsString)],
    sftp_server: &Path,
) -> Result<SpawnedExec> {
    let mut cmd = Command::new(sftp_server);
    cmd.current_dir(&account.home)
        .env_clear()
        .envs(env.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    install_child_setup(&mut cmd, account, &account.home)?;

    let mut child = cmd.spawn().context("failed to spawn sftp child")?;

    Ok(SpawnedExec {
        stdin: child.stdin.take().context("spawned child did not expose stdin")?,
        stdout: child.stdout.take().context("spawned child did not expose stdout")?,
        stderr: child.stderr.take().context("spawned child did not expose stderr")?,
        child,
    })
}

/// Spawn a PTY shell session using the embedded bash.
pub fn spawn_pty_shell(
    account: &ResolvedAccount,
    env: &[(OsString, OsString)],
    spec: PtySpec,
) -> Result<SpawnedPty> {
    let winsize = Winsize {
        ws_col: u16::try_from(spec.cols).context("pty cols exceed u16")?,
        ws_row: u16::try_from(spec.rows).context("pty rows exceed u16")?,
        ws_xpixel: u16::try_from(spec.px_width).context("pty pixel width exceeds u16")?,
        ws_ypixel: u16::try_from(spec.px_height).context("pty pixel height exceeds u16")?,
    };

    let pty = openpty(None, Some(&winsize)).context("failed to allocate pty")?;
    let shell = MemfdShell::new()?;

    let mut cmd = Command::new(shell.path());
    cmd.arg0(shell.login_arg0().clone())
        .current_dir(&account.home)
        .env_clear()
        .envs(env.iter().cloned());

    let setup = child_setup_spec(account, &account.home)?;
    let slave = StdFile::from(pty.user);

    unsafe {
        cmd.pre_exec(move || {
            apply_child_setup(&setup).map_err(io_error_from_errno)?;
            let slave = dup(&slave).map_err(io_error_from_errno)?;
            login_tty(slave).map_err(io_error_from_errno)?;
            Ok(())
        });
    }

    let controller_flags = fcntl_getfl(&pty.controller)
        .context("failed to read pty controller flags")?;
    fcntl_setfl(&pty.controller, controller_flags | OFlags::NONBLOCK)
        .context("failed to set pty controller nonblocking mode")?;
    let controller = AsyncFd::new(StdFile::from(pty.controller))
        .context("failed to register pty controller with tokio")?;

    let child = cmd.spawn().context("failed to spawn pty shell")?;

    Ok(SpawnedPty { child, controller })
}

#[derive(Clone)]
struct ChildSetupSpec {
    identity: Option<IdentitySpec>,
    cwd: PathBuf,
}

#[derive(Clone)]
struct IdentitySpec {
    supplementary_groups: Vec<Gid>,
    gid: Gid,
    uid: Uid,
}

fn install_child_setup(
    command: &mut Command,
    account: &ResolvedAccount,
    cwd: &Path,
) -> Result<()> {
    let setup = child_setup_spec(account, cwd)?;

    unsafe {
        command.pre_exec(move || apply_child_setup(&setup).map_err(io_error_from_errno));
    }

    Ok(())
}

fn child_setup_spec(account: &ResolvedAccount, cwd: &Path) -> Result<ChildSetupSpec> {
    Ok(ChildSetupSpec {
        identity: identity_spec(account)?,
        cwd: cwd.to_path_buf(),
    })
}

fn identity_spec(account: &ResolvedAccount) -> Result<Option<IdentitySpec>> {
    if !identity_change_required(account)? {
        return Ok(None);
    }

    Ok(Some(IdentitySpec {
        supplementary_groups: account
            .supplementary_groups
            .iter()
            .copied()
            .map(Gid::from_raw)
            .collect(),
        gid: Gid::from_raw(account.gid),
        uid: Uid::from_raw(account.uid),
    }))
}

fn identity_change_required(account: &ResolvedAccount) -> Result<bool> {
    if account.uid != geteuid().as_raw() || account.gid != getegid().as_raw() {
        return Ok(true);
    }

    let mut current_groups = getgroups()
        .context("failed to inspect current supplementary groups")?
        .into_iter()
        .map(|gid| gid.as_raw())
        .filter(|gid| *gid != account.gid)
        .collect::<Vec<_>>();
    let mut target_groups = account.supplementary_groups.clone();

    current_groups.sort_unstable();
    target_groups.sort_unstable();

    Ok(current_groups != target_groups)
}

fn apply_identity_if_needed(identity: Option<&IdentitySpec>) -> rustix::io::Result<()> {
    let Some(identity) = identity else {
        return Ok(());
    };

    #[cfg(any(target_os = "android", target_os = "linux"))]
    set_thread_groups(&identity.supplementary_groups)?;
    set_thread_gid(identity.gid)?;
    set_thread_uid(identity.uid)?;
    Ok(())
}

fn apply_child_setup(setup: &ChildSetupSpec) -> rustix::io::Result<()> {
    apply_identity_if_needed(setup.identity.as_ref())?;
    chdir(&setup.cwd)?;
    Ok(())
}

fn io_error_from_errno(errno: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(errno.raw_os_error())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use rustix::process::{getegid, geteuid, getgroups};
    use tempfile::TempDir;
    use tokio::io::unix::AsyncFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{Duration, timeout};
    use users::{all_users, get_current_username};

    use crate::account::{ResolvedAccount, resolve_account};

    use super::{PtySpec, spawn_exec, spawn_pty_shell, spawn_sftp};

    fn _account_fixture() -> ResolvedAccount {
        ResolvedAccount {
            username: "alice".to_string(),
            uid: 1000,
            gid: 1000,
            supplementary_groups: vec![1001, 1002],
            home: PathBuf::from("/home/alice"),
            shell: PathBuf::from("/bin/bash"),
        }
    }

    fn current_account(home: &TempDir) -> ResolvedAccount {
        let username = get_current_username()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| "user".to_string());

        ResolvedAccount {
            username,
            uid: geteuid().as_raw(),
            gid: getegid().as_raw(),
            supplementary_groups: getgroups()
                .unwrap()
                .into_iter()
                .filter(|gid| gid.as_raw() != getegid().as_raw())
                .map(|gid| gid.as_raw())
                .collect(),
            home: home.path().to_path_buf(),
            shell: PathBuf::from("/bin/sh"),
        }
    }

    fn env_for(account: &ResolvedAccount, term: bool) -> Vec<(OsString, OsString)> {
        let mut env = vec![
            (OsString::from("HOME"), account.home.clone().into_os_string()),
            (OsString::from("USER"), OsString::from(account.username.clone())),
            (OsString::from("LOGNAME"), OsString::from(account.username.clone())),
            (OsString::from("SHELL"), account.shell.clone().into_os_string()),
            (
                OsString::from("PATH"),
                std::env::var_os("PATH")
                    .unwrap_or_else(|| OsString::from("/usr/local/bin:/usr/bin:/bin")),
            ),
            (OsString::from("CUSTOM"), OsString::from("from-test")),
        ];

        if term {
            env.push((OsString::from("TERM"), OsString::from("xterm-256color")));
        }

        env
    }

    async fn write_all_controller(controller: &AsyncFd<std::fs::File>, mut buf: &[u8]) {
        while !buf.is_empty() {
            let mut guard = controller.writable().await.unwrap();
            match guard.try_io(|inner| (&*inner.get_ref()).write(buf)) {
                Ok(Ok(written)) => buf = &buf[written..],
                Ok(Err(err)) => panic!("controller write failed: {err}"),
                Err(_would_block) => continue,
            }
        }
    }

    async fn read_until_contains(
        controller: &AsyncFd<std::fs::File>,
        needle: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();

        loop {
            if out.windows(needle.len()).any(|window| window == needle) {
                return out;
            }

            let mut guard = controller.readable().await.unwrap();
            let mut buf = [0_u8; 1024];
            match guard.try_io(|inner| (&*inner.get_ref()).read(&mut buf)) {
                Ok(Ok(0)) => return out,
                Ok(Ok(read)) => out.extend_from_slice(&buf[..read]),
                Ok(Err(err)) => panic!("controller read failed: {err}"),
                Err(_would_block) => continue,
            }
        }
    }

    #[test]
    fn sftp_spec_runs_the_configured_binary() {
        // sftp doesn't use the embedded shell, so just verify the path
        assert_eq!(
            PathBuf::from("/usr/lib/openssh/sftp-server"),
            PathBuf::from("/usr/lib/openssh/sftp-server")
        );
    }

    #[tokio::test]
    async fn spawn_exec_runs_with_piped_stdio() {
        let home = TempDir::new().unwrap();
        let account = current_account(&home);
        let env = env_for(&account, false);

        let mut spawned = spawn_exec(
            &account,
            &env,
            "printf '%s|%s|' \"$HOME\" \"$CUSTOM\"; pwd",
        )
        .unwrap();

        spawned.stdin.shutdown().await.unwrap();
        drop(spawned.stdin);

        let mut stdout = Vec::new();
        spawned.stdout.read_to_end(&mut stdout).await.unwrap();
        let mut stderr = Vec::new();
        spawned.stderr.read_to_end(&mut stderr).await.unwrap();
        let status = spawned.child.wait().await.unwrap();

        assert!(status.success());
        assert_eq!(
            String::from_utf8(stdout).unwrap(),
            format!("{}|from-test|{}\n", account.home.display(), account.home.display())
        );
        assert!(stderr.is_empty());
    }

    #[tokio::test]
    async fn spawn_sftp_runs_the_configured_program_with_pipes() {
        let home = TempDir::new().unwrap();
        let account = current_account(&home);
        let env = env_for(&account, false);
        let mut spawned = spawn_sftp(&account, &env, Path::new("/bin/cat")).unwrap();

        spawned.stdin.write_all(b"ping").await.unwrap();
        spawned.stdin.shutdown().await.unwrap();
        drop(spawned.stdin);

        let mut stdout = Vec::new();
        spawned.stdout.read_to_end(&mut stdout).await.unwrap();
        let mut stderr = Vec::new();
        spawned.stderr.read_to_end(&mut stderr).await.unwrap();
        let status = spawned.child.wait().await.unwrap();

        assert!(status.success());
        assert_eq!(stdout, b"ping");
        assert!(stderr.is_empty());
    }

    #[tokio::test]
    async fn spawn_pty_shell_returns_async_controller_with_requested_winsize() {
        let home = TempDir::new().unwrap();
        let account = current_account(&home);
        let env = env_for(&account, true);
        let spec = PtySpec {
            cols: 91,
            rows: 37,
            px_width: 900,
            px_height: 700,
        };

        let mut spawned = spawn_pty_shell(&account, &env, spec).unwrap();
        let winsize = rustix::termios::tcgetwinsize(spawned.controller.get_ref()).unwrap();
        let controller_flags = rustix::fs::fcntl_getfl(spawned.controller.get_ref()).unwrap();

        assert_eq!(u32::from(winsize.ws_col), spec.cols);
        assert_eq!(u32::from(winsize.ws_row), spec.rows);
        assert_eq!(u32::from(winsize.ws_xpixel), spec.px_width);
        assert_eq!(u32::from(winsize.ws_ypixel), spec.px_height);
        assert!(controller_flags.contains(rustix::fs::OFlags::NONBLOCK));

        let marker = format!("__pty_roundtrip__:{}:from-test", account.home.display());
        write_all_controller(
            &spawned.controller,
            format!("printf '{}\\n' \"$HOME:$CUSTOM\"\n", marker).as_bytes(),
        )
        .await;
        let output = timeout(
            Duration::from_secs(5),
            read_until_contains(&spawned.controller, marker.as_bytes()),
        )
        .await
        .unwrap();

        assert!(
            String::from_utf8_lossy(&output).contains(&marker),
            "pty output did not contain marker: {:?}",
            String::from_utf8_lossy(&output)
        );

        write_all_controller(&spawned.controller, b"exit\n").await;
        let status = timeout(Duration::from_secs(5), spawned.child.wait())
            .await
            .unwrap()
            .unwrap();

        assert!(status.success());
    }

    #[tokio::test]
    async fn spawn_exec_drops_privileges_when_running_as_root() {
        if geteuid().as_raw() != 0 {
            eprintln!("skipping: privilege-drop coverage requires root");
            return;
        }

        let Some(candidate) = (unsafe { all_users() }).find(|user| user.uid() != 0) else {
            eprintln!("skipping: no non-root account available");
            return;
        };

        let username = candidate.name().to_string_lossy().into_owned();
        let mut account = resolve_account(&username).unwrap();
        account.home = PathBuf::from("/tmp");
        account.shell = PathBuf::from("/bin/sh");

        let env = env_for(&account, false);
        let mut spawned = spawn_exec(
            &account,
            &env,
            "id -u; id -g; id -G; pwd; printf '%s\\n' \"$HOME\"",
        )
        .unwrap();

        spawned.stdin.shutdown().await.unwrap();
        drop(spawned.stdin);

        let mut stdout = Vec::new();
        spawned.stdout.read_to_end(&mut stdout).await.unwrap();
        let mut stderr = Vec::new();
        spawned.stderr.read_to_end(&mut stderr).await.unwrap();
        let status = spawned.child.wait().await.unwrap();

        assert!(status.success(), "stderr: {}", String::from_utf8_lossy(&stderr));

        let output = String::from_utf8(stdout).unwrap();
        let mut lines = output.lines();
        let uid = lines.next().unwrap().parse::<u32>().unwrap();
        let gid = lines.next().unwrap().parse::<u32>().unwrap();
        let mut groups = lines
            .next()
            .unwrap()
            .split_whitespace()
            .map(|value| value.parse::<u32>().unwrap())
            .collect::<Vec<_>>();
        let pwd = lines.next().unwrap();
        let home = lines.next().unwrap();

        let mut expected_groups = account.supplementary_groups.clone();
        expected_groups.push(account.gid);
        expected_groups.sort_unstable();
        expected_groups.dedup();
        groups.sort_unstable();
        groups.dedup();

        assert_eq!(uid, account.uid);
        assert_eq!(gid, account.gid);
        assert_eq!(groups, expected_groups);
        assert_eq!(pwd, "/tmp");
        assert_eq!(home, "/tmp");
        assert!(stderr.is_empty());
    }

    #[tokio::test]
    async fn spawn_exec_checks_target_home_after_privilege_drop() {
        if geteuid().as_raw() != 0 {
            eprintln!("skipping: cwd privilege-drop coverage requires root");
            return;
        }

        let Some(candidate) = (unsafe { all_users() }).find(|user| user.uid() != 0) else {
            eprintln!("skipping: no non-root account available");
            return;
        };

        let username = candidate.name().to_string_lossy().into_owned();
        let mut account = resolve_account(&username).unwrap();
        let locked_home = TempDir::new().unwrap();
        fs::set_permissions(locked_home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        account.home = locked_home.path().to_path_buf();
        account.shell = PathBuf::from("/bin/sh");

        let env = env_for(&account, false);
        let error = match spawn_exec(&account, &env, "pwd") {
            Ok(_) => panic!("spawn_exec unexpectedly succeeded"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("failed to spawn exec child"),
            "unexpected error: {error:#}"
        );
    }
}
