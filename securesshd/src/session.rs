use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::File as StdFile;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use russh::server::{Auth, Handler, Session};
use russh::{Channel, ChannelId};
use rustix::process::{getegid, geteuid, getgroups};
use rustix::termios::{Winsize, tcsetwinsize};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;
use tokio::sync::oneshot;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::sleep;

use crate::account::{RequestedEnv, build_session_env, record_requested_env, resolve_account};
use crate::auth::{random_password_delay_ms, reject_with_advertised_methods};
use crate::child::{PtySpec, SpawnedExec, spawn_exec, spawn_pty_shell, spawn_sftp};
use crate::config::RuntimeConfig;

pub(crate) struct SessionHandler {
    runtime: Arc<RuntimeConfig>,
    session_limiter: Arc<Semaphore>,
    authenticated_username: Option<String>,
    session_permit: Option<Arc<OwnedSemaphorePermit>>,
    pending_channels: HashMap<ChannelId, PendingChannel>,
    active_ptys: HashMap<ChannelId, StdFile>,
    active_sessions: HashMap<ChannelId, ActiveSession>,
}

struct PendingChannel {
    channel: Option<Channel<russh::server::Msg>>,
    requested_env: RequestedEnv,
    pty_spec: Option<PtySpec>,
}

struct ActiveSession {
    shutdown: Option<oneshot::Sender<()>>,
}

impl SessionHandler {
    pub(crate) fn new(runtime: Arc<RuntimeConfig>, session_limiter: Arc<Semaphore>) -> Self {
        Self {
            runtime,
            session_limiter,
            authenticated_username: None,
            session_permit: None,
            pending_channels: HashMap::new(),
            active_ptys: HashMap::new(),
            active_sessions: HashMap::new(),
        }
    }

    fn current_username(&self) -> Option<&str> {
        self.authenticated_username.as_deref()
    }

    fn take_pending_channel(&mut self, channel: ChannelId) -> Option<PendingChannel> {
        self.pending_channels.remove(&channel)
    }

    fn restore_pending_channel(&mut self, channel: ChannelId, pending: PendingChannel) {
        self.pending_channels.insert(channel, pending);
    }

    fn pty_spec_from_request(cols: u32, rows: u32, px_width: u32, px_height: u32) -> PtySpec {
        PtySpec {
            cols,
            rows,
            px_width,
            px_height,
        }
    }

    fn resize_pty(controller: &StdFile, spec: PtySpec) -> Result<()> {
        let winsize = Winsize {
            ws_col: u16::try_from(spec.cols).context("pty cols exceed u16")?,
            ws_row: u16::try_from(spec.rows).context("pty rows exceed u16")?,
            ws_xpixel: u16::try_from(spec.px_width).context("pty pixel width exceeds u16")?,
            ws_ypixel: u16::try_from(spec.px_height).context("pty pixel height exceeds u16")?,
        };

        tcsetwinsize(controller, winsize).context("failed to resize pty")?;
        Ok(())
    }

    fn resolved_account_for_session(&self) -> Result<crate::account::ResolvedAccount> {
        let requested_username = self
            .current_username()
            .ok_or_else(|| anyhow::anyhow!("session is not authenticated"))?;
        let mut account = resolve_account(requested_username)?;
        account.username = requested_username.to_owned();

        if should_override_current_supplementary_groups(account.uid, account.gid) {
            account.supplementary_groups = getgroups()
                .context("failed to read current supplementary groups")?
                .into_iter()
                .map(|gid| gid.as_raw())
                .filter(|gid| *gid != account.gid)
                .collect();
        }

        Ok(account)
    }

    fn channel_state_mut(&mut self, channel: ChannelId) -> Option<&mut PendingChannel> {
        self.pending_channels.get_mut(&channel)
    }

    fn register_active_session(&mut self, channel: ChannelId, shutdown: oneshot::Sender<()>) {
        self.active_sessions.insert(
            channel,
            ActiveSession {
                shutdown: Some(shutdown),
            },
        );
    }

    fn shutdown_active_session(&mut self, channel: ChannelId) {
        if let Some(mut active) = self.active_sessions.remove(&channel) {
            if let Some(shutdown) = active.shutdown.take() {
                let _ = shutdown.send(());
            }
        }
    }

    fn shutdown_all_active_sessions(&mut self) {
        for (_, mut active) in self.active_sessions.drain() {
            if let Some(shutdown) = active.shutdown.take() {
                let _ = shutdown.send(());
            }
        }
    }
}

impl Drop for SessionHandler {
    fn drop(&mut self) {
        self.shutdown_all_active_sessions();
    }
}

impl Handler for SessionHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(reject_with_advertised_methods())
    }

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        sleep(Duration::from_millis(random_password_delay_ms())).await;
        Ok(reject_with_advertised_methods())
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        if public_key.key_data() == self.runtime.allowed_key.key_data() {
            Ok(Auth::Accept)
        } else {
            Ok(reject_with_advertised_methods())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        if public_key.key_data() != self.runtime.allowed_key.key_data() {
            return Ok(reject_with_advertised_methods());
        }

        let permit = match self.session_limiter.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return Ok(reject_with_advertised_methods()),
        };

        self.authenticated_username = Some(user.to_owned());
        self.session_permit = Some(Arc::new(permit));
        Ok(Auth::Accept)
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<russh::server::Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.pending_channels.insert(
            channel.id(),
            PendingChannel {
                channel: Some(channel),
                requested_env: RequestedEnv::default(),
                pty_spec: None,
            },
        );
        Ok(true)
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pending_channels.remove(&channel);
        self.active_ptys.remove(&channel);
        self.shutdown_active_session(channel);
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let accepted = if let Some(state) = self.channel_state_mut(channel) {
            record_requested_env(&mut state.requested_env, variable_name, variable_value)
        } else {
            false
        };

        if accepted {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }

        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channel_state_mut(channel) {
            state.pty_spec = Some(Self::pty_spec_from_request(
                col_width, row_height, pix_width, pix_height,
            ));
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }

        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let spec = Self::pty_spec_from_request(col_width, row_height, pix_width, pix_height);

        if let Some(controller) = self.active_ptys.get(&channel) {
            if let Err(err) = Self::resize_pty(controller, spec) {
                log::debug!("pty resize failed for {channel:?}: {err:#}");
                session.channel_failure(channel)?;
            } else {
                session.channel_success(channel)?;
            }
            return Ok(());
        }

        if let Some(state) = self.channel_state_mut(channel) {
            state.pty_spec = Some(spec);
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }

        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(username) = self.current_username().map(ToOwned::to_owned) else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let Some(mut pending) = self.take_pending_channel(channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let Some(pty_spec) = pending.pty_spec else {
            self.restore_pending_channel(channel, pending);
            session.channel_failure(channel)?;
            return Ok(());
        };

        let account = match self.resolved_account_for_session() {
            Ok(account) => account,
            Err(err) => {
                log::debug!("failed to resolve account {username:?}: {err:#}");
                self.restore_pending_channel(channel, pending);
                session.channel_failure(channel)?;
                return Ok(());
            }
        };

        let env = build_session_env(&account, &pending.requested_env, true);
        let spawned = match spawn_pty_shell(&account, &env, pty_spec) {
            Ok(spawned) => spawned,
            Err(err) => {
                log::debug!("failed to spawn pty shell for {username:?}: {err:#}");
                self.restore_pending_channel(channel, pending);
                session.channel_failure(channel)?;
                return Ok(());
            }
        };

        let Some(channel_obj) = pending.channel.take() else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        self.register_active_session(channel, shutdown_tx);
        let permit = self.session_permit.clone();
        let controller_clone = AsyncFd::new(
            spawned
                .controller
                .get_ref()
                .try_clone()
                .context("failed to clone pty controller")?,
        )
        .context("failed to wrap pty controller clone")?;
        let controller_for_resize = spawned.controller.into_inner();

        self.active_ptys.insert(channel, controller_for_resize);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) =
                serve_pty_session(channel_obj, spawned.child, controller_clone, shutdown_rx).await
            {
                log::debug!("pty session for {username:?} ended with error: {err:#}");
            }
        });

        let _ = session.channel_success(channel);

        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(username) = self.current_username().map(ToOwned::to_owned) else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let Some(mut pending) = self.take_pending_channel(channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let account = match self.resolved_account_for_session() {
            Ok(account) => account,
            Err(err) => {
                log::debug!("failed to resolve account {username:?}: {err:#}");
                self.restore_pending_channel(channel, pending);
                session.channel_failure(channel)?;
                return Ok(());
            }
        };

        let env = build_session_env(&account, &pending.requested_env, false);
        let command = String::from_utf8_lossy(data).into_owned();
        log::debug!("starting exec session for {username:?}: {command:?}");
        let spawned = match spawn_exec(&account, &env, &command) {
            Ok(spawned) => spawned,
            Err(err) => {
                log::debug!("failed to spawn exec for {username:?}: {err:#}");
                self.restore_pending_channel(channel, pending);
                session.channel_failure(channel)?;
                return Ok(());
            }
        };

        let Some(channel_obj) = pending.channel.take() else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        self.register_active_session(channel, shutdown_tx);
        let permit = self.session_permit.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = serve_exec_session(channel_obj, spawned, shutdown_rx).await {
                log::debug!("exec session for {username:?} ended with error: {err:#}");
            }
        });

        let _ = session.channel_success(channel);

        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            session.channel_failure(channel)?;
            return Ok(());
        }

        let Some(username) = self.current_username().map(ToOwned::to_owned) else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let Some(mut pending) = self.take_pending_channel(channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let account = match self.resolved_account_for_session() {
            Ok(account) => account,
            Err(err) => {
                log::debug!("failed to resolve account {username:?}: {err:#}");
                self.restore_pending_channel(channel, pending);
                session.channel_failure(channel)?;
                return Ok(());
            }
        };

        let env = build_session_env(&account, &pending.requested_env, false);
        let spawned = match spawn_sftp(&account, &env, self.runtime.sftp_server.as_path()) {
            Ok(spawned) => spawned,
            Err(err) => {
                log::debug!("failed to spawn sftp for {username:?}: {err:#}");
                self.restore_pending_channel(channel, pending);
                session.channel_failure(channel)?;
                return Ok(());
            }
        };

        let Some(channel_obj) = pending.channel.take() else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        self.register_active_session(channel, shutdown_tx);
        let permit = self.session_permit.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = serve_sftp_session(channel_obj, spawned, shutdown_rx).await {
                log::debug!("sftp session for {username:?} ended with error: {err:#}");
            }
        });

        let _ = session.channel_success(channel);
        Ok(())
    }
}

async fn serve_exec_session(
    channel: Channel<russh::server::Msg>,
    spawned: SpawnedExec,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let (mut read_half, write_half) = channel.split();
    let mut stdout_writer = write_half.make_writer();
    let mut stderr_writer = write_half.make_writer_ext(Some(1));
    let SpawnedExec {
        mut child,
        mut stdin,
        mut stdout,
        mut stderr,
    } = spawned;

    let stdin_task = tokio::spawn(async move {
        let mut channel_reader = read_half.make_reader();
        let result = tokio::io::copy(&mut channel_reader, &mut stdin).await;
        let _ = stdin.shutdown().await;
        if let Err(err) = result {
            log::debug!("stdin bridge ended with error: {err:#}");
        } else {
            log::debug!("stdin bridge reached EOF");
        }
    });

    let stdout_task = tokio::spawn(async move {
        tokio::io::copy(&mut stdout, &mut stdout_writer)
            .await
            .context("failed while forwarding stdout")
    });

    let stderr_task = tokio::spawn(async move {
        tokio::io::copy(&mut stderr, &mut stderr_writer)
            .await
            .context("failed while forwarding stderr")
    });

    let status = wait_for_child_exit(&mut child, &mut shutdown).await?;
    stdout_task
        .await
        .context("stdout bridge task panicked or was cancelled")??;
    stderr_task
        .await
        .context("stderr bridge task panicked or was cancelled")??;

    let code = status.code().unwrap_or(255) as u32;
    let _ = write_half.exit_status(code).await;

    let _ = write_half.eof().await;
    let _ = write_half.close().await;
    stdin_task.abort();
    let _ = stdin_task.await;
    log::debug!("exec session closed");
    Ok(())
}

async fn serve_sftp_session(
    channel: Channel<russh::server::Msg>,
    spawned: SpawnedExec,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let (mut read_half, write_half) = channel.split();
    let mut channel_writer = write_half.make_writer();
    let SpawnedExec {
        mut child,
        mut stdin,
        mut stdout,
        mut stderr,
    } = spawned;

    let stdin_task = tokio::spawn(async move {
        let mut channel_reader = read_half.make_reader();
        let result = tokio::io::copy(&mut channel_reader, &mut stdin).await;
        let _ = stdin.shutdown().await;
        if let Err(err) = result {
            log::debug!("sftp stdin bridge ended with error: {err:#}");
        } else {
            log::debug!("sftp stdin bridge reached EOF");
        }
    });

    let stdout_task = tokio::spawn(async move {
        tokio::io::copy(&mut stdout, &mut channel_writer)
            .await
            .context("failed while forwarding sftp stdout")?;
        let _ = channel_writer.shutdown().await;
        Result::<()>::Ok(())
    });

    let stderr_task = tokio::spawn(async move {
        let mut sink = tokio::io::sink();
        tokio::io::copy(&mut stderr, &mut sink)
            .await
            .context("failed while draining sftp stderr")?;
        Result::<()>::Ok(())
    });

    let _status = wait_for_child_exit(&mut child, &mut shutdown).await?;
    let stdout_result = stdout_task
        .await
        .context("sftp stdout bridge task panicked or was cancelled")?;
    let stderr_result = stderr_task
        .await
        .context("sftp stderr bridge task panicked or was cancelled")?;

    stdout_result?;
    stderr_result?;

    let _ = write_half.close().await;
    stdin_task.abort();
    let _ = stdin_task.await;
    log::debug!("sftp session closed");
    Ok(())
}

async fn serve_pty_session(
    channel: Channel<russh::server::Msg>,
    mut child: Child,
    controller: AsyncFd<StdFile>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let (mut read_half, write_half) = channel.split();
    let mut channel_writer = write_half.make_writer();
    let controller_for_input = AsyncFd::new(
        controller
            .get_ref()
            .try_clone()
            .context("failed to clone pty controller for input bridge")?,
    )
    .context("failed to wrap cloned pty controller for input bridge")?;

    let channel_to_pty = tokio::spawn(async move {
        let mut channel_reader = read_half.make_reader();
        if let Err(err) = copy_channel_to_pty(&mut channel_reader, &controller_for_input).await {
            log::debug!("pty input bridge ended with error: {err:#}");
        } else {
            log::debug!("pty input bridge reached EOF");
        }
    });
    let pty_to_channel =
        tokio::spawn(async move { copy_pty_to_channel(&controller, &mut channel_writer).await });
    let status = wait_for_child_exit(&mut child, &mut shutdown).await?;

    pty_to_channel
        .await
        .context("pty output bridge task panicked or was cancelled")??;

    let code = status.code().unwrap_or(255) as u32;
    let _ = write_half.exit_status(code).await;

    let _ = write_half.close().await;
    channel_to_pty.abort();
    let _ = channel_to_pty.await;
    log::debug!("pty session closed");
    Ok(())
}

async fn wait_for_child_exit(
    child: &mut Child,
    shutdown: &mut oneshot::Receiver<()>,
) -> Result<std::process::ExitStatus> {
    let mut shutdown_requested = false;

    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to poll child exit status")?
        {
            return Ok(status);
        }

        if !shutdown_requested {
            tokio::select! {
                _ = &mut *shutdown => {
                    let _ = child.start_kill();
                    shutdown_requested = true;
                }
                _ = sleep(Duration::from_millis(10)) => {}
            }
        } else {
            sleep(Duration::from_millis(10)).await;
        }
    }
}

fn should_override_current_supplementary_groups(account_uid: u32, account_gid: u32) -> bool {
    account_uid != 0 && account_uid == geteuid().as_raw() && account_gid == getegid().as_raw()
}

async fn copy_channel_to_pty(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    controller: &AsyncFd<StdFile>,
) -> Result<()> {
    let mut buf = [0_u8; 8192];

    loop {
        let count = reader
            .read(&mut buf)
            .await
            .context("failed to read from ssh channel")?;
        if count == 0 {
            return Ok(());
        }

        let mut written = 0;
        while written < count {
            let mut guard = controller
                .writable()
                .await
                .context("failed waiting for pty writability")?;
            match guard.try_io(|inner| inner.get_ref().write(&buf[written..count])) {
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(n)) => written += n,
                Ok(Err(err)) => return Err(err).context("failed to write to pty"),
                Err(_would_block) => continue,
            }
        }
    }
}

async fn copy_pty_to_channel(
    controller: &AsyncFd<StdFile>,
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<()> {
    let mut buf = [0_u8; 8192];

    loop {
        let mut guard = controller
            .readable()
            .await
            .context("failed waiting for pty readability")?;
        match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(count)) => {
                writer
                    .write_all(&buf[..count])
                    .await
                    .context("failed to write pty output to ssh channel")?;
            }
            Ok(Err(err)) if err.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) => {
                return Ok(());
            }
            Ok(Err(err)) => return Err(err).context("failed to read from pty"),
            Err(_would_block) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use russh::keys::{Algorithm, PrivateKey};
    use russh::server::{Auth, Handler};
    use rustix::process::{getegid, geteuid};
    use tokio::sync::Semaphore;

    use crate::auth::advertised_methods;
    use crate::config::{
        DEFAULT_SERVER_ID, DEFAULT_SESSION_LIMIT, DEFAULT_SFTP_SERVER, RuntimeConfig,
    };

    use super::SessionHandler;

    #[test]
    fn supplementary_group_override_is_disabled_for_root() {
        assert!(!super::should_override_current_supplementary_groups(0, 0));

        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        if uid != 0 {
            assert_eq!(
                super::should_override_current_supplementary_groups(uid, gid),
                true
            );
        }
    }

    #[tokio::test]
    async fn auth_publickey_rejects_a_non_allowed_key_even_with_permit_available() {
        let runtime = Arc::new(RuntimeConfig::for_tests(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            russh::SshId::Standard(DEFAULT_SERVER_ID.into()),
            vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()],
            PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
            DEFAULT_SFTP_SERVER.into(),
            DEFAULT_SESSION_LIMIT,
            advertised_methods(),
        ));
        let mut handler = SessionHandler::new(runtime, Arc::new(Semaphore::new(1)));
        let signed_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone();

        match handler
            .auth_publickey("someuser", &signed_key)
            .await
            .unwrap()
        {
            Auth::Reject { .. } => {}
            other => panic!("unexpected auth result: {other:?}"),
        }
    }
}
