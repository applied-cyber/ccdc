use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use russh::server::Server as _;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::config::RuntimeConfig;
use crate::session::SessionHandler;

#[derive(Clone)]
struct DaemonServer {
    runtime: Arc<RuntimeConfig>,
    session_limiter: Arc<Semaphore>,
}

impl DaemonServer {
    fn new(runtime: Arc<RuntimeConfig>) -> Self {
        let session_limit = runtime.session_limit;
        Self {
            runtime,
            session_limiter: Arc::new(Semaphore::new(session_limit)),
        }
    }
}

impl russh::server::Server for DaemonServer {
    type Handler = SessionHandler;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        SessionHandler::new(self.runtime.clone(), self.session_limiter.clone())
    }

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        log::debug!("ssh session error: {error:#}");
    }
}

fn server_config(runtime: &RuntimeConfig) -> russh::server::Config {
    let server_id = match &runtime.server_id {
        russh::SshId::Standard(id) => russh::SshId::Standard(id.clone()),
        russh::SshId::Raw(id) => russh::SshId::Raw(id.clone()),
    };

    russh::server::Config {
        server_id,
        methods: runtime.auth_methods.clone(),
        auth_rejection_time: Duration::from_millis(450),
        auth_rejection_time_initial: Some(Duration::from_millis(150)),
        keys: runtime.host_keys.clone(),
        inactivity_timeout: Some(Duration::from_secs(600)),
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    }
}

pub async fn run(runtime: RuntimeConfig) -> Result<()> {
    let listener = TcpListener::bind(runtime.listen_addr)
        .await
        .context("failed to bind ssh listener")?;
    run_on_listener(listener, runtime).await
}

pub async fn run_on_listener(listener: TcpListener, runtime: RuntimeConfig) -> Result<()> {
    log::info!("listening on {}", listener.local_addr()?);

    let mut server = DaemonServer::new(Arc::new(runtime));
    let config = Arc::new(server_config(server.runtime.as_ref()));

    server
        .run_on_socket(config, &listener)
        .await
        .context("ssh server failed")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::PathBuf;

    use russh::keys::{Algorithm, PrivateKey};
    use russh::MethodKind;
    use russh::SshId;

    use crate::auth::advertised_methods;
    use crate::config::{
        RuntimeConfig, DEFAULT_SERVER_ID, DEFAULT_SESSION_LIMIT, DEFAULT_SFTP_SERVER,
    };

    use super::server_config;

    #[test]
    fn server_config_uses_the_task_timings() {
        let runtime = RuntimeConfig::for_tests(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            SshId::Standard(DEFAULT_SERVER_ID.into()),
            vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()],
            PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
            PathBuf::from(DEFAULT_SFTP_SERVER),
            DEFAULT_SESSION_LIMIT,
            advertised_methods(),
        );

        let config = server_config(&runtime);

        assert_eq!(
            config.auth_rejection_time,
            std::time::Duration::from_millis(450)
        );
        assert_eq!(
            config.auth_rejection_time_initial,
            Some(std::time::Duration::from_millis(150))
        );
        assert_eq!(
            config.keepalive_interval,
            Some(std::time::Duration::from_secs(30))
        );
        assert_eq!(
            &*config.methods,
            &[MethodKind::PublicKey, MethodKind::Password]
        );
    }
}
