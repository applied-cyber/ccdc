use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use russh::{MethodSet, SshId};
use russh::keys::{PrivateKey, PublicKey};

use crate::auth::advertised_methods;
use crate::cli::Cli;
use crate::identity::{
    allowed_public_key, load_present_host_keys,
};

pub const DEFAULT_PORT: u16 = 50000;
pub const DEFAULT_SERVER_ID: &str = "SSH-2.0-OpenSSH_10.2p1 Debian-5";
pub const DEFAULT_SFTP_SERVER: &str = "/usr/lib/openssh/sftp-server";
pub const DEFAULT_SESSION_LIMIT: usize = 32;

#[derive(Debug)]
pub struct RuntimeConfig {
    pub listen_addr: SocketAddr,
    pub server_id: SshId,
    pub host_keys: Vec<PrivateKey>,
    pub allowed_key: PublicKey,
    pub sftp_server: PathBuf,
    pub session_limit: usize,
    pub auth_methods: MethodSet,
}

impl RuntimeConfig {
    pub fn production(cli: &Cli) -> Result<Self> {
        Ok(production_config(
            SocketAddr::from(([0, 0, 0, 0], cli.port)),
            load_present_host_keys()?,
            allowed_public_key()?,
        ))
    }

    pub fn for_tests(
        listen_addr: SocketAddr,
        server_id: SshId,
        host_keys: Vec<PrivateKey>,
        allowed_key: PublicKey,
        sftp_server: PathBuf,
        session_limit: usize,
        auth_methods: MethodSet,
    ) -> Self {
        Self {
            listen_addr,
            server_id,
            host_keys,
            allowed_key,
            sftp_server,
            session_limit,
            auth_methods,
        }
    }
}

fn production_config(
    listen_addr: SocketAddr,
    host_keys: Vec<PrivateKey>,
    allowed_key: PublicKey,
) -> RuntimeConfig {
    RuntimeConfig {
        listen_addr,
        server_id: SshId::Standard(DEFAULT_SERVER_ID.into()),
        host_keys,
        allowed_key,
        sftp_server: PathBuf::from(DEFAULT_SFTP_SERVER),
        session_limit: DEFAULT_SESSION_LIMIT,
        auth_methods: advertised_methods(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::PathBuf;

    use russh::{MethodKind, SshId};
    use russh::keys::{PrivateKey, PublicKey};

    use super::{production_config, DEFAULT_SERVER_ID, DEFAULT_SFTP_SERVER, DEFAULT_SESSION_LIMIT};

    const ED25519_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM\n\
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg\n\
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf\n\
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==\n\
-----END OPENSSH PRIVATE KEY-----\n";

    #[test]
    fn production_defaults_are_applied_through_the_helper_path() {
        let host_key = PrivateKey::from_openssh(ED25519_PRIVATE_KEY).unwrap();
        let allowed_key = PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFCfol4TWngg47IUH3ECFjIzxdxq1+84Q7wmipyjnP1o user@applied-cyber",
        )
        .unwrap();

        let config = production_config(
            SocketAddr::from(([127, 0, 0, 1], 60000)),
            vec![host_key.clone()],
            allowed_key.clone(),
        );

        assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 60000)));
        assert!(matches!(
            config.server_id,
            SshId::Standard(ref id) if id.as_ref() == DEFAULT_SERVER_ID
        ));
        assert_eq!(config.host_keys, vec![host_key]);
        assert_eq!(config.allowed_key, allowed_key);
        assert_eq!(config.sftp_server, PathBuf::from(DEFAULT_SFTP_SERVER));
        assert_eq!(config.session_limit, DEFAULT_SESSION_LIMIT);
        assert_eq!(
            &*config.auth_methods,
            &[MethodKind::PublicKey, MethodKind::Password]
        );
    }
}
