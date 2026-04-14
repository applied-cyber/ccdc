use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use russh::keys::{load_secret_key, PrivateKey, PublicKey};
use std::io::ErrorKind;

pub const ALLOWED_PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFCfol4TWngg47IUH3ECFjIzxdxq1+84Q7wmipyjnP1o user@applied-cyber";

pub const DEFAULT_HOST_KEY_RSA_PATH: &str = "/etc/ssh/ssh_host_rsa_key";
pub const DEFAULT_HOST_KEY_ECDSA_PATH: &str = "/etc/ssh/ssh_host_ecdsa_key";
pub const DEFAULT_HOST_KEY_ED25519_PATH: &str = "/etc/ssh/ssh_host_ed25519_key";

pub fn allowed_public_key() -> Result<PublicKey> {
    Ok(PublicKey::from_openssh(ALLOWED_PUBLIC_KEY)?)
}

pub fn default_rsa_host_key_path() -> PathBuf {
    PathBuf::from(DEFAULT_HOST_KEY_RSA_PATH)
}

pub fn default_ecdsa_host_key_path() -> PathBuf {
    PathBuf::from(DEFAULT_HOST_KEY_ECDSA_PATH)
}

pub fn default_ed25519_host_key_path() -> PathBuf {
    PathBuf::from(DEFAULT_HOST_KEY_ED25519_PATH)
}

pub fn load_present_host_keys() -> Result<Vec<PrivateKey>> {
    load_present_host_keys_from_paths([
        default_rsa_host_key_path(),
        default_ecdsa_host_key_path(),
        default_ed25519_host_key_path(),
    ])
}

pub fn load_present_host_keys_from_paths<P, I>(paths: I) -> Result<Vec<PrivateKey>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut host_keys = Vec::new();

    for path in paths {
        match load_secret_key(path.as_ref(), None) {
            Ok(key) => host_keys.push(key),
            Err(russh::keys::Error::IO(err)) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }

    if host_keys.is_empty() {
        bail!("no host keys found");
    }

    Ok(host_keys)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::PathBuf;

    use russh::keys::{Algorithm, PrivateKey, PublicKey};
    use tempfile::NamedTempFile;

    use super::{
        allowed_public_key, default_ecdsa_host_key_path, default_ed25519_host_key_path,
        default_rsa_host_key_path, load_present_host_keys_from_paths, ALLOWED_PUBLIC_KEY,
        DEFAULT_HOST_KEY_ECDSA_PATH, DEFAULT_HOST_KEY_ED25519_PATH, DEFAULT_HOST_KEY_RSA_PATH,
    };

    const ED25519_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM\n\
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg\n\
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf\n\
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==\n\
-----END OPENSSH PRIVATE KEY-----\n";

    #[test]
    fn parses_the_fixed_allowed_public_key() {
        let key = allowed_public_key().unwrap();

        assert_eq!(key, PublicKey::from_openssh(ALLOWED_PUBLIC_KEY).unwrap());
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
        assert_eq!(key.comment(), "user@applied-cyber");
    }

    #[test]
    fn exposes_the_default_host_key_paths() {
        assert_eq!(
            default_rsa_host_key_path(),
            PathBuf::from(DEFAULT_HOST_KEY_RSA_PATH)
        );
        assert_eq!(
            default_ecdsa_host_key_path(),
            PathBuf::from(DEFAULT_HOST_KEY_ECDSA_PATH)
        );
        assert_eq!(
            default_ed25519_host_key_path(),
            PathBuf::from(DEFAULT_HOST_KEY_ED25519_PATH)
        );
    }

    #[test]
    fn loads_present_host_keys_from_existing_paths() {
        let mut first = NamedTempFile::new().unwrap();
        let mut second = NamedTempFile::new().unwrap();
        let missing = PathBuf::from("/definitely/missing/host-key");

        first.write_all(ED25519_PRIVATE_KEY.as_bytes()).unwrap();
        second.write_all(ED25519_PRIVATE_KEY.as_bytes()).unwrap();

        let keys: Vec<PrivateKey> = load_present_host_keys_from_paths([
            first.path(),
            missing.as_path(),
            second.path(),
        ])
        .unwrap();

        assert_eq!(keys.len(), 2);
        for key in &keys {
            assert_eq!(key.algorithm(), Algorithm::Ed25519);
        }
    }

    #[test]
    fn errors_when_no_host_keys_are_present() {
        let result = load_present_host_keys_from_paths([
            PathBuf::from("/definitely/missing/one"),
            PathBuf::from("/definitely/missing/two"),
            PathBuf::from("/definitely/missing/three"),
        ]);

        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn returns_the_real_error_for_an_inaccessible_host_key_path() {
        use std::os::unix::fs::PermissionsExt;

        struct RestorePermissions {
            path: PathBuf,
            mode: u32,
        }

        impl Drop for RestorePermissions {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(
                    &self.path,
                    std::fs::Permissions::from_mode(self.mode),
                );
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("host_key");
        std::fs::write(&key_path, ED25519_PRIVATE_KEY).unwrap();

        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o000)).unwrap();
        let _restore = RestorePermissions {
            path: dir.path().to_path_buf(),
            mode,
        };

        let result = load_present_host_keys_from_paths([key_path.as_path()]);

        let err = result.unwrap_err();
        assert_ne!(err.to_string(), "no host keys found");
    }
}
