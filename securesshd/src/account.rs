use std::convert::TryFrom;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use users::get_user_by_name;

#[cfg(unix)]
use users::os::unix::UserExt;

const SESSION_PATH: &str = "/root/.local/bin:/usr/local/bin:/usr/bin:/bin";
const SESSION_TERM: &str = "xterm-256color";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAccount {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub supplementary_groups: Vec<u32>,
    pub home: PathBuf,
    pub shell: PathBuf,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RequestedEnv {
    entries: Vec<(OsString, OsString)>,
}

pub fn resolve_account(username: &str) -> Result<ResolvedAccount> {
    let user = get_user_by_name(username).ok_or_else(|| anyhow!("unknown user: {username}"))?;

    let uid = u32::try_from(user.uid())
        .map_err(|_| anyhow!("user id out of range for {username}"))?;
    let gid = u32::try_from(user.primary_group_id())
        .map_err(|_| anyhow!("group id out of range for {username}"))?;

    let supplementary_groups = user
        .groups()
        .ok_or_else(|| anyhow!("could not resolve supplementary groups for {username}"))?
        .into_iter()
        .filter(|group| group.gid() != user.primary_group_id())
        .map(|group| {
            u32::try_from(group.gid())
                .map_err(|_| anyhow!("supplementary group id out of range for {username}"))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ResolvedAccount {
        username: user.name().to_string_lossy().into_owned(),
        uid,
        gid,
        supplementary_groups,
        home: user.home_dir().to_path_buf(),
        shell: user.shell().to_path_buf(),
    })
}

pub fn record_requested_env(requested: &mut RequestedEnv, name: &str, value: &str) -> bool {
    let allowed = is_allowed_requested_env_name(name) && is_allowed_requested_env_value(value);

    if allowed {
        upsert_requested_env(requested, name, value);
    }

    allowed
}

pub fn build_session_env(
    account: &ResolvedAccount,
    requested: &RequestedEnv,
    with_pty: bool,
) -> Vec<(OsString, OsString)> {
    let mut env = vec![
        (OsString::from("HOME"), account.home.clone().into_os_string()),
        (OsString::from("USER"), OsString::from(account.username.clone())),
        (OsString::from("LOGNAME"), OsString::from(account.username.clone())),
        (OsString::from("SHELL"), account.shell.clone().into_os_string()),
        (OsString::from("PATH"), OsString::from(SESSION_PATH)),
    ];

    if with_pty {
        env.push((OsString::from("TERM"), OsString::from(SESSION_TERM)));
    }

    env.extend(requested.entries.iter().cloned());
    env
}

fn is_allowed_requested_env_name(name: &str) -> bool {
    if name.contains('=') || name.contains('\0') {
        return false;
    }

    matches!(name, "LANG" | "COLORTERM" | "NO_COLOR") || is_valid_locale_env_name(name)
}

fn is_valid_locale_env_name(name: &str) -> bool {
    let suffix = name.strip_prefix("LC_").unwrap_or_default();

    !suffix.is_empty()
        && suffix
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn is_allowed_requested_env_value(value: &str) -> bool {
    !value.contains('\0')
}

fn upsert_requested_env(requested: &mut RequestedEnv, name: &str, value: &str) {
    let name = OsStr::new(name);
    if let Some((_, existing_value)) = requested
        .entries
        .iter_mut()
        .find(|(existing_name, _)| existing_name == name)
    {
        *existing_value = OsString::from(value);
    } else {
        requested
            .entries
            .push((OsString::from(name), OsString::from(value)));
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::path::PathBuf;

    use users::os::unix::UserExt;
    use users::{get_current_username, get_user_by_name};

    use super::{
        build_session_env, record_requested_env, resolve_account, RequestedEnv, ResolvedAccount,
    };

    fn sample_account() -> ResolvedAccount {
        ResolvedAccount {
            username: "alice".to_string(),
            uid: 1000,
            gid: 1000,
            supplementary_groups: vec![1001, 1002],
            home: PathBuf::from("/home/alice"),
            shell: PathBuf::from("/bin/zsh"),
        }
    }

    fn env_value<'a>(env: &'a [(OsString, OsString)], key: &str) -> Option<&'a OsStr> {
        env.iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_os_str())
    }

    #[test]
    fn record_requested_env_accepts_only_the_whitelist() {
        let mut requested = RequestedEnv::default();

        assert!(record_requested_env(&mut requested, "LANG", "en_US.UTF-8"));
        assert!(record_requested_env(&mut requested, "COLORTERM", "truecolor"));
        assert!(record_requested_env(&mut requested, "NO_COLOR", "1"));
        assert!(record_requested_env(&mut requested, "LC_ALL", "C"));
        assert!(!record_requested_env(&mut requested, "PATH", "/tmp/bin"));
    }

    #[test]
    fn record_requested_env_rejects_malformed_locale_names() {
        let mut requested = RequestedEnv::default();

        assert!(!record_requested_env(&mut requested, "LC_", "C"));
        assert!(!record_requested_env(&mut requested, "LC_TIME=C", "C"));
        assert!(!record_requested_env(&mut requested, "LC_TIME\0BAD", "C"));
        assert!(!record_requested_env(&mut requested, "LC-time", "C"));
    }

    #[test]
    fn record_requested_env_rejects_nul_containing_values() {
        let mut requested = RequestedEnv::default();

        assert!(!record_requested_env(&mut requested, "LANG", "en_US.UTF-8\0bad"));
    }

    #[test]
    fn repeated_requests_overwrite_existing_values() {
        let account = sample_account();
        let mut requested = RequestedEnv::default();

        assert!(record_requested_env(&mut requested, "LANG", "en_US.UTF-8"));
        assert!(record_requested_env(&mut requested, "LANG", "C"));

        let env = build_session_env(&account, &requested, false);
        let values: Vec<_> = env
            .iter()
            .filter(|(name, _)| name == "LANG")
            .map(|(_, value)| value.as_os_str())
            .collect();

        assert_eq!(values, vec![OsStr::new("C")]);
    }

    #[test]
    fn build_session_env_includes_base_and_requested_values() {
        let account = sample_account();
        let mut requested = RequestedEnv::default();

        assert!(record_requested_env(&mut requested, "LANG", "en_US.UTF-8"));
        assert!(record_requested_env(&mut requested, "LC_TIME", "C"));
        assert!(!record_requested_env(&mut requested, "EDITOR", "vim"));

        let env = build_session_env(&account, &requested, true);

        assert_eq!(env_value(&env, "HOME"), Some(OsStr::new("/home/alice")));
        assert_eq!(env_value(&env, "USER"), Some(OsStr::new("alice")));
        assert_eq!(env_value(&env, "LOGNAME"), Some(OsStr::new("alice")));
        assert_eq!(env_value(&env, "SHELL"), Some(OsStr::new("/bin/zsh")));
        assert_eq!(
            env_value(&env, "PATH"),
            Some(OsStr::new("/root/.local/bin:/usr/local/bin:/usr/bin:/bin"))
        );
        assert_eq!(env_value(&env, "TERM"), Some(OsStr::new("xterm-256color")));
        assert_eq!(env_value(&env, "LANG"), Some(OsStr::new("en_US.UTF-8")));
        assert_eq!(env_value(&env, "LC_TIME"), Some(OsStr::new("C")));
        assert_eq!(env_value(&env, "EDITOR"), None);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_account_uses_the_system_user_database() {
        let Some(username) = get_current_username() else {
            eprintln!("skipping: current username unavailable");
            return;
        };
        let username = username.to_string_lossy().into_owned();
        let Some(user) = get_user_by_name(&username) else {
            eprintln!("skipping: current user record unavailable");
            return;
        };

        let resolved = resolve_account(&username).unwrap();

        assert_eq!(resolved.username, username);
        assert_eq!(resolved.uid, user.uid());
        assert_eq!(resolved.gid, user.primary_group_id());
        assert_eq!(resolved.home, user.home_dir());
        assert_eq!(resolved.shell, user.shell());

        let Some(user_groups) = user.groups() else {
            eprintln!("skipping: current user groups unavailable");
            return;
        };

        let mut expected_groups: Vec<u32> = user_groups
            .into_iter()
            .map(|group| group.gid())
            .filter(|gid| *gid != user.primary_group_id())
            .collect();
        expected_groups.sort_unstable();

        let mut actual_groups = resolved.supplementary_groups.clone();
        actual_groups.sort_unstable();

        assert_eq!(actual_groups, expected_groups);
    }

    #[test]
    fn resolve_account_errors_for_unknown_users() {
        assert!(resolve_account("__securesshd_missing_user__").is_err());
    }
}
