use rand::random_range;
use russh::{server::Auth, MethodKind, MethodSet};

pub fn advertised_methods() -> MethodSet {
    MethodSet::from(&[MethodKind::PublicKey, MethodKind::Password][..])
}

pub fn reject_with_advertised_methods() -> Auth {
    Auth::Reject {
        proceed_with_methods: Some(advertised_methods()),
        partial_success: false,
    }
}

pub fn random_password_delay_ms() -> u64 {
    random_range(500..=750)
}

#[cfg(test)]
mod tests {
    use russh::server::Auth;
    use russh::{MethodKind, MethodSet};

    use super::{advertised_methods, random_password_delay_ms, reject_with_advertised_methods};

    #[test]
    fn advertises_publickey_and_password_only() {
        let methods = advertised_methods();

        assert_eq!(&*methods, &[MethodKind::PublicKey, MethodKind::Password]);
    }

    #[test]
    fn rejects_with_the_advertised_methods() {
        match reject_with_advertised_methods() {
            Auth::Reject {
                proceed_with_methods,
                partial_success,
            } => {
                assert_eq!(
                    proceed_with_methods,
                    Some(MethodSet::from(
                        &[MethodKind::PublicKey, MethodKind::Password][..]
                    ))
                );
                assert!(!partial_success);
            }
            other => panic!("unexpected auth response: {other:?}"),
        }
    }

    #[test]
    fn random_password_delay_is_within_bounds() {
        for _ in 0..128 {
            let delay_ms = random_password_delay_ms();
            assert!((500..=750).contains(&delay_ms), "{delay_ms}");
        }
    }
}
