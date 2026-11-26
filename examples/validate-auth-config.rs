const DEV_EXTENSION_ID: &str = "lfmldljfbheedcddndbnfckfkhjmkekp";

/// Key IDs follow `<channel>-<purpose>-<YYYYMMDD>`, e.g. `prod-preflight-20270101`.
/// Production rings must contain only `prod-` keys (current + optional next per purpose)
/// and never the Dev extension identity; Internal Dev rings must contain only `dev-` keys.
fn validate(config: &str, ids: &str, internal_dev: bool) -> Result<(), &'static str> {
    safeagent::auth::validate_key_config(config)?;
    let key_ids: Vec<&str> = config
        .split(',')
        .filter_map(|entry| entry.split_once(':').map(|(id, _)| id))
        .collect();
    let channel = if internal_dev { "dev-" } else { "prod-" };
    if key_ids.iter().any(|id| !id.starts_with(channel)) {
        return Err(if internal_dev {
            "INTERNAL_DEV_KEY_CHANNEL_INVALID"
        } else {
            "PRODUCTION_RING_CONTAINS_NON_PRODUCTION_KEY"
        });
    }
    // Rotation window: at most current + next key for each purpose.
    let mut purposes = std::collections::BTreeMap::<&str, usize>::new();
    for id in &key_ids {
        let purpose = id[channel.len()..]
            .rsplit_once('-')
            .map_or("", |(purpose, _)| purpose);
        *purposes.entry(purpose).or_default() += 1;
    }
    if purposes.values().any(|count| *count > 2) {
        return Err("RING_EXCEEDS_CURRENT_PLUS_NEXT");
    }
    if internal_dev && ids != DEV_EXTENSION_ID {
        return Err("INTERNAL_DEV_IDENTITY_INVALID");
    }
    if !internal_dev && ids.split(',').any(|id| id == DEV_EXTENSION_ID) {
        return Err("PRODUCTION_BUILD_CONTAINS_DEV_IDENTITY");
    }
    Ok(())
}

fn main() {
    // Distribution builds must enforce the Chrome parent check.
    if std::env::var("SAFEAGENT_ALLOW_ANY_PARENT").is_ok_and(|value| !value.is_empty()) {
        eprintln!("SAFEAGENT_ALLOW_ANY_PARENT_FORBIDDEN: parent check must stay enforced");
        std::process::exit(1);
    }
    let config = std::env::var("SAFEAGENT_AUTH_PUBLIC_KEYS").unwrap_or_default();
    let ids = std::env::var("SAFEAGENT_ALLOWED_EXTENSION_IDS").unwrap_or_default();
    let internal_dev = std::env::args().any(|arg| arg == "--internal-dev");
    if let Err(code) = validate(&config, &ids, internal_dev) {
        eprintln!("{code}: approved public configuration required for distribution");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::SigningKey;

    fn ring(ids: &[&str]) -> String {
        ids.iter()
            .enumerate()
            .map(|(index, id)| {
                let key = SigningKey::from_bytes(&[index as u8 + 42; 32]);
                format!(
                    "{id}:{}",
                    URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    #[test]
    fn production_ring_rejects_dev_keys_dev_identity_and_oversized_rotation() {
        let prod = "abcdefghijklmnopabcdefghijklmnop";
        let current_next = ring(&[
            "prod-preflight-20270101",
            "prod-preflight-20270701",
            "prod-monitoring-20270101",
        ]);
        assert!(validate(&current_next, prod, false).is_ok());
        let mixed = ring(&["prod-preflight-20270101", "dev-preflight-20261016"]);
        assert_eq!(
            validate(&mixed, prod, false),
            Err("PRODUCTION_RING_CONTAINS_NON_PRODUCTION_KEY")
        );
        let unlabelled = ring(&["preflight-20270101"]);
        assert!(validate(&unlabelled, prod, false).is_err());
        let three = ring(&[
            "prod-preflight-20270101",
            "prod-preflight-20270701",
            "prod-preflight-20280101",
        ]);
        assert_eq!(
            validate(&three, prod, false),
            Err("RING_EXCEEDS_CURRENT_PLUS_NEXT")
        );
        let prod_ring = ring(&["prod-preflight-20270101"]);
        assert_eq!(
            validate(&prod_ring, &format!("{prod},{DEV_EXTENSION_ID}"), false),
            Err("PRODUCTION_BUILD_CONTAINS_DEV_IDENTITY")
        );
        assert!(validate(&ring(&["prod-preflight-20270101"]), DEV_EXTENSION_ID, true).is_err());
    }

    #[test]
    fn internal_distribution_requires_exact_identity_and_valid_ring() {
        let config = ring(&["dev-preflight-20261016"]);
        assert!(validate(&config, DEV_EXTENSION_ID, true).is_ok());
        for ids in [
            "",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "lfmldljfbheedcddndbnfckfkhjmkekp,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(validate(&config, ids, true).is_err());
        }
        for ring in [
            "",
            "invalid",
            "test:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(validate(ring, DEV_EXTENSION_ID, true).is_err());
        }
        assert!(validate(&format!("{config},{config}"), DEV_EXTENSION_ID, true).is_err());
    }
}
