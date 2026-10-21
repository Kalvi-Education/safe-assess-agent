const DEV_EXTENSION_ID: &str = "khafofcbffjkkeeldejiplkfpdfckeol";

fn validate(config: &str, ids: &str, internal_dev: bool) -> Result<(), &'static str> {
    safeagent::auth::validate_key_config(config)?;
    if internal_dev && ids != DEV_EXTENSION_ID {
        return Err("INTERNAL_DEV_IDENTITY_INVALID");
    }
    Ok(())
}

fn main() {
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

    #[test]
    fn internal_distribution_requires_exact_identity_and_valid_ring() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let config = format!(
            "unit-test:{}",
            URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())
        );
        assert!(validate(&config, DEV_EXTENSION_ID, true).is_ok());
        for ids in [
            "",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "khafofcbffjkkeeldejiplkfpdfckeol,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
