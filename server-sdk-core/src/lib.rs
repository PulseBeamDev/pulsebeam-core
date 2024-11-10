#![no_std]
extern crate alloc;
use alloc::string::{String, ToString};

use anyhow::{self, Context};
use chrono::{Duration, Utc};
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use jwt_compact::{alg::Ed25519, prelude::*};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct CustomClaims {
    #[serde(rename = "sub")]
    subject: String,
    // other fields...
}

pub fn create_token(id: &str, signing_key_hex: &str) -> anyhow::Result<String> {
    let signing_key_raw =
        hex::decode(signing_key_hex).with_context(|| "invalid signing_key format")?;
    let signing_key_bytes: [u8; SECRET_KEY_LENGTH] = signing_key_raw[..].try_into()?;
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);

    let time_options = TimeOptions::default();
    let header = Header::empty().with_key_id(id);
    let claims = Claims::new(CustomClaims {
        subject: "alice".to_string(),
    })
    .set_duration_and_issuance(&time_options, Duration::hours(1))
    .set_not_before(Utc::now());

    let token_string = Ed25519.token(&header, &claims, &signing_key)?;
    Ok(token_string)
}

#[cfg(test)]
mod tests {
    use anyhow::Ok;

    use super::*;

    #[test]
    fn test_create_token() -> anyhow::Result<()> {
        create_token(
            "347da29c4d3b4d2398237ed99dcd7eb8",
            "61eb06aa1a3a4ef80dd2a77503e226cc9afb667bed2dde38b31852ac781ea68a",
        )?;
        Ok(())
    }
}
