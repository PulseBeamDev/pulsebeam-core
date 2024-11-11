#![no_std]
extern crate alloc;
use alloc::string::{String, ToString};

use anyhow::{self, Context};
use chrono::{Duration, Utc};
use core::default::Default;
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use jwt_compact::{alg::Ed25519, prelude::*};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Error, Debug)]
pub struct AppError {
    reason: String,
}

// Implement the Display trait from core
impl core::fmt::Display for AppError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Assuming Diagnostics implements core::fmt::Display
        write!(f, "{}", self.reason)
    }
}

// https://rustwasm.github.io/wasm-bindgen/reference/types/result.html
impl Into<JsValue> for AppError {
    fn into(self) -> JsValue {
        JsValue::from(js_sys::Error::new(&self.reason))
    }
}

impl From<anyhow::Error> for AppError {
    fn from(value: anyhow::Error) -> Self {
        Self {
            reason: value.to_string(),
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct PeerClaims {
    #[serde(rename = "sub")]
    subject: String,
    group_id: String,
}

#[wasm_bindgen]
#[derive(Default)]
pub struct TokenOpts {
    subject: String,
    group_id: String,
}

#[wasm_bindgen]
impl TokenOpts {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[wasm_bindgen(setter = subject)]
    pub fn set_subject(&mut self, subject: String) {
        self.subject = subject;
    }

    #[wasm_bindgen(setter = groupId)]
    pub fn set_group_id(&mut self, group_id: String) {
        self.group_id = group_id;
    }
}

// public fields will treated as copyable by wasm_bindgen:
// https://github.com/rustwasm/wasm-bindgen/issues/1985
#[wasm_bindgen]
pub struct App {
    id: String,
    secret: String,
}

#[wasm_bindgen]
impl App {
    #[wasm_bindgen(constructor)]
    pub fn new(id: String, secret: String) -> Self {
        Self { id, secret }
    }

    #[wasm_bindgen(js_name=createToken)]
    pub fn create_token(&self, opts: TokenOpts) -> Result<String, AppError> {
        let signing_key_raw =
            hex::decode(&self.secret).with_context(|| "invalid secret format, expecting hex")?;
        let signing_key_bytes: [u8; SECRET_KEY_LENGTH] = signing_key_raw[..]
            .try_into()
            .with_context(|| "invalid secret length")?;
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);

        let time_options = TimeOptions::default();
        let header = Header::empty().with_key_id(&self.id);
        let claims = Claims::new(PeerClaims {
            subject: opts.subject,
            group_id: opts.group_id,
        })
        .set_duration_and_issuance(&time_options, Duration::hours(1))
        .set_not_before(Utc::now());

        let token_string = Ed25519
            .token(&header, &claims, &signing_key)
            .with_context(|| "failed to sign token")?;
        Ok(token_string)
    }
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;
    use anyhow::Ok;

    use super::*;

    #[test]
    fn test_create_token() -> anyhow::Result<()> {
        let app = App::new(
            "347da29c4d3b4d2398237ed99dcd7eb8".to_owned(),
            "61eb06aa1a3a4ef80dd2a77503e226cc9afb667bed2dde38b31852ac781ea68a".to_owned(),
        );
        app.create_token(TokenOpts {
            subject: "alice".to_owned(),
            group_id: "0".to_owned(),
        })?;
        Ok(())
    }
}
