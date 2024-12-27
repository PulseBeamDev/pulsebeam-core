#![no_std]
extern crate alloc;
use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
};

use anyhow::{self, Context};
use chrono::Duration;
use core::default::Default;
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use jwt_compact::{alg::Ed25519, prelude::*, AlgorithmExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Error, Debug)]
pub struct AppError {
    reason: String,
}

impl AppError {
    pub fn new(reason: &str) -> Self {
        Self {
            reason: reason.to_owned(),
        }
    }
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

#[wasm_bindgen]
#[derive(Debug, PartialEq, Serialize, Deserialize, Default, Clone)]
pub struct PeerClaims {
    group_id: String,
    peer_id: String,

    allow_incoming_0: Option<FirewallClaims>,
    allow_outgoing_0: Option<FirewallClaims>,
}

#[wasm_bindgen]
impl PeerClaims {
    #[wasm_bindgen(constructor)]
    pub fn new(group_id: &str, peer_id: &str) -> Self {
        Self {
            group_id: group_id.to_owned(),
            peer_id: peer_id.to_owned(),
            ..Self::default()
        }
    }

    #[wasm_bindgen(js_name = "setAllowIncoming0")]
    pub fn set_allow_incoming_0(&mut self, val: &FirewallClaims) {
        self.allow_incoming_0 = Some(val.clone());
    }

    #[wasm_bindgen(js_name = "setAllowOutgoing0")]
    pub fn set_allow_outgoing_0(&mut self, val: &FirewallClaims) {
        self.allow_outgoing_0 = Some(val.clone());
    }
}

#[wasm_bindgen]
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct FirewallClaims {
    group_id: String,
    peer_id: String,
}

#[wasm_bindgen]
impl FirewallClaims {
    #[wasm_bindgen(constructor)]
    pub fn new(group_id: &str, peer_id: &str) -> Self {
        Self {
            group_id: group_id.to_owned(),
            peer_id: peer_id.to_owned(),
        }
    }
}

// public fields will treated as copyable by wasm_bindgen:
// https://github.com/rustwasm/wasm-bindgen/issues/1985
#[wasm_bindgen]
pub struct App {
    app_id: String,
    app_secret: String,
}

#[wasm_bindgen]
impl App {
    #[wasm_bindgen(constructor)]
    pub fn new(app_id: &str, app_secret: &str) -> Self {
        Self {
            app_id: app_id.to_owned(),
            app_secret: app_secret.to_owned(),
        }
    }

    #[wasm_bindgen(js_name=createToken)]
    pub fn create_token(
        &self,
        claims: &PeerClaims,
        duration_secs: u32,
    ) -> Result<String, AppError> {
        let claims = claims.clone();

        let formatted = &self.app_secret;
        let (_, app_secret) = if let Some(index) = formatted.find("_") {
            let entity = formatted[..index].to_string();
            let id = formatted[index + 1..].to_string();
            (entity, id)
        } else {
            return Err(AppError::new("invalid app_secret"));
        };

        let signing_key_raw =
            hex::decode(&app_secret).with_context(|| "invalid secret format, expecting hex")?;
        let signing_key_bytes: [u8; SECRET_KEY_LENGTH] = signing_key_raw[..]
            .try_into()
            .with_context(|| "invalid secret length")?;
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);

        let time_options = TimeOptions::default();
        let header = Header::empty().with_key_id(&self.app_id);
        let claims = Claims::new(claims)
            .set_duration(&time_options, Duration::seconds(duration_secs as i64));

        let token_string = Ed25519
            .token(&header, &claims, &signing_key)
            .with_context(|| "failed to sign token")?;
        Ok(token_string)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Ok;

    use super::*;

    #[test]
    fn test_create_token() -> anyhow::Result<()> {
        let app = App::new(
            "app_Ycl5ClRWJWNw8bqB25DMH",
            "sk_e63bd11ff7491adc5f7cca5a4566b94d75ea6a9bafcd68252540eaa493a42109",
        );

        let claims = PeerClaims::new("default", "alice");
        app.create_token(&claims, 3600)?;
        Ok(())
    }
}
