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

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, PartialEq, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PeerClaims {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "sub")]
    pub subject: String, // human-friendly name

    #[wasm_bindgen(js_name = groupId)]
    pub group_id: String,
    #[wasm_bindgen(js_name = peerId)]
    pub peer_id: String,

    #[wasm_bindgen(js_name = allowIncoming0)]
    pub allow_incoming_0: Option<FirewallClaims>,
    #[wasm_bindgen(js_name = allowIncoming1)]
    pub allow_incoming_1: Option<FirewallClaims>,

    #[wasm_bindgen(js_name = allowOutgoing0)]
    pub allow_outgoing_0: Option<FirewallClaims>,
    #[wasm_bindgen(js_name = allowOutgoing1)]
    pub allow_outgoing_1: Option<FirewallClaims>,
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, PartialEq, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FirewallClaims {
    #[wasm_bindgen(js_name = groupId)]
    pub group_id: String,
    #[wasm_bindgen(js_name = peerId)]
    pub peer_id: String,
}

#[wasm_bindgen]
impl FirewallClaims {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }
}

#[wasm_bindgen]
impl PeerClaims {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[wasm_bindgen]
    pub fn validate(&self) -> Result<(), AppError> {
        // TODO: add validation
        // limit id lengths
        // check rules
        Ok(())
    }
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Default, Clone)]
pub struct AppOpts {
    #[wasm_bindgen(js_name = projectId)]
    pub project_id: String,
    #[wasm_bindgen(js_name = appId)]
    pub app_id: String,
    #[wasm_bindgen(js_name = appSecret)]
    pub app_secret: String,
}

#[wasm_bindgen]
impl AppOpts {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<(), AppError> {
        // TODO: check ids
        Ok(())
    }
}

// public fields will treated as copyable by wasm_bindgen:
// https://github.com/rustwasm/wasm-bindgen/issues/1985
#[wasm_bindgen]
pub struct App {
    opts: AppOpts,
}

#[wasm_bindgen]
impl App {
    #[wasm_bindgen(constructor)]
    pub fn new(opts: &AppOpts) -> Self {
        Self { opts: opts.clone() }
    }

    #[wasm_bindgen(js_name=createToken)]
    pub fn create_token(
        &self,
        claims: &PeerClaims,
        duration_secs: u32,
    ) -> Result<String, AppError> {
        let claims = claims.clone();
        claims.validate()?;

        let formatted = &self.opts.app_secret;
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
        let header = Header::empty().with_key_id(&self.opts.app_id);
        let claims = Claims::new(claims)
            .set_duration(&time_options, Duration::seconds(duration_secs as i64));

        let token_string = Ed25519
            .compact_token(&header, &claims, &signing_key)
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
        let mut app_opts = AppOpts::new();
        app_opts.project_id = "p_CjZbgQHDvWiujEj7fii7N".to_owned();
        app_opts.app_id = "app_Ycl5ClRWJWNw8bqB25DMH".to_owned();
        app_opts.app_secret =
            "sk_e63bd11ff7491adc5f7cca5a4566b94d75ea6a9bafcd68252540eaa493a42109".to_owned();

        let app = App::new(&app_opts);

        let mut claims = PeerClaims::new();
        claims.subject = "alice L".to_owned();
        claims.peer_id = "alice".to_owned();
        app.create_token(&claims, 3600)?;
        Ok(())
    }
}
