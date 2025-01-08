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

// @pulsebeam/server: Open-Source Server SDK.
//
// Use `@pulsebeam/server` to generate tokens for your `@pulsebeam/peer` clients to use.
//
// For more on @pulsebeam/server: https://jsr.io/@pulsebeam/server
//
// For more on @pulsebeam/peer: https://jsr.io/@pulsebeam/peer
//
// For more on PulseBeam: https://pulsebeam.dev/
//
// For more on tokens, specifically JWTs, see the RFC: https://datatracker.ietf.org/doc/html/rfc7519
//
// # Example Usage
//
// ```ts
// // Step 1: Initialize app
// const { PULSEBEAM_API_KEY, PULSEBEAM_API_SECRET } = process.env;
// const app = new App(PULSEBEAM_API_KEY, PULSEBEAM_API_SECRET);
//
// // Step 2: Listen for JWT requests from your clients'
// router.post('/auth', (req, res) => {
//   // Step 3: Generate JWT and respond with JWT
//   const claims = new PeerClaims("myGroup1", "myPeer1");
//   const rule = new PeerPolicy("myGroup*", "*");
//   claims.setAllowPolicy(rule);
//
//   const ttlSeconds = 3600;
//   const token = app.createToken(claims, ttlSeconds);
//   res.json({ groupId, peerId, token });
// });
// ```
//
// If any of the following methods are present, you should NOT use them:
//
// free
//
// __destroy_into_raw
//
// __wbg_getTime_*  - internal method do not use
//
// __wbg_new0_* - internal method do not use
//
// __wbg_new_* - internal method do not use
//
// __wbg_set_wasm - internal method do not use
//
// __wbindgen_init_externref_table - internal method do not use
//
// __wbindgen_throw - internal method do not use

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

/// `PeerClaims` are used to identify the peer and control which peer(s) this peer
/// is allowed to connect to.
///
/// These claims are embedded in the JWT token you generate. They are later
/// read by PulseBeam's signaling servers.
///
/// To learn about claims see JWT RFC {@link https://datatracker.ietf.org/doc/html/rfc7519}
///
/// `free()` - internal method do not use
///
/// `__destroy_into_raw()` - internal method do not use
#[wasm_bindgen]
#[derive(Debug, PartialEq, Serialize, Deserialize, Default, Clone)]
pub struct PeerClaims {
    #[wasm_bindgen(skip)]
    #[serde(rename = "gid")]
    pub group_id: String,
    #[wasm_bindgen(skip)]
    #[serde(rename = "pid")]
    pub peer_id: String,

    #[wasm_bindgen(skip)]
    #[serde(rename = "ap")]
    pub allow_policy: Option<PeerPolicy>,
}

#[wasm_bindgen]
impl PeerClaims {
    /// Construct `PeerClaims` from a given `group_id` and `peer_id`.
    ///
    /// `group_id` must be the identifier for the group which the peer belongs to. Must be a valid UTF-8 string of 1-16 characters.
    ///
    /// `peer_id` must be the identifier for the peer. Must be a valid UTF-8 string of 1-16 characters.
    ///
    /// # Examples
    /// ```ts
    /// const claims = new PeerClaims("myGroup1", "myPeer1");
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(group_id: &str, peer_id: &str) -> Self {
        Self {
            group_id: group_id.to_owned(),
            peer_id: peer_id.to_owned(),
            ..Self::default()
        }
    }
    #[wasm_bindgen(js_name = "setAllowPolicy")]
    pub fn set_allow(&mut self, claims: &PeerPolicy) {
        self.allow_policy = Some(claims.clone());
    }
}

/// Define what peer(s) this peer is allowed to connect to
///
/// These are stored as JWT claims. For more info on JWTs see RFC
/// https://datatracker.ietf.org/doc/html/rfc7519
///
/// Note: Regardless of `PeerPolicy`, peers can only connect to other peers
/// within the scope of your `app-id`.
///
/// # Examples
/// `PeerPolicy("*", "*")` allows this peer to connect to any other peer.
///
/// From there, you can opt to further scope-down permissions.
///
/// Let's say you are building a video call app. Where non-developers are only
/// allowed to talk with other non-developers. If you put all non-developers in
/// group called 'nonDev', you could set `PeerPolicy("nonDev", "*")` on
/// those peers to configure this behavior.
///
/// `free()` - internal method do not use
///
/// `__destroy_into_raw()` - internal method do not use
#[wasm_bindgen]
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct PeerPolicy {
    #[wasm_bindgen(skip)]
    pub group_id: String,
    #[wasm_bindgen(skip)]
    pub peer_id: String,
}

#[wasm_bindgen]
impl PeerPolicy {
    /// Create `PeerPolicy` instance using provided `group_id` and
    /// `peer_id`.
    ///
    /// This is used in conjunction with `PeerClaims` to scope connection permissions.
    ///
    /// `group_id` - Desired rule for allowed groupIds
    ///
    /// `peer_id` - Desired for allowed peerIds
    ///
    /// Policy string must be:
    /// - Valid UTF-8 string
    /// - 1 character <= length(string) <= 16 characters
    /// - Contains no more than 1 wildcard (*)
    ///  
    /// # Examples
    /// Policy String:
    /// `["*", "myGroup", "*bob", "dev*"]`
    ///
    /// Usage:
    ///
    /// `const rule = new PeerPolicy("myGroup*", "*");`
    #[wasm_bindgen(constructor)]
    pub fn new(group_id: &str, peer_id: &str) -> Self {
        Self {
            group_id: group_id.to_owned(),
            peer_id: peer_id.to_owned(),
        }
    }
}

// public fields will be treated as copyable by wasm_bindgen:
// https://github.com/rustwasm/wasm-bindgen/issues/1985

/// Represents the main application instance.
///
/// Get an `api_key` and `api_secret` from {@link https://pulsebeam.dev}
///
/// You are required to set `PeerPolicy` as network rules on `PeerClaims`
/// in order for resultant token to be valid.
///
/// `free()` - internal method do not use
///
/// `__destroy_into_raw()` - internal method do not use
///
/// # Examples
///
/// ```ts
/// const { PULSEBEAM_API_KEY, PULSEBEAM_API_SECRET } = process.env;
/// const app = new App(PULSEBEAM_API_KEY, PULSEBEAM_API_SECRET);
///
/// router.post('/auth', (req, res) => {
///   const claims = new PeerClaims("myGroup1", "myPeer1");
///   const policy = new PeerPolicy("myGroup*", "*");
///   claims.setAllowPolicy(policy); // required
///
///   const ttlSeconds = 3600; // 1 hour
///   const token = app.createToken(claims, ttlSeconds);
///   res.json({ groupId, peerId, token });
/// });```
#[wasm_bindgen]
pub struct App {
    #[wasm_bindgen(skip)]
    pub api_key: String,
    #[wasm_bindgen(skip)]
    pub api_secret: String,
}

#[wasm_bindgen]
impl App {
    /// Creates a new `App` instance using your config. Essential for creating
    /// client tokens.
    ///
    /// Get an api_key and api_secret from {@link https://pulsebeam.dev}
    ///
    /// # Examples
    ///
    /// ```ts
    /// const app = new App(MY_API_KEY, MY_API_SECRET);```
    #[wasm_bindgen(constructor)]
    pub fn new(api_key: &str, api_secret: &str) -> Self {
        Self {
            api_key: api_key.to_owned(),
            api_secret: api_secret.to_owned(),
        }
    }

    /// Create a JWT. The JWT should be used by your client-side application.
    ///
    /// Given `claims` the peer claims to be included in the token and a
    /// `durationSecs` TTL before token expiration. `createToken` Returns the
    /// generated JWT token as a string ready to be passed to your client
    ///
    /// To learn about JWTs and claims see JWT RFC https://datatracker.ietf.org/doc/html/rfc7519
    ///
    /// # Throws
    ///
    /// {Error} When token creation fails. Likely an issue with your
    /// AppSecret.
    ///
    /// # Example
    ///
    /// ```ts
    /// const token = app.createToken(claims, ttlSeconds);```
    #[wasm_bindgen(js_name=createToken)]
    pub fn create_token(
        &self,
        claims: &PeerClaims,
        duration_secs: u32,
    ) -> Result<String, AppError> {
        let claims = claims.clone();

        let formatted = &self.api_secret;
        let (_, api_secret) = if let Some(index) = formatted.find("_") {
            let entity = formatted[..index].to_string();
            let id = formatted[index + 1..].to_string();
            (entity, id)
        } else {
            return Err(AppError::new("invalid api_secret"));
        };

        let signing_key_raw =
            hex::decode(&api_secret).with_context(|| "invalid secret format, expecting hex")?;
        let signing_key_bytes: [u8; SECRET_KEY_LENGTH] = signing_key_raw[..]
            .try_into()
            .with_context(|| "invalid secret length")?;
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);

        let time_options = TimeOptions::default();
        let header = Header::empty().with_key_id(&self.api_key);
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
            "kid_Ycl5ClRWJWNw8bqB25DMH",
            "sk_e63bd11ff7491adc5f7cca5a4566b94d75ea6a9bafcd68252540eaa493a42109",
        );

        let claims = PeerClaims::new("default", "alice");
        app.create_token(&claims, 3600)?;
        Ok(())
    }
}
