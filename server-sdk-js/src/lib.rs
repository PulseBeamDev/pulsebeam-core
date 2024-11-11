mod utils;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = createToken)]
pub fn create_token(id: String, signing_key_hex: String) -> Result<String, JsError> {
    server_sdk_core::create_token(&id, &signing_key_hex).map_err(|e| JsError::new(&e.to_string()))
}
