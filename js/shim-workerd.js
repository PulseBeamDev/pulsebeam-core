// Cloudflare doesn't support URL, import.meta.url, and fs.readFileSync
// https://github.com/cloudflare/workers-sdk/issues/7265#issuecomment-2480871605

let imports = {};
import * as import0 from "./pulsebeam_core_bg.js";
import wasmModule from "./pulsebeam_core_bg.wasm";
imports["./pulsebeam_core_bg.js"] = import0;

const wasmInstance = await WebAssembly.instantiate(wasmModule, imports);
const wasm = wasmInstance.exports;
export const __wasm = wasm;

imports["./pulsebeam_core_bg.js"].__wbg_set_wasm(
  wasm,
  wasmModule,
);
wasm.__wbindgen_start();

export * from "./pulsebeam_core_bg.js";
