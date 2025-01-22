// This runtime check will eventually become obselete as static exports will become the standard
// https://runtime-keys.proposal.wintercg.org/#example-usage

if (globalThis.navigator?.userAgent === "Cloudflare-Workers") {
  // https://developers.cloudflare.com/workers/runtime-apis/web-standards/#navigatoruseragent
} else if (globalThis.process?.release?.name === "node") {
  // https://nodejs.org/api/process.html#processrelease
} else if (globalThis.Deno) {
}
