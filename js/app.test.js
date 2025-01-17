import {
  AccessToken,
  PeerClaims,
  PeerPolicy,
} from "./pkg-bundler/pulsebeam_core.js";

const app = new AccessToken(
  "kid_73d8caa6c387d46c",
  "sk_7edea599046490dfd271b863b03398d2b613812b1f23efd023ca3b08026d3e67",
);

const claims = new PeerClaims("default", "alice");
const policy = new PeerPolicy("default", "*");
claims.setAllowPolicy(policy);

const token = app.createToken(claims, 3600);
console.log(token);
