import { App, PeerClaims, PeerPolicy } from "./pkg-bundler/pulsebeam_core.js";

const app = new App(
  "kid_Ycl5ClRWJWNw8bqB25DMH",
  "sk_e63bd11ff7491adc5f7cca5a4566b94d75ea6a9bafcd68252540eaa493a42109",
);

const claims = new PeerClaims("default", "alice");
const policy = new PeerPolicy("default", "*");
claims.setAllowPolicy(policy);

const token = app.createToken(claims, 3600);
console.log(token);
