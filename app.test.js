const {
  App,
  FirewallClaims,
  PeerClaims,
} = require("./pkg-node/pulsebeam_core.js");

const app = new App(
  "app_Ycl5ClRWJWNw8bqB25DMH",
  "sk_e63bd11ff7491adc5f7cca5a4566b94d75ea6a9bafcd68252540eaa493a42109",
);

const claims = new PeerClaims("default", "alice");
const incoming = new FirewallClaims("default", "*");
claims.setAllowIncoming0(incoming);
claims.setAllowOutgoing0(incoming);

const token = app.createToken(claims, 3600);
console.log(token);
