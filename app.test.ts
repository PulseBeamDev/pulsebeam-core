import {
  App,
  FirewallClaims,
  PeerClaims,
} from "./pkg-deno/pulsebeam_core.js";
import { assertEquals } from "jsr:@std/assert";

Deno.test({
  name: "create token",
  fn: () => {
    const app = new App(
      "app_Ycl5ClRWJWNw8bqB25DMH",
      "sk_e63bd11ff7491adc5f7cca5a4566b94d75ea6a9bafcd68252540eaa493a42109",
    );

    const claims = new PeerClaims("default", "alice");
    const incoming = new FirewallClaims("default", "*");
    claims.allowIncoming0 = incoming;
    claims.allowOutgoing0 = incoming;

    const token = app.createToken(claims, 3600);
    console.log(token);

    const parts = token.split(".");
    assertEquals(parts.length, 3);
  },
});
