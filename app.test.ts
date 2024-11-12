import {
  App,
  AppOpts,
  FirewallClaims,
  PeerClaims,
} from "./pkg-deno/server_sdk_core.js";
import { assertEquals } from "jsr:@std/assert";

Deno.test({
  name: "create token",
  fn: () => {
    const appOpts = new AppOpts();
    appOpts.setProjectId("p_CjZbgQHDvWiujEj7fii7N");
    appOpts.setAppId("app_Ycl5ClRWJWNw8bqB25DMH");
    appOpts.setAppSecret(
      "sk_e63bd11ff7491adc5f7cca5a4566b94d75ea6a9bafcd68252540eaa493a42109",
    );
    appOpts.validate();

    const app = new App(appOpts);

    const claims = new PeerClaims();
    claims.setPeerId("alice");
    claims.setGroupId("0");

    const incoming = new FirewallClaims();
    incoming.setGroupId("*");
    incoming.setPeerId("*");
    claims.setAllowIncoming(0, incoming);
    claims.setAllowOutgoing(0, incoming);

    const token = app.createToken(claims, 3600);
    console.log(token);

    const parts = token.split(".");
    assertEquals(parts.length, 3);
  },
});
