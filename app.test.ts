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
    appOpts.projectId = "p_CjZbgQHDvWiujEj7fii7N";
    appOpts.appId = "app_Ycl5ClRWJWNw8bqB25DMH";
    appOpts.appSecret =
      "sk_e63bd11ff7491adc5f7cca5a4566b94d75ea6a9bafcd68252540eaa493a42109";
    appOpts.validate();

    const app = new App(appOpts);

    const claims = new PeerClaims();
    claims.peerId = "alice";
    claims.groupId = "0";

    const incoming = new FirewallClaims();
    incoming.groupId = "*";
    incoming.peerId = "*";
    claims.allowIncoming0 = incoming;
    claims.allowOutgoing0 = incoming;

    const token = app.createToken(claims, 3600);
    console.log(token);

    const parts = token.split(".");
    assertEquals(parts.length, 3);
  },
});
