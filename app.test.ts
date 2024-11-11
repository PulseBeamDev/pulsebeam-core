import { App, TokenOpts } from "./pkg-deno/server_sdk_core.js";
import { assertEquals } from "jsr:@std/assert";

Deno.test({
  name: "create token",
  fn: () => {
    const app = new App(
      "347da29c4d3b4d2398237ed99dcd7eb8",
      "61eb06aa1a3a4ef80dd2a77503e226cc9afb667bed2dde38b31852ac781ea68a",
    );

    const opts = new TokenOpts();
    opts.subject = "alice";
    opts.groupId = "0";

    const token = app.createToken(opts);
    console.log(token);

    const parts = token.split(".");
    assertEquals(parts.length, 3);
  },
});
