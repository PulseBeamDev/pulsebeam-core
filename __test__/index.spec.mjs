import test from "ava";

import { createToken } from "../index.js";

test("sum from native", (t) => {
  const token = createToken(
    "347da29c4d3b4d2398237ed99dcd7eb8",
    "61eb06aa1a3a4ef80dd2a77503e226cc9afb667bed2dde38b31852ac781ea68a",
  );
  console.log("From native", token);

  // TODO: more thorough test
  const parts = token.split(".");
  t.is(parts.length, 3); // there are only 3 parts in jwt
});
