import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const dockerfile = readFileSync(new URL("../../Dockerfile", import.meta.url), "utf8");
const workflow = readFileSync(
  new URL("../../.github/workflows/askway-production-image.yml", import.meta.url),
  "utf8"
);

test("ASKWay production image excludes the unused global npm runtime", () => {
  assert.match(dockerfile, /^FROM runner-base AS runner-production$/m);
  assert.match(dockerfile, /rm -rf \/usr\/local\/lib\/node_modules\/npm/);
  assert.match(dockerfile, /rm -f \/usr\/local\/bin\/npm \/usr\/local\/bin\/npx/);
  assert.match(workflow, /^\s+target: runner-production$/m);
});
