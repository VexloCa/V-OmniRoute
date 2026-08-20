import assert from "node:assert/strict";
import test from "node:test";

import {
  buildSmokeEnv,
  FATAL_LOG_PATTERNS,
  findFatalLogPattern,
  LINUX_EXECUTABLE_NAMES,
} from "../../scripts/dev/smoke-electron-packaged.mjs";

test("electron smoke discovers the default Linux executable name", () => {
  assert.ok(LINUX_EXECUTABLE_NAMES.includes("omniroute-desktop"));
});

test("electron smoke env allowlists runtime variables and drops secrets", () => {
  const env = buildSmokeEnv({
    currentPlatform: "linux",
    dataDir: "/tmp/omniroute-electron-smoke-test",
    parentEnv: {
      DISPLAY: ":99",
      GITHUB_TOKEN: "should-not-leak",
      PATH: "/usr/bin",
      SNYK_TOKEN: "should-not-leak",
    },
  });

  assert.equal(env.DATA_DIR, "/tmp/omniroute-electron-smoke-test");
  assert.equal(env.DISPLAY, ":99");
  assert.equal(env.PATH, "/usr/bin");
  assert.equal(env.HOME, "/tmp/omniroute-electron-smoke-test/home");
  assert.equal(env.XDG_CONFIG_HOME, "/tmp/omniroute-electron-smoke-test/config");
  assert.equal(env.ELECTRON_ENABLE_LOGGING, "1");
  assert.equal(env.ELECTRON_ENABLE_STACK_DUMPING, "1");
  assert.equal(env.GITHUB_TOKEN, undefined);
  assert.equal(env.SNYK_TOKEN, undefined);
});

test("electron smoke treats Electron process errors as fatal startup logs", () => {
  const logs = [
    "[Electron] Unhandled Rejection: Error: startup failed",
    "[Electron] Uncaught Exception: Error: startup failed",
  ];

  for (const log of logs) {
    assert.ok(
      FATAL_LOG_PATTERNS.some((pattern) => pattern.test(log)),
      `${log} should match a fatal log pattern`
    );
  }
});

test("electron smoke permits expected optional SQLite driver fallbacks", () => {
  const logs = [
    "[Server] [DB] Sync driver 'better-sqlite3' failed to open, will try next driver: Cannot find module 'better-sqlite3'",
    "[DB] Sync driver 'node:sqlite' failed to open, will try next driver: Cannot find module 'node:sqlite'",
    "[Server:err] [DB] Pre-initializing sql.js WASM (synchronous drivers unavailable)...",
    "[Server] [DB] SQLite database ready: /tmp/omniroute-electron-smoke/storage.sqlite",
  ].join("\n");

  assert.equal(findFatalLogPattern(logs), undefined);
});

test("electron smoke still rejects unrelated missing runtime modules", () => {
  const logs = "Error: Cannot find module 'required-runtime-package'";

  assert.equal(findFatalLogPattern(logs)?.source, "Cannot find module");
});

test("electron smoke still rejects a fatal code after an expected SQLite fallback", () => {
  const logs = [
    "[DB] Sync driver 'better-sqlite3' failed to open, will try next driver: Cannot find module 'better-sqlite3'",
    "code: MODULE_NOT_FOUND",
  ].join("\n");

  assert.equal(findFatalLogPattern(logs)?.source, "MODULE_NOT_FOUND");
});
