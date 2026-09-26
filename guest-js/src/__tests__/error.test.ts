// error.test.ts
// =============
// Exercises `throwFromRpcError` and cross-checks `KNOWN_ERROR_PREFIXES`
// against `error.rs`'s `ErrorKind::ALL` — see that module's doc comment on
// why this specific list (not the transfer/session logic, which needs a
// live Tauri IPC layer to exercise meaningfully — see README.md's "What's
// tested where") is worth a dedicated, no-mocking-required test file: it's
// exactly the kind of two-sided-list drift that let pyside6-webusb v0.0.4b2
// fix a real gap in fox-webusb's predecessor and then, per this crate's own
// error.rs doc comment, leave a *different* one (`NotSupportedError`)
// unfixed in its own polyfill.py. Run with: `node --test` after `tsc`
// (see package.json's `test` script).

import { test } from "node:test";
import assert from "node:assert/strict";
import { throwFromRpcError, KNOWN_ERROR_PREFIXES } from "../polyfill.js";

test("KNOWN_ERROR_PREFIXES has exactly the seven prefixes error.rs can produce", () => {
  assert.deepEqual(
    [...KNOWN_ERROR_PREFIXES].sort(),
    ["DataError", "IndexSizeError", "InvalidAccessError", "InvalidStateError", "NotFoundError", "NotSupportedError", "SecurityError"].sort(),
  );
});

for (const prefix of ["SecurityError", "InvalidStateError", "NotFoundError", "InvalidAccessError", "IndexSizeError", "DataError", "NotSupportedError"]) {
  test(`throwFromRpcError maps "${prefix}: ..." to a DOMException named ${prefix}`, () => {
    assert.throws(
      () => throwFromRpcError(new Error(`${prefix}: something went wrong`)),
      (err: unknown) => err instanceof DOMException && err.name === prefix && err.message === "something went wrong",
    );
  });
}

test("throwFromRpcError falls back to the given default name for an unrecognized prefix", () => {
  assert.throws(
    () => throwFromRpcError(new Error("TotallyMadeUpError: oops"), "NetworkError"),
    (err: unknown) => err instanceof DOMException && err.name === "NetworkError",
  );
});

test("throwFromRpcError falls back to NetworkError by default when no default is given", () => {
  assert.throws(
    () => throwFromRpcError(new Error("plain message with no prefix at all")),
    (err: unknown) => err instanceof DOMException && err.name === "NetworkError",
  );
});

test("throwFromRpcError does not misfire on a message that merely contains a prefix mid-string", () => {
  // "SecurityError" appearing anywhere other than as the literal leading
  // "Prefix: " is not a match — a device whose product name happens to
  // contain the substring "NotFoundError" should not have that
  // misinterpreted as this plugin's own error-prefix convention.
  assert.throws(
    () => throwFromRpcError(new Error("some message mentioning SecurityError in passing")),
    (err: unknown) => err instanceof DOMException && err.name === "NetworkError",
  );
});

test("throwFromRpcError handles a plain string throw (not an Error instance)", () => {
  assert.throws(
    () => throwFromRpcError("NotFoundError: no device"),
    (err: unknown) => err instanceof DOMException && err.name === "NotFoundError" && err.message === "no device",
  );
});
