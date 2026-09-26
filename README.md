# tauri-webusb

A [Tauri](https://tauri.app) v2 plugin that ports the [WebUSB API](https://wicg.github.io/webusb/)
(`navigator.usb`) to Tauri desktop apps.

## Why this exists

WebUSB is a WICG Draft Report implemented only by Chromium-family browsers.
Tauri's webview is never Chromium — it's WebView2 on Windows, WKWebView on
macOS, WebKitGTK on Linux — so `navigator.usb` simply does not exist in a
Tauri app's frontend today, and won't, upstream, for the same reason it
doesn't exist in Firefox or Safari: neither WebKit nor (to my knowledge)
Microsoft's WebView2 team has implemented it, and Mozilla's own standards
position on WebUSB is explicitly negative.

This plugin fills that gap the way a polyfill fills any other missing
browser API: it defines `navigator.usb` itself, backed by a real Rust USB
implementation ([`nusb`](https://github.com/kevinmehall/nusb)) running
in-process as part of your Tauri app, with its own permission-prompt and
device-blocklist model standing in for the parts of the real WebUSB security
story that only a browser vendor can normally provide.

**Status: v0.0.0, initial release.** Please read "Known limitations" below
before depending on this for anything that touches real hardware — several
things here are architecturally complete but haven't been exercised against
a real device (see "Development environment" for exactly why, and exactly
what *has* been verified).

## Relationship to prior art

This is not the first attempt at solving "give a non-Chromium desktop
webview a `navigator.usb`". Two earlier MIT-licensed projects solved the
same problem for different host environments, and this plugin's security
model is a direct descendant of both:

- **pyside6-webusb** — a QtWebEngine/PySide6 desktop-app implementation. The
  original: a `QWebChannel` bridge exposing a Python `pyusb`-backed object
  to page JS, with a hand-rolled per-frame origin-tracking scheme
  (`QWebEngineUrlRequestInterceptor` + injected tokens) since Qt gives no
  verified "which frame is this call from" for free.
- **fox-webusb** — a port of pyside6-webusb (specifically, its v0.0.4b0
  snapshot) to a Firefox extension: a `page_polyfill.js` content-script
  injection talking to a Python native-messaging host over stdin/stdout,
  using `sender.url` (which the WebExtensions API verifies for you) instead
  of a bespoke token scheme.

tauri-webusb was written with the full source of both available side by
side — including a `fox-webusb` v0.0.0a0 update tracking pyside6-webusb
forward to its v0.0.4b1 fixes. That let this port do something neither
single-lineage project could: catch places where the two had *diverged*,
and deliberately pick the more-correct side rather than just following
whichever one looked most directly reusable. Specifically:

| Behavior | fox-webusb (v0.0.0/v0.0.0a0) | pyside6-webusb v0.0.4b2 | tauri-webusb |
|---|---|---|---|
| Transfer-size-exceeded / isochronous packetLengths-mismatch error | `IndexSizeError` | `DataError` (confirmed against real Blink's `usb_device.cc`) | `DataError` — follows v0.0.4b2, since fox-webusb was ported from the older, pre-fix v0.0.4b0 |
| Bulk/isochronous transfer size limit | Hard reject at 64 MiB / 16 MiB | Chrome-reference 32 MiB *warning* (transfer still proceeds) + a separate, much larger host-safety hard ceiling; framed explicitly as "WebUSB-*compatible*, not a Chrome clone" | Follows v0.0.4b2's policy: `CHROME_TRANSFER_WARN_LENGTH` (32 MiB, warns) + `HOST_SAFETY_MAX_TRANSFER_LENGTH` (512 MiB, hard ceiling) — see `hardening.rs` |
| `NotSupportedError` recognition | Not in the 5-entry known-prefix list | pyside6-webusb's own `bridge.py` *emits* a hand-written `"NotSupportedError: ..."` string for its isochronous-unavailable case, but its own `KNOWN_ERROR_PREFIXES` list — audited and expanded in the very same v0.0.4b2 release — still doesn't include it, so that specific rejection actually surfaces as `NetworkError` in both predecessors | Added as a properly-recognized 7th prefix (see `error.rs`), and is what this plugin's own isochronous-transfers-unavailable case actually uses |
| `navigator.usb`/`USBDevice` class design | v0.0.0: plain objects + `.prototype` assignment. v0.0.0a0: rewritten as real `class ... extends EventTarget`/`extends Event` with private (`#`) fields, `Symbol.toStringTag`, for compatibility with real-world feature-detection code | (v0.0.0a0's rewrite postdates pyside6-webusb v0.0.4b2; not back-ported there) | Follows fox-webusb v0.0.0a0's class design (see `guest-js/src/polyfill.ts`) — modern TypeScript classes get most of these properties "for free" |
| Isochronous transfer implementation | Best-effort via `dev.read()`/`dev.write()` against the raw endpoint address (pyusb's public API has no isochronous support) | Explicitly considered and *rejected* an unsafe libusb-FFI implementation for v0.0.4b2, for lack of real isochronous-capable hardware to validate it against; kept the pyusb-internals hack from earlier versions instead | **Not implemented.** `nusb` (this plugin's backend) has no isochronous transfer support at all as of this writing ([tracked upstream](https://github.com/kevinmehall/nusb/issues/47)), and for the same reason pyside6-webusb gave for not doing unsafe FFI, this version doesn't attempt one either. Returns a clear `NotSupportedError` after running full validation — see `bridge.rs` |

None of this required copying source between the two predecessors' languages
— the actual reason to look at both was to catch exactly this kind of
version-skew bug before repeating it a third time.

## Installation

### Rust side

```toml
# src-tauri/Cargo.toml
[dependencies]
tauri-plugin-webusb = "0.0"
```

```rust
// src-tauri/src/main.rs
tauri::Builder::default()
    .plugin(tauri_plugin_webusb::init())
    // ...
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
```

### JS side

```sh
npm install tauri-plugin-webusb-api
```

You don't need to import anything from it for `navigator.usb` itself to
exist — this plugin registers its guest-js bundle as a webview
initialization script, so it's present before your app's own page JS runs,
the same way a real browser's `navigator.usb` just *is there*. Install the
package anyway for its TypeScript types (`import type {} from
"tauri-plugin-webusb-api"` or reference `types/webusb-polyfill.d.ts`
directly — see that file's own header comment) and for the trusted
management API if you're building a device/permissions settings screen (see
"Trust model" below).

### Capabilities

Tauri v2 gates every command behind its own capability/ACL system, checked
*before* this plugin's command handlers ever run. You need at least one
capability granting `"webusb:default"` to whichever window(s) should see
`navigator.usb`:

```json
// src-tauri/capabilities/main.json
{
  "identifier": "webusb-main-window",
  "windows": ["main"],
  "permissions": ["webusb:default"]
}
```

The device chooser this plugin shows for `requestDevice()` is itself a
dynamically-created window (label `tauri-webusb-chooser-*`) — the same
capability's `windows` pattern needs to also match it, or widen it to a
second capability entry:

```json
{
  "identifier": "webusb-chooser-window",
  "windows": ["tauri-webusb-chooser-*"],
  "permissions": ["webusb:default"]
}
```

If you're building a trusted settings UI that lists/revokes granted origins
(see below), grant it `"webusb:manage"` too — **only** on a window that
never loads third-party content:

```json
{
  "identifier": "webusb-settings-window",
  "windows": ["settings"],
  "permissions": ["webusb:manage"]
}
```

## Usage

Once installed and capability-granted, page code is exactly what you'd
write against a real browser's WebUSB — nothing tauri-webusb-specific to
import or call:

```js
const button = document.querySelector("#connect");
button.addEventListener("click", async () => {
  try {
    const device = await navigator.usb.requestDevice({ filters: [{ vendorId: 0x2341 }] });
    await device.open();
    await device.selectConfiguration(1);
    await device.claimInterface(0);
    const result = await device.transferIn(1, 64);
    console.log(new Uint8Array(result.data.buffer));
    await device.close();
  } catch (err) {
    console.error(err.name, err.message); // a real DOMException, same as in Chrome
  }
});

navigator.usb.addEventListener("disconnect", (event) => {
  console.log("unplugged:", event.device.productName);
});
```

## Architecture

```
┌─────────────────────────┐        Tauri IPC (invoke / events)        ┌──────────────────────────┐
│  Page JS                │  ───────────────────────────────────────▶ │  Rust plugin              │
│  navigator.usb (guest-js│                                            │                            │
│  polyfill: USB,         │ ◀───────────────────────────────────────  │  commands.rs               │
│  USBDevice, ...)        │        connect/disconnect events           │   ├─ origin.rs  (who's calling)
└─────────────────────────┘                                            │   ├─ hardening.rs (is it allowed)
                                                                        │   ├─ bridge.rs  (do it, via nusb)
                                                                        │   ├─ settings_store.rs (persist grants)
                                                                        │   ├─ chooser.rs (requestDevice UI)
                                                                        │   └─ hotplug.rs (connect/disconnect fan-out)
                                                                        └──────────────┬─────────────┘
                                                                                       │
                                                                                  nusb (pure Rust,
                                                                                  no libusb/Python)
                                                                                       │
                                                                                  OS USB stack
```

Everything right of the IPC boundary runs in-process, as part of your
compiled app — there is no separate native-messaging host process (unlike
`fox-webusb`) and no Python interpreter to bundle (unlike either
predecessor). That's a direct consequence of Tauri's own architecture: the
"native host" a browser extension needs and the "native backend" a Tauri
plugin *is* are the same thing here.

## Trust model

Three independent mechanisms compose to decide what a given piece of page
JS can actually do — worth understanding all three if you're auditing this:

**1. Tauri's own capability/ACL system.** Checked by Tauri's core before a
command handler runs at all, based on the calling webview's window label and
current URL matched against your app's `capabilities/*.json`. This is what
makes the "page" vs "manage" split real: a window you never granted
`"webusb:manage"` cannot invoke `list_granted_origins` etc. even in
principle — the call is rejected before any of this plugin's own code sees
it. Both predecessors had to build an equivalent themselves by hand
(`fox-webusb`'s `_TRUSTED_ONLY_METHODS` + a `sender.url` check inside a
single shared message dispatcher); here it's a structural property of using
Tauri's own per-command permission model instead of a single shared RPC
endpoint.

**2. Origin-scoped device grants**, exactly like real browser WebUSB. A
`requestDevice()` call shows a chooser; picking a device grants *that
origin* — `origin.rs`'s `origin_of(&webview.url())`, which is Tauri's own
core-tracked, unspoofable navigation state, the direct analogue of
`sender.url` in `fox-webusb` or the injected-token scheme in
`pyside6-webusb` — persistent access to that specific `(vendorId,
productId)` pair. `getDevices()` only ever returns devices the calling
origin was previously granted. This is enforced in `bridge.rs`/
`settings_store.rs`, independent of the capability layer above.

**3. Protected interface classes + a device blocklist**, applied regardless
of what an origin has been granted. `claimInterface()` on an interface
declaring Audio, HID, Mass Storage, Hub, Smart Card, Video, Audio/Video, or
Wireless-Controller (0x01/0x03/0x08/0x09/0x0B/0x0E/0x10/0xE0) always fails
with `SecurityError`, and a small list of known security-key
`(vendorId, productId)` pairs (ported from Chromium's own
`usb_blocklist.cc`) can never be opened at all — see `hardening.rs` for the
full table and reasoning. This is the layer that actually matters for
keeping WebUSB from becoming "any web page that convinces someone to click
Connect can read their keyboard/security key/hard drive"; the blocklist is
explicitly a second, narrower layer on top of it, not the load-bearing one.

The chooser window itself (`chooser.rs`) adds a fourth, narrower mechanism
just for its own three internal commands
(`chooser_list_candidates`/`chooser_select`/`chooser_cancel`): those check
the *calling window's own label* against whichever chooser session is
currently active, rather than relying on origin or capability at all — see
that file's module doc comment for why a page cannot reach those commands
just by having the `"webusb:default"` capability, even though they're
nominally reachable through the same permission set the chooser window
itself uses.

## Known limitations

Read this before relying on tauri-webusb for anything hardware-critical.

- **Isochronous transfers are not implemented.** `isochronousTransferIn`/
  `Out` run full validation (endpoint exists and is actually isochronous,
  `packetLengths` is well-formed and within size limits) and then reject
  with `NotSupportedError`. This plugin's backend, `nusb`, has no
  isochronous transfer support to call into as of this writing
  ([nusb#47](https://github.com/kevinmehall/nusb/issues/47)); see the table
  above for why an unsafe hand-rolled libusb-FFI path was deliberately not
  attempted instead.
- **Babble (data overflow) is not distinguished from a generic transfer
  failure.** `nusb::transfer::TransferError` currently has no dedicated
  variant for it (only `Cancelled | Stall | Disconnected | Fault |
  InvalidArgument | Unknown`), unlike the `LIBUSB_ERROR_OVERFLOW` both
  predecessors could detect through `pyusb`/libusb. A real babble condition
  surfaces as a rejected promise rather than a resolved
  `{status: "babble"}`. `stall` itself *is* correctly detected and resolved.
- **Device identity for hotplug/grants is `(vendorId, productId)`, not a
  specific physical unit.** Two simultaneously-connected identical devices
  are indistinguishable to the grant system and the hotplug watcher — both
  predecessors have the same simplification for the same reason (no serial
  number to key off unless the device happens to report one, and
  `USBDeviceFilter.serialNumber` filtering still works fine for a page that
  wants to disambiguate on its own).
- **`USBDevice.forget()` requires the device to currently be open.** Real
  Chrome's `forget()` works regardless of open state; this plugin's backend
  currently keys the revoke off a live session handle for implementation
  simplicity, and raises a clear `InvalidStateError` (pointing at the
  trusted-management API's `revokeOriginGrant` as the workaround) rather
  than silently doing nothing. See `USBDevice.forget()` in
  `guest-js/src/polyfill.ts`.
- **One device chooser at a time, globally**, not per-origin/per-window —
  matches both predecessors' practical single-native-dialog constraint. A
  second concurrent `requestDevice()` call anywhere in the app gets
  `InvalidStateError` immediately.
- **No auto-revoke when an origin's last window closes.** Both
  predecessors' browser-hosted models had a natural "tab closed" signal to
  hook; a Tauri app's window lifecycle doesn't map onto that as cleanly
  (an app might legitimately want a grant to outlive a window it happens to
  close), so v0.0.0 leaves revocation entirely to explicit `forget()` calls
  and the trusted management API.
- **Hotplug detection polls** (every 1.5s) rather than using `nusb`'s native
  watch-devices stream — a deliberate choice for this version; see
  `hotplug.rs`'s module doc comment for why (the same verification
  constraint described below applied to committing to that stream API's
  exact shape).
- **The `Function.prototype.toString` spoofing from `fox-webusb` v0.0.0a0's
  devtools-resistance work was not ported.** This version's classes *are*
  real `EventTarget`/`Event` subclasses with private fields (the part that
  matters for real-world feature-detection compatibility) but a
  `.toString()` on one of their methods will show real source, not
  `"[native code]"`. See `guest-js/src/polyfill.ts`'s header comment for the
  reasoning — mainly that it matters much less for a Tauri app's own
  bundled frontend (which already knows it depends on this package) than it
  did for a browser extension injecting into arbitrary third-party pages.

## Development environment

This crate was written in a sandboxed environment with **no access to
`rustup`** — only whatever `apt` provides, which on the Ubuntu base image
used here is **`rustc`/`cargo` 1.75.0**. `nusb` requires Rust 1.79+, and
current `tauri` requires newer still. That means the `nusb`/`tauri`-facing
code (`bridge.rs`, `chooser.rs`, `hotplug.rs`, `lib.rs`, `commands.rs`,
`state.rs`) **could not be compiled in the environment it was written in.**
Their exact API call shapes are based on `nusb` 0.2.x's published
documentation and real downstream usage (`probe-rs`, `rockusb`) as read at
the time of writing, cited inline wherever a specific shape mattered — see
in particular the header comment on `bridge.rs`, which flags the two or
three specific functions most likely to need a small adjustment against
whatever `nusb` version your `Cargo.lock` actually resolves.

This is the same category of honesty both predecessor projects modeled for
their own respective gaps (real hardware, for both; a few Windows-specific
native-messaging behaviors for `fox-webusb`, until real-machine testing
feedback came in for its v0.0.0a0) — flagged clearly rather than glossed
over, in the same place a reader would actually need it.

### What's tested where

- `error.rs`, `models.rs`, `hardening.rs`, `origin.rs`, `settings_logic.rs`
  — no `nusb`/`tauri` dependency at all. **90 unit tests, compiled and run
  for real** against the sandbox's 1.75.0 toolchain (7 + 6 + 43 + 11 + 23,
  respectively). This is the entire security-decision surface of the plugin
  (protected classes, blocklist, filter matching, transfer-size policy,
  origin derivation, grant bookkeeping) plus the DOMException taxonomy —
  the parts where a mistake would be a real vulnerability, not just a bug.
- `settings_store.rs` — its two file-only functions (`load_or_default`,
  `persist`; the atomic write-temp-then-rename logic) have no `tauri`
  dependency, unlike the rest of that file. Verified by extracting a
  byte-for-byte copy into the same sandboxed toolchain as the rest of this
  list — 5 tests, real temp-directory reads/writes/renames, all passing.
  That extraction step is not a formality: it caught a real bug on the
  first attempt (`load_or_default`'s corrupt-JSON fallback used `map_err`
  where it needed `unwrap_or_else`, which type-checked into nonsense —
  `Result<SettingsData, SettingsData>` — the moment a real compiler looked
  at it). Only `SettingsStore::init`'s use of a live `AppHandle` remains
  untested here.
- `bridge.rs`, `chooser.rs`, `hotplug.rs` — the pure helper functions with no
  `nusb`/Tauri type in their signature (packet-size rounding, the
  Gregorian-date formatter behind timestamp generation, the chooser
  window-label hashing, the hotplug add/remove diffing algorithm,
  endpoint-address bit math) are extracted and unit tested the same way —
  17 tests (5 + 5 + 7); the surrounding `nusb`/`tauri`-calling code around
  them is not, for the reason above.
- **112 Rust tests total**, all passing, none skipped.
- `guest-js/src/polyfill.ts` and `index.ts` — **type-checks cleanly under
  strict TypeScript** (`strict`, `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`, `noUnusedLocals`/`Parameters`) against real
  `@tauri-apps/api` 2.x type definitions. The error-mapping logic
  (`throwFromRpcError`, the `KNOWN_ERROR_PREFIXES` list) additionally has a
  real, executable test suite (`guest-js/src/__tests__/error.test.ts`, run
  with Node's built-in test runner — no mocking needed, since that logic
  takes a plain string in and throws a `DOMException`, nothing more). The
  RPC-calling methods themselves (`open`, `transferIn`, etc.) are not
  covered by an automated test here, since meaningfully exercising them
  needs either a live Tauri IPC layer or a hand-rolled mock of
  `@tauri-apps/api`'s `invoke`/`listen` — noted as a natural follow-up
  rather than attempted partially.
- Nothing in this plugin has been run against real USB hardware, or inside
  an actual compiled Tauri application, by the author.

## License

MIT. See `LICENSE`, including its notes on the relationship to
pyside6-webusb and fox-webusb.
