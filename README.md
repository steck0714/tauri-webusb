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

**Status: v0.0.0.** Please read "Known limitations" below before depending on
this for anything that touches real hardware — several things here are
architecturally complete but haven't been exercised against a real device
(see "Development environment" for exactly why, and exactly what *has* been
verified). This revision is a security-hardening pass over the initial
v0.0.0 (see "Security" below) — the version number is unchanged because
nothing about the public API or supported feature set changed, only what's
underneath it.

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

**Tracking pyside6-webusb forward again, past this same version-skew trap.**
The comparison above reflects tauri-webusb's *original* port, against
pyside6-webusb v0.0.4b2. This revision re-ran the same exercise against
pyside6-webusb v0.0.5.post5 (released after a security audit of that exact
v0.0.4b2 snapshot — `security_report/VULNERABILITY_REPORT.md` in that
project — and the six-finding fix that followed it) specifically because
tauri-webusb's original port necessarily predates both the audit and its
fixes. See "Security" below for the finding-by-finding result: this crate's
`hardening.rs`/`bridge.rs` design shares enough of its reasoning with
pyside6-webusb's that two of the six findings applied here too (one of them
in a more severe form, since `nusb`'s API shape opens a simpler version of
the same bypass than `pyusb`'s did), one was already independently correct
here for an architectural reason specific to Tauri, and the rest don't
translate (Python-dynamic-typing-specific, or superseded by this crate's own
equivalent already being stricter).

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

**5. A short-lived, single-use gesture token**, specifically for
`requestDevice()`. `guest-js/src/polyfill.ts` checks
`navigator.userActivation.isActive` before doing anything else, but that
check alone runs in the page's own JS context and so cannot be the real
enforcement point — see `gesture.rs`'s module doc comment for the full
reasoning, and "Security" below for the finding this closes.

## Security

This crate's `hardening.rs`/`bridge.rs` design was ported from pyside6-webusb
back when that project was at v0.0.4b2 — before
`security_report/VULNERABILITY_REPORT.md`'s security audit of that exact
version, and before the six-finding fix that followed it in v0.0.4b3. This
revision closes that gap: every finding was checked against this crate's own
code (not assumed fixed just because it shares a design), and where an
analogous — or, in two cases, more severe — issue existed here, it's fixed
below. Ported fixes are cited inline at their exact location (search for
`security_report` in `src/`); this section is the index.

| # | Finding | Status in this revision |
|---|---|---|
| 1 | **Protected-interface-class bypass.** Control transfers with `recipient: 'interface'`/`'endpoint'` never checked whether the targeted interface/endpoint was actually claimed or protected — `nusb::Interface::control_in`/`_out` accept *any* `recipient`/`index` regardless of which claimed interface issues the call, on every platform but Windows. Independently, `transferIn`/`Out`/`clearHalt` resolved *some* claimed interface to act as a vehicle rather than the *specific* one owning the target endpoint. Both were a complete `claimInterface()` bypass — worse here than the finding pyside6-webusb's audit describes, since no alternate-setting trickery was even needed. | Fixed: `hardening::resolve_control_transfer_target`/`resolve_transfer_endpoint_owner`, used by `bridge.rs`'s `control_transfer_in`/`_out`/`transfer_in`/`_out`/`clear_halt`. `select_alternate_interface` also independently re-checks the target alternate's class now, alongside `claim_interface`'s own (more conservative) check. |
| 2 | **`requestDevice()` had no server-side proof of a user gesture.** `guest-js/src/polyfill.ts` checked `navigator.userActivation.isActive` client-side only — bypassable by any script with IPC access, same as any other command. Filter-shape validation was already server-side from the start. | Fixed: `gesture.rs`'s mint/consume token, required by `commands::request_device`. See that module's doc comment for exactly what this does and doesn't guarantee. |
| 3 | **Device-supplied strings (name, manufacturer, serial) reached the chooser UI unsanitized** — a malicious device could use bidi-override characters to visually spoof its own displayed identity, and nothing bounded string length. `chooser-ui/index.html` already used `textContent` exclusively (no markup-injection angle to begin with, unlike a native rich-text label), but the spoofing and unbounded-length issues were real. | Fixed: `hardening::sanitize_device_string`, applied in `bridge.rs`'s descriptor-building functions — once, at the source, so every consumer benefits. |
| 4 | **`close()` on an invalid handle didn't return a clean error.** Python-specific (a dynamically-typed return value breaking the "always valid JSON" contract) — Rust's type system makes this class of bug structurally impossible. | N/A here (free from switching languages) — see finding 4's continuation below for a related fix made anyway. |
| 5 | **Hotplug events could reach the wrong origin.** pyside6-webusb's Qt signal model broadcasts based on the top-level page only, regardless of which frame actually receives it. | Was already correct here: `hotplug.rs`'s `notify()` checks each *webview's own* current origin before emitting — see that function and `origin.rs`'s module doc comment (including why a cross-origin `<iframe>` isn't the gap here that it historically was for Tauri itself — [CVE-2024-35222](https://github.com/tauri-apps/tauri/security/advisories/GHSA-57fm-592m-34r7)). |
| 6 | **No cap on concurrently open handles per origin** — unbounded `device.open()` calls could grow memory in the host app's own process indefinitely. | Fixed: `hardening::MAX_OPEN_HANDLES_PER_ORIGIN`, enforced (with oldest-handle eviction, not rejection) in `bridge::open_device`. |

Additionally, ported from pyside6-webusb v0.0.5.post5 (its *own* most recent
hardening, past the audit above): the WebUSB-spec allowed-standard-request
list for control transfers (`hardening::is_allowed_standard_control_request`);
bounds on `filters`/`exclusionFilters` array length, base64 payload length
before decoding, and `packetLengths` array length
(`hardening::MAX_DEVICE_FILTERS`/`MAX_BASE64_PAYLOAD_CHARS`/
`MAX_ISOCHRONOUS_PACKETS`) — resource-exhaustion defenses with no single
finding number, described in that project's changelog as "hardened options
and base64 payload boundaries."

This crate's own review, independent of anything in the reference project,
also found and fixed: a `close()`-adjacent cross-origin existence leak (guessable
sequential handle IDs let a script distinguish "some other origin has this
handle open" from "no such handle" — see `bridge::close_device`'s doc
comment); silently-discarded settings-persistence errors on the grant/revoke
paths (`commands.rs`, `bridge::open_device`/`forget_device` now propagate
`SettingsStore::mutate`'s `Result` instead of dropping it); and a
`ChooserRegistry` reference held across an FFI-adjacent boundary via a raw
pointer cast, replaced with a plain `Arc` clone (see `chooser.rs`).

## Known limitations

Read this before relying on tauri-webusb for anything hardware-critical.

- **The gesture-token check (`gesture.rs`) proves a script completed one
  authenticated round trip, not that a human clicked anything.** A
  sufficiently determined scripted attacker with IPC access could mint its
  own token the same way `polyfill.ts` does, then call `requestDevice()`
  directly. This raises the bar substantially over no check at all without
  being a perfect guarantee — the same documented caveat pyside6-webusb
  states for the identical limitation, which stems from neither this
  plugin nor that one having a way to directly observe a page's real DOM
  `UserActivation` state from the host process.
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

This crate is being developed in a sandboxed environment with **no access to
`rustup`** — only whatever `apt` provides, which on the Ubuntu base image used
here is **`rustc`/`cargo` 1.75.0**. `nusb` requires Rust 1.85+ as of 0.2.6
(bumped from 1.79 in August 2026 — re-checked directly against
[index.crates.io](https://index.crates.io/) for this revision, not assumed
stale from when this crate's first version was written), and `tauri` 2.x
moves independently on its own "roughly three stable releases behind current"
policy. That means `cargo build`/`test` against the *real* `nusb`/`tauri`
crates **still isn't possible in this environment** — see `Cargo.toml`'s
`rust-version` note for exactly what was re-checked and how.

What changed in this revision: rather than leaving the `nusb`/`tauri`-facing
code (`bridge.rs`, `chooser.rs`, `hotplug.rs`, `lib.rs`, `commands.rs`,
`settings_store.rs`) unverified beyond "read carefully," this pass downloaded
the exact real crate source for both (`static.crates.io`'s and GitHub's own
hosting are reachable even where the toolchain to *use* them isn't) and built
minimal stand-in crates — matching real signatures, module paths, and trait
shapes, not just plausible-looking ones — literally named `nusb` and `tauri`
so every module could be compiled against them, unmodified, as a genuine
`cargo build`. This is not the same as testing against the real crates (a
stand-in's *behavior* is fake; only its *shape* is real), but it exercises
something a careful read cannot: actual type-checking and borrow-checking of
every line in every file, including the parts a human reviewer's eyes tend to
slide past. It found four real, independently-confirmed defects that had
never been caught before, described where they're fixed rather than repeated
here: a wrong module path for an enum a match statement depended on
(`bridge.rs`, corrected against real `nusb` 0.2.7 source), a borrow-checker
conflict in the per-handle operation lock that would have failed to compile
as originally written (`bridge.rs`'s `OpenSession::op_lock`, now `Arc`-wrapped
with the reasoning inline), a stray doc-comment typo that would have failed
to compile as its own, separate error (`chooser.rs`, a single `///` where
`//!` was meant, mid-block), and a type mismatch between a declared
`(u32, u32)` physical-device-identity tuple and the plain `u32` the code
actually built (`hotplug.rs`). It also caught a test with a correct
implementation but an incorrect hand-computed expected value
(`bridge.rs::civil_from_days_known_date`, off by one day — verified
independently against Python's own `datetime` module) and a broken `npm test`
invocation (`guest-js/package.json` — `node --test <dir>/` silently resolves
zero tests on this Node version; an explicit glob does not).

This is the same category of honesty both predecessor projects modeled for
their own respective gaps (real hardware, for both; a few Windows-specific
native-messaging behaviors for `fox-webusb`, until real-machine testing
feedback came in for its v0.0.0a0) — flagged clearly rather than glossed
over, in the same place a reader would actually need it. It remains true that
**nothing here has been run against real USB hardware, or inside an actual
compiled Tauri application** — a stand-in crate that type-checks correctly is
still not a substitute for that, only a substantially stronger floor under
it than "compiled in the author's head."

### What's tested where

- `error.rs`, `models.rs`, `hardening.rs`, `origin.rs`, `settings_logic.rs`,
  `gesture.rs` — no `nusb`/`tauri` dependency at all (`gesture.rs` needs only
  `tokio`, whose own MSRV is comfortably under this sandbox's 1.75.0, and the
  `getrandom` crate, which — unusually for a crate `tauri-webusb` depends on —
  declares no `rust-version` at all as of the 0.2.x line it's pinned to).
  **153 unit tests, compiled and run for real** against the sandbox's 1.75.0
  toolchain. This is the entire security-decision surface of the plugin
  (protected classes, blocklist, filter matching, transfer-size policy,
  control-transfer and bulk/interrupt-transfer target resolution, origin
  derivation, grant bookkeeping, gesture-token issuance/consumption) plus the
  `DOMException` taxonomy — the parts where a mistake is a real
  vulnerability, not just a bug. Includes a direct reproduction of the
  composite-device alternate-setting-confusion scenario from
  `security_report/VULNERABILITY_REPORT.md` finding No.1, confirming the fix
  actually closes it (`hardening.rs`'s
  `control_transfer_endpoint_recipient_rejects_the_hidden_hid_endpoint` and
  neighboring tests).
- `bridge.rs`, `chooser.rs`, `hotplug.rs`, `commands.rs`, `lib.rs`,
  `settings_store.rs` — the `nusb`/`tauri`-dependent code. **Compiles cleanly
  (zero errors, zero warnings) against real-shaped stand-in crates** built
  for this revision from the actual published `nusb` 0.2.7 and current
  `tauri` v2 API surface — see "Development environment" above for what that
  did and didn't catch. `settings_store.rs`'s two file-only functions
  (`load_or_default`, `persist`) additionally have real, executable tests (5)
  that need no stand-in at all, since neither touches `tauri::AppHandle`.
- `guest-js/src/polyfill.ts` and `index.ts` — **type-checks cleanly under
  strict TypeScript** (`strict`, `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`, `noUnusedLocals`/`Parameters`) against real
  `@tauri-apps/api` 2.x type definitions. The error-mapping logic
  (`throwFromRpcError`, the `KNOWN_ERROR_PREFIXES` list) additionally has a
  real, executable test suite (`guest-js/src/__tests__/error.test.ts`, 12
  tests, run with Node's built-in test runner — no mocking needed, since that
  logic takes a plain string in and throws a `DOMException`, nothing more).
  The RPC-calling methods themselves (`open`, `transferIn`, etc.) are not
  covered by an automated test here, since meaningfully exercising them needs
  either a live Tauri IPC layer or a hand-rolled mock of `@tauri-apps/api`'s
  `invoke`/`listen` — noted as a natural follow-up rather than attempted
  partially.

## License

MIT. See `LICENSE`, including its notes on the relationship to
pyside6-webusb and fox-webusb.
