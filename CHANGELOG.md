# Changelog

## [0.0.0] — security-hardening pass (unreleased revision)

Not a new version number: the public API and feature set are unchanged, only
what's underneath. This revision re-verified tauri-webusb's original port
against a newer snapshot of its own reference project
(`pyside6-webusb`, now tracked through v0.0.5.post5 rather than v0.0.4b2 — see
README.md's "Relationship to prior art"), specifically because that newer
snapshot includes a security audit
(`security_report/VULNERABILITY_REPORT.md`) and fix cycle that postdates
tauri-webusb's original port entirely. It also builds and type-checks
essentially the whole crate for the first time, against real-shaped stand-in
`nusb`/`tauri` crates built for this pass (see README.md's "Development
environment") — the original port could not do this at all, for either
crate, in the sandbox it was written in.

### Security

Full detail and inline citations in README.md's "Security" section and at
each fix site (search `src/` for `security_report`). Summary:

- **Fixed — control-transfer interface/endpoint bypass**
  (`hardening::resolve_control_transfer_target`, `bridge.rs`'s
  `control_transfer_in`/`_out`). Neither `recipient: 'interface'` nor
  `'endpoint'` control transfers checked that the targeted interface/endpoint
  was claimed or unprotected — `nusb`'s own `control_in`/`_out` accept any
  `recipient`/`index` regardless of which claimed interface issues the call,
  on every platform but Windows. A page could `claimInterface()` any single
  benign interface, then send a `class`/`vendor` control transfer naming a
  *different*, unclaimed, protected interface (HID, Mass Storage, ...) —
  a complete bypass, and a simpler one to trigger than the alternate-
  setting-confusion scenario `security_report/VULNERABILITY_REPORT.md`
  finding No.1 describes for the reference project.
- **Fixed — bulk/interrupt/clearHalt interface resolution**
  (`hardening::resolve_transfer_endpoint_owner`, `bridge.rs`'s
  `resolve_transfer_endpoint`). `transferIn`/`Out`/`clearHalt` resolved
  *some* claimed interface as a vehicle rather than the specific one owning
  the target endpoint — accidentally non-exploitable only because `nusb`'s
  own `Interface::endpoint()` happens to re-scope to whichever interface
  object it's called on, but a real functional bug for any device with more
  than one simultaneously claimed interface, and fragile defense-in-depth to
  rely on regardless.
- **Fixed — `selectAlternateInterface()` had no protected-class check of its
  own** (`bridge.rs`), relying entirely on `claimInterface()`'s own
  (already-conservative) check never having let a protected interface be
  claimed in the first place. Still safe before this fix, given that
  invariant, but a fragile, implicit one; now independently checked too.
- **Added — `requestDevice()` gesture-token requirement** (`gesture.rs`,
  new; wired into `commands::request_device`), closing
  `security_report/VULNERABILITY_REPORT.md` finding No.2's user-gesture half
  (the filter-validity half was already enforced server-side from the
  start). `guest-js/src/polyfill.ts`'s `requestDevice()` now mints a token
  immediately after confirming `navigator.userActivation.isActive`, and
  `request_device` requires and consumes it before ever showing the chooser.
- **Added — device-supplied string sanitization**
  (`hardening::sanitize_device_string`, applied in `bridge.rs`'s descriptor
  builders), closing finding No.3: manufacturer/product/serial/
  configuration/interface-name strings — entirely under a connected device's
  control — are now stripped of C0/C1 control characters and bidi-override/
  isolate characters (spoofing defense) and length-capped, once, at the
  source.
- **Added — per-origin open-handle cap with LRU eviction**
  (`hardening::MAX_OPEN_HANDLES_PER_ORIGIN`, `bridge::open_device`), closing
  finding No.6: an origin can no longer grow this plugin's session table —
  memory in the *host app's own process* — without bound just by calling
  `device.open()` in a loop.
- **Added — WebUSB-spec standard-request allowlist for control transfers**
  (`hardening::is_allowed_standard_control_request`) and **resource-
  exhaustion bounds** on `filters`/`exclusionFilters` array length, base64
  payload length (checked before decoding, not just after), and
  `packetLengths` array length (`hardening::MAX_DEVICE_FILTERS`/
  `MAX_BASE64_PAYLOAD_CHARS`/`MAX_ISOCHRONOUS_PACKETS`) — ported from
  pyside6-webusb v0.0.5.post5's own later hardening pass, past the audit
  above.
- **Added — endpoint-number range validation**
  (`hardening::is_valid_transfer_endpoint_number`), matching real Chrome's
  `USBDevice::EnsureEndpointAvailable()`: `transferIn`/`Out`/`clearHalt` now
  reject endpoint `0` and anything above `15` with `IndexSizeError` before
  attempting to resolve it, rather than only implicitly via "no such
  endpoint" during resolution.
- **Fixed — `close()` cross-origin existence leak** (`bridge::close_device`):
  previously returned a different, distinguishable outcome for "handle
  belongs to a different origin" (`Err`) versus "handle never existed"
  (`Ok`) — small but real, since handle IDs are small, guessable, sequential
  integers reachable from any script with IPC access. Now uniformly `Ok(())`
  in both cases; only actually removes the session when the origin matches.
- **Fixed — silently-discarded settings-persistence errors**
  (`commands.rs`'s `revoke_origin_grant`/`revoke_all_for_origin`/
  `forget_known_device`/`forget_all_known_devices`, `bridge.rs`'s
  `open_device`/`forget_device`). Four of these were an outright compile
  error (`Ok(a_Result<T,_>_value)`, doubly-wrapping the `Result`) that had
  never been caught since this file could not previously be compiled at
  all; the other two silently discarded `SettingsStore::mutate`'s own
  `Result`, meaning a disk-write failure during a grant/revoke would report
  success to the page while never actually persisting.
- **Added — new WebUSB spec compatibility: serial-number-based `open()`
  disambiguation and `window.USB`/`USBDevice`/`USBConnectionEvent`
  exposure**, ported from pyside6-webusb v0.0.5.post5. `USBDevice.open()`
  now passes its own already-known `serialNumber` through transparently
  (page code calls it exactly as before — real `USBDevice.open()` takes no
  arguments per spec) so multiple simultaneously-connected devices sharing
  one vendor/product ID pair no longer collapse onto "whichever happens to
  enumerate first."

### Fixed (found independently, not from the reference project)

- A wrong module path in a `match` (`nusb::transfer::EndpointType::Bulk`,
  which does not exist — `EndpointType` there is a type-level marker trait
  with no variants at all; the real enum is `nusb::descriptors::TransferType`)
  — would not have compiled against the real crate, corrected against its
  actual downloaded source (`bridge.rs`).
- A borrow-checker conflict in the per-handle operation lock
  (`OpenSession::op_lock`) that would not have compiled as originally
  written — a held `MutexGuard` borrowed from `session.op_lock` conflicted
  with the `&mut OpenSession` needed immediately after; now `Arc`-wrapped so
  the guard is taken from a cloned, independent handle (`bridge.rs`).
- A stray `///` in the middle of a `//!`-style module doc comment block —
  its own, separate compile error, unrelated to the two above
  (`chooser.rs`).
- `hotplug.rs`'s `PhysicalDeviceId` was declared as a `(u32, u32)` tuple, but
  the code that built one always produced a plain `u32`
  (`vendorId << 16 | productId`) — a compile error; the type now matches
  what's actually built, with a doc comment on the real fix (real bus/
  address identity) this stands in for.
- `bridge.rs`'s own `civil_from_days_known_date` test had a correct
  algorithm (Howard Hinnant's `civil_from_days`) but an incorrect
  hand-computed expected value, off by one day — verified independently
  against Python's `datetime` module and corrected.
- An unused `Manager` import (`chooser.rs`) and a `close_device`/
  `revoke_origin_grant`-adjacent set of clippy-would-have-caught issues,
  cleaned up as part of getting the crate to compile warning-free against
  the stand-in crates.
- `guest-js/package.json`'s `test` script (`node --test dist-js/__tests__/`)
  silently discovered and ran *zero* tests on the Node version used here —
  a bare directory argument is not recursively globbed for `*.test.js`
  files the way a bare (argument-less) invocation is. Replaced with an
  explicit glob (`node --test "dist-js/**/*.test.js"`), confirmed to
  actually run all 12 tests.
- A `ChooserRegistry` reference held across `on_window_event`'s `'static`
  closure boundary via a raw pointer cast (`chooser as *const ChooserRegistry
  as usize`, reconstructed with `unsafe` inside the closure) — safe in
  practice given Tauri's managed-state lifetime, but resting on an implicit,
  undocumented-in-the-type-system invariant. Replaced with an ordinary `Arc`
  clone (`WebUsbState.chooser` is now `Arc<ChooserRegistry>`), removing the
  `unsafe` block entirely.

### Changed

- `Cargo.toml`'s `rust-version` raised from `1.79` to `1.85`, re-verified
  directly against `nusb`'s and (transitively, via `url` → `idna_adapter`)
  `edition2024`'s actual current MSRV rather than left at the value that was
  accurate when the crate was first written — see that file's comment for
  the exact sources checked.
- `origin.rs` gained an explicit citation
  ([CVE-2024-35222](https://github.com/tauri-apps/tauri/security/advisories/GHSA-57fm-592m-34r7))
  for why a cross-origin `<iframe>` isn't the gap for Tauri that per-frame
  origin tracking closes for `pyside6-webusb` — previously asserted without
  showing the reasoning.

### Added (verification infrastructure, not shipped in the crate)

- 41 new Rust unit tests (112 → 153): direct coverage of
  `resolve_control_transfer_target`/`resolve_transfer_endpoint_owner`
  (including a reproduction of finding No.1's exact composite-device
  scenario), `sanitize_device_string`, the new standard-request/bounds
  checks, and `gesture.rs`'s mint/consume/eviction/expiry logic (the last of
  these run for real with `#[tokio::test]`, since `tokio` alone — unlike
  `nusb`/`tauri` — compiles fine under this sandbox's rustc).
- The entire `nusb`/`tauri`-dependent surface (`bridge.rs`, `chooser.rs`,
  `hotplug.rs`, `commands.rs`, `lib.rs`, `settings_store.rs`) now compiles
  cleanly, for the first time, against minimal stand-in `nusb`/`tauri`
  crates built from the real published API shape for this pass — see
  README.md's "Development environment" for what that is and isn't
  equivalent to.

## [0.0.0] — initial port

Initial release: a Tauri v2 plugin porting the WebUSB API to Tauri desktop
apps. Written with the full source of both `pyside6-webusb` (through
v0.0.4b2) and `fox-webusb` (through v0.0.0a0) available as reference —
see `README.md`'s "Relationship to prior art" for the specifics of what was
carried forward from which, including three cases where those two projects
had diverged and this one had to pick a side rather than just port whichever
looked most reusable.

### Added

- `navigator.usb` polyfill (`guest-js/`): `USB` (extends `EventTarget`),
  `USBDevice`, `USBConfiguration`, `USBInterface`, `USBAlternateInterface`,
  `USBEndpoint`, `USBConnectionEvent` (extends `Event`), and all four
  transfer-result shapes, as real ES2022 classes with private (`#`) fields
  and `Symbol.toStringTag` — following `fox-webusb` v0.0.0a0's devtools-
  resistant class design rather than a plain-object polyfill.
- Rust plugin backend (`src/`), using `nusb` for device access:
  - `hardening.rs` — the WebUSB security model: 8 protected interface
    classes, a ~35-entry security-key blocklist ported from Chromium's
    `usb_blocklist.cc`, WebUSB spec-faithful `USBDeviceFilter` matching,
    and pyside6-webusb v0.0.4b2's transfer-size policy (32 MiB Chrome-
    reference warning threshold, 512 MiB host-safety hard ceiling).
  - `error.rs` — a 7-entry `DOMException` taxonomy: the union of
    `fox-webusb`'s 5, `pyside6-webusb` v0.0.4b2's `DataError` addition, and
    a `NotSupportedError` recognition gap this project's own cross-
    referencing of both predecessors found and fixed (see `error.rs`'s
    module doc comment for the full account).
  - `origin.rs` — derives a calling webview's origin from
    `tauri::Webview::url()`, Tauri's own core-tracked, unspoofable
    navigation state — the direct analogue of `sender.url` in the
    WebExtensions API (`fox-webusb`'s approach) rather than
    `pyside6-webusb`'s hand-rolled per-frame token scheme, which Tauri
    turns out not to need either.
  - `settings_store.rs` / `settings_logic.rs` — persistent per-origin
    device grants and a known-devices history, as an atomically-written
    (write-temp-file-then-rename) JSON file under the app's own config
    directory.
  - `bridge.rs` — the session manager: enumeration, open/close, configuration
    /interface/alternate-setting lifecycle, control/bulk/interrupt
    transfers. Reconciles `nusb`'s requirement that IN-transfer buffers be
    an exact multiple of the endpoint's max packet size with WebUSB's
    arbitrary-length `transferIn(endpointNumber, length)` by rounding the
    submitted buffer up and truncating the result back down to at most what
    was asked for.
  - `chooser.rs` — the `requestDevice()` picker, as a dedicated
    `WebviewWindow` (a `data:` URL, self-contained HTML/CSS/JS compiled
    into the plugin binary) with a live-refreshing device list. Its three
    internal commands are gated by the *calling window's own label*
    matching the active chooser session, rather than by origin or
    capability — closing what would otherwise be a passive-fingerprinting
    hole (a page invoking the chooser's own list-candidates command
    directly, with arbitrary filters, without ever triggering a
    `requestDevice()` call or showing any UI).
  - `hotplug.rs` — polls for device connect/disconnect and fans out
    `USBConnectionEvent`s only to webviews whose *current* origin
    (re-checked live via the same `origin.rs` mechanism on every tick, so a
    navigated-away webview automatically stops matching with no explicit
    unregistration needed) holds a grant for that specific device.
- Two-tier Tauri capability/permission model (`permissions/`): a `default`/
  `page` set for the page-facing WebUSB surface, and a separate `manage` set
  for trusted origin/device administration
  (`listGrantedOrigins`/`revokeOriginGrant`/`revokeAllForOrigin`/
  `listKnownDevices`/`forgetKnownDevice`/`forgetAllKnownDevices`) — the
  Tauri-native structural replacement for both predecessors' hand-rolled
  trusted-sender checks (enforced by Tauri's core before a command handler
  runs, rather than inside one shared dispatcher).
- `types/webusb-polyfill.d.ts` — standalone global type declarations for
  editor/TypeScript support on page code that never explicitly imports the
  guest-js package, carrying forward `fox-webusb` v0.0.0a0's fix for
  `USBIsochronousInTransferResult.packets`' type (it must use the
  `USBIsochronousInTransferPacket` interface it declares, not a bespoke
  `{length, status}` shape that silently drops each packet's own data).
- 112 Rust unit tests total — 90 across `error`/`models`/`hardening`/
  `origin`/`settings_logic` (the entire `nusb`/`tauri`-independent security
  and data-model surface), plus 22 more across extracted, byte-for-byte
  copies of the pure helper functions inside `bridge.rs` (5),
  `settings_store.rs`'s file persistence logic (5 — this extraction step
  caught a real bug, a `map_err`/`unwrap_or_else` mix-up in the corrupt-JSON
  fallback path, on its first compile attempt), and `chooser.rs`/
  `hotplug.rs`'s pure helpers (12) — all verified the same way, since those
  files' `tauri`/`nusb` imports otherwise block compiling any of them in
  this sandbox (see README.md's "Development environment"). Plus a
  TypeScript test suite for the error-mapping logic
  (`guest-js/src/__tests__/error.test.ts`). All passing.

### Known limitations (see README.md for full detail)

- Isochronous transfers are not implemented (`nusb` has no isochronous
  support as of this writing); full validation runs regardless, ending in a
  clear `NotSupportedError` rather than an incorrect result.
- Babble (data-overflow) transfer status is not distinguished from a
  generic transfer failure — `nusb`'s error enum has no dedicated variant
  for it.
- Device identity for grants and hotplug is `(vendorId, productId)`, not a
  specific physical unit (matches both predecessors' own simplification).
- `USBDevice.forget()` requires the device to currently be open.
- One device chooser at a time, globally.
- No auto-revoke when an origin's last window closes.
- Hotplug detection polls every 1.5s rather than using `nusb`'s native
  watch-devices stream.
- The `nusb`/`tauri`-facing Rust code could not be compiled in the sandboxed
  environment this was written in (capped at rustc 1.75.0 via `apt`, no
  `rustup`; `nusb` needs 1.79+) — see README.md's "Development environment"
  for exactly which functions carry the most API-shape uncertainty as a
  result, and exactly what *was* compiled and tested there regardless.
