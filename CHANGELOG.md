# Changelog

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
