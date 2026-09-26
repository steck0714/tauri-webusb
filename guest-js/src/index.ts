// index.ts
// ========
// Public entry point. Two ways to use this package:
//
// 1. **Automatic** (recommended, matches both predecessors' "polyfill"
//    framing — page code should not need to change at all): this plugin's
//    Rust side registers this bundle's compiled output as a Tauri webview
//    initialization script (`Builder::js_init_script`), so `navigator.usb`
//    already exists before any of the app's own page JS runs. Nothing to
//    import.
// 2. **Manual**: `import { installWebUsbPolyfill } from "tauri-plugin-webusb-api"`
//    and call it yourself — useful if the automatic init script is disabled,
//    or from a test harness that wants to control exactly when it happens.
//
// Either path calls the same `installWebUsbPolyfill()` below.

import { USB, USBDevice, USBConnectionEvent } from "./polyfill.js";

export {
  USB,
  USBDevice,
  USBConfiguration,
  USBInterface,
  USBAlternateInterface,
  USBEndpoint,
  USBConnectionEvent,
  USBInTransferResult,
  USBOutTransferResult,
  USBIsochronousInTransferPacket,
  USBIsochronousInTransferResult,
  USBIsochronousOutTransferPacket,
  USBIsochronousOutTransferResult,
  KNOWN_ERROR_PREFIXES,
  throwFromRpcError,
} from "./polyfill.js";
export type { USBControlTransferParameters } from "./polyfill.js";

export interface InstallOptions {
  /** Overwrite an existing `navigator.usb` even if one is already present
   * (a real browser implementation, or a previous install). Default
   * `false` — see `installWebUsbPolyfill`'s doc comment on why silently
   * overwriting a real implementation would be actively harmful. */
  force?: boolean;
}

/**
 * Defines `navigator.usb` if it isn't already present. Safe to call more
 * than once (idempotent) and safe to call in a context that already has a
 * *real* WebUSB implementation — it does nothing in that case rather than
 * shadowing it, matching the principle both predecessors state explicitly:
 * this plugin exists to fill a gap in non-Chromium webviews, not to
 * override a genuine implementation a page might actually prefer (a real
 * implementation could support isochronous transfers, for instance, which
 * this version cannot — see bridge.rs's module doc comment).
 *
 * Returns `true` if it installed the polyfill, `false` if it left an
 * existing `navigator.usb` alone (or the context isn't secure — see below).
 */
export function installWebUsbPolyfill(options: InstallOptions = {}): boolean {
  if (typeof navigator === "undefined") return false;

  if (!options.force && "usb" in navigator) {
    return false;
  }

  // Matches the real spec's own restriction (`[SecureContext]` on the `USB`
  // interface) rather than a Tauri-specific choice: Tauri's own bundled
  // frontend is served over a context the webview engine treats as secure
  // (a custom `tauri://` scheme on macOS/Linux, `https://tauri.localhost`
  // on Windows — see `origin.rs`'s module doc comment), so this passes for
  // an app's own UI without any special-casing. It correctly fails for a
  // webview that's been pointed at plain `http://` remote content, exactly
  // as a real browser would refuse WebUSB there too.
  if (typeof window !== "undefined" && window.isSecureContext === false) {
    return false;
  }

  const usb = new USB();
  usb._startHotplugListeners();
  Object.defineProperty(navigator, "usb", {
    value: usb,
    writable: false,
    enumerable: true,
    configurable: true, // matches real Chrome's own navigator.usb descriptor — lets a test harness replace it
  });

  // Ported from pyside6-webusb v0.0.5.post5: some feature-detection and
  // "is WebUSB available" code in the wild checks for the *constructor*
  // (`window.USBDevice`, `"USBDevice" in window`), not only for
  // `navigator.usb` itself. A real browser exposes these as ordinary
  // `Window` properties (`[Exposed=Window] interface USBDevice`, etc. — see
  // the WebUSB IDL), so this mirrors that rather than being a Tauri- or
  // polyfill-specific addition. Each is defined independently and only if
  // genuinely absent (`in window`, not `options.force`, which only governs
  // `navigator.usb` above) — a page's own unrelated global named `USB`
  // should never be clobbered just because installing this polyfill was
  // otherwise a no-op for it.
  if (typeof window !== "undefined") {
    const globals: Record<string, unknown> = { USB, USBDevice, USBConnectionEvent };
    for (const [name, value] of Object.entries(globals)) {
      if (!(name in window)) {
        Object.defineProperty(window, name, { value, writable: true, enumerable: false, configurable: true });
      }
    }
  }

  return true;
}
