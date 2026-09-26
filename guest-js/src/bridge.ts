// bridge.ts
// =========
// Everything in this file is transport plumbing: turning a page-facing
// polyfill method call into a `plugin:webusb|...` invoke, and turning a
// Rust-side hotplug event into a callback. `polyfill.ts` is the only other
// file that imports from here, and it never imports `@tauri-apps/api`
// directly — this is the one seam between "the WebUSB shape" and "how Tauri
// IPC actually works", mirroring the same split `content_script.js` gave
// `page_polyfill.js` in both predecessors (there, the seam was
// `window.postMessage`; here, it's `invoke`/`listen`).
//
// Every RPC method below throws a plain `Error` whose `.message` is exactly
// the `"KindError: detail"` string `error.rs` produces on the Rust side —
// `polyfill.ts`'s `throwFromRpcError` is what turns that back into the
// right `DOMException`. This file does no interpretation of failures at
// all, on purpose: keeping every "what does this failure mean" decision in
// one place (`polyfill.ts`) is what let both predecessors catch the
// prefix-list gaps documented in `error.rs`'s module doc comment by
// auditing a single function, and this keeps that property.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

const PLUGIN = "webusb";

function cmd(name: string): string {
  return `plugin:${PLUGIN}|${name}`;
}

/** Rethrows Tauri's rejection as a plain `Error` carrying just the message
 * string `error.rs` produced — Tauri wraps command errors in ways that vary
 * slightly by version/platform, so this normalizes to "one string" before
 * `polyfill.ts` ever has to look at it. */
async function call<T>(name: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd(name), args);
  } catch (e) {
    const message = typeof e === "string" ? e : e instanceof Error ? e.message : String(e);
    throw new Error(message);
  }
}

// ---- base64 <-> BufferSource, matching both predecessors' wire choice ----
// See bridge.rs's module doc comment for why this plugin's Rust side also
// keeps base64 (rather than raw-byte IPC) for v0.0.0: parity with both
// prior implementations' well-exercised wire format, not a Tauri
// limitation — Tauri's IPC has no equivalent to Firefox's 1MB
// native-messaging cap that made `protocol.py`'s chunking necessary, so
// that entire layer simply doesn't exist here.

export function bufferSourceToBase64(source: BufferSource): string {
  const bytes = source instanceof ArrayBuffer ? new Uint8Array(source) : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  let binary = "";
  const chunkSize = 0x8000; // avoid a huge single call to String.fromCharCode/apply on large buffers
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

export function base64ToUint8Array(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ---- wire shapes (mirrors models.rs's camelCase serde output) ----

export interface WireEndpoint {
  endpointNumber: number;
  direction: "in" | "out";
  type: "bulk" | "interrupt" | "isochronous";
  packetSize: number;
}

export interface WireAlternateInterface {
  alternateSetting: number;
  interfaceClass: number;
  interfaceSubclass: number;
  interfaceProtocol: number;
  interfaceProtected: boolean;
  interfaceName: string | null;
  endpoints: WireEndpoint[];
}

export interface WireInterface {
  interfaceNumber: number;
  alternates: WireAlternateInterface[];
}

export interface WireConfiguration {
  configurationValue: number;
  configurationName: string | null;
  interfaces: WireInterface[];
}

export interface WireDevice {
  vendorId: number;
  productId: number;
  manufacturerName: string | null;
  productName: string | null;
  serialNumber: string | null;
  deviceClass: number;
  deviceSubclass: number;
  deviceProtocol: number;
  usbVersionMajor: number;
  usbVersionMinor: number;
  usbVersionSubminor: number;
  deviceVersionMajor: number;
  deviceVersionMinor: number;
  deviceVersionSubminor: number;
  configurations: WireConfiguration[];
  activeConfigurationValue: number | null;
  connectCount?: number;
}

export interface WireFilter {
  vendorId?: number;
  productId?: number;
  classCode?: number;
  subclassCode?: number;
  protocolCode?: number;
  serialNumber?: string;
}

export interface WireInTransferResult {
  status: "ok" | "stall" | "babble";
  data: string; // base64
  warning?: string;
}

export interface WireOutTransferResult {
  status: "ok" | "stall" | "babble";
  bytesWritten: number;
  warning?: string;
}

export interface WireIsoInPacket {
  status: "ok" | "stall" | "babble";
  data: string; // base64
}

export interface WireIsoOutPacket {
  status: "ok" | "stall" | "babble";
  bytesWritten: number;
}

export interface WireControlSetup {
  requestType: string;
  recipient: string;
  request: number;
  value: number;
  index: number;
}

export interface WireOpenResult {
  handle: number;
  descriptor: WireDevice;
}

// ---- RPCs ----

export const rpc = {
  getDevices: () => call<WireDevice[]>("get_devices"),
  /** See `polyfill.ts`'s `requestDevice()` for why this is minted and
   * consumed as its own round trip rather than a parameter derived purely
   * client-side: `hardening::GESTURE_TOKEN_TTL_SECS`'s doc comment (via
   * `gesture.rs`) explains the server-side half of the check this backs. */
  mintGestureToken: () => call<string>("mint_gesture_token"),
  requestDevice: (filters: WireFilter[], exclusionFilters: WireFilter[], gestureToken: string) =>
    call<WireDevice>("request_device", { filters, exclusionFilters, gestureToken }),
  /** `serialNumber` is `undefined` for a device that doesn't report one, or
   * for `getDevices()`-obtained devices this session never disambiguated —
   * see `polyfill.ts`'s `USBDevice.open()`, which passes its own already-known
   * `serialNumber` through automatically; page code never supplies this
   * directly (real `USBDevice.open()` takes no arguments at all, per spec). */
  open: (vendorId: number, productId: number, serialNumber?: string) => call<WireOpenResult>("open", { vendorId, productId, serialNumber }),
  close: (handle: number) => call<void>("close", { handle }),
  forget: (handle: number) => call<void>("forget", { handle }),
  selectConfiguration: (handle: number, configurationValue: number) =>
    call<void>("select_configuration", { handle, configurationValue }),
  claimInterface: (handle: number, interfaceNumber: number) => call<void>("claim_interface", { handle, interfaceNumber }),
  releaseInterface: (handle: number, interfaceNumber: number) => call<void>("release_interface", { handle, interfaceNumber }),
  selectAlternateInterface: (handle: number, interfaceNumber: number, alternateSetting: number) =>
    call<void>("select_alternate_interface", { handle, interfaceNumber, alternateSetting }),
  resetDevice: (handle: number) => call<void>("reset_device", { handle }),
  clearHalt: (handle: number, endpointNumber: number, direction: "in" | "out") =>
    call<void>("clear_halt", { handle, endpointNumber, direction }),
  controlTransferIn: (handle: number, setup: WireControlSetup, length: number) =>
    call<WireInTransferResult>("control_transfer_in", { handle, setup, length }),
  controlTransferOut: (handle: number, setup: WireControlSetup, data: string) =>
    call<WireOutTransferResult>("control_transfer_out", { handle, setup, data }),
  transferIn: (handle: number, endpointNumber: number, length: number) =>
    call<WireInTransferResult>("transfer_in", { handle, endpointNumber, length }),
  transferOut: (handle: number, endpointNumber: number, data: string) =>
    call<WireOutTransferResult>("transfer_out", { handle, endpointNumber, data }),
  isochronousTransferIn: (handle: number, endpointNumber: number, packetLengths: number[]) =>
    call<WireIsoInPacket[]>("isochronous_transfer_in", { handle, endpointNumber, packetLengths }),
  isochronousTransferOut: (handle: number, endpointNumber: number, data: string, packetLengths: number[]) =>
    call<WireIsoOutPacket[]>("isochronous_transfer_out", { handle, endpointNumber, data, packetLengths }),
};

// ---- hotplug events ----
// Fan-out (which webviews receive these at all) is entirely a Rust-side
// decision made by `hotplug.rs` per-origin, before this ever reaches JS —
// this side just subscribes and reshapes the payload.

export function onConnect(handler: (device: WireDevice) => void): Promise<UnlistenFn> {
  return listen<WireDevice>("tauri-webusb://connect", (event) => handler(event.payload));
}

export function onDisconnect(handler: (device: WireDevice) => void): Promise<UnlistenFn> {
  return listen<WireDevice>("tauri-webusb://disconnect", (event) => handler(event.payload));
}
