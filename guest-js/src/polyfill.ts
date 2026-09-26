// polyfill.ts
// ===========
// The actual `navigator.usb` polyfill: real `class ... extends EventTarget`
// / `extends Event` hierarchies with private (`#`) fields, matching
// `fox-webusb` v0.0.0a0's devtools-resistant rewrite rather than its
// original plain-object/`.prototype`-assignment design (`fox-webusb`
// v0.0.0/`pyside6-webusb`). See that release's own reasoning (its
// `CHANGELOG.md`, "Deep devtools inspection resistance"): a page's `'usb' in
// navigator`, `navigator.usb instanceof EventTarget`,
// `Object.getPrototypeOf(device).constructor.name === 'USBDevice'`-style
// feature-detection code (real code that exists in real hardware/serial
// JS libraries, not a hypothetical) works correctly against this shape and
// silently falls through to treating a plain-object stand-in as "USB not
// really supported" against the old one — this is a compatibility property,
// not merely a cosmetic one.
//
// One thing deliberately *not* ported from that same release: its
// `_nativeLooking()` `Function.prototype.toString` Proxy spoofing (making
// every method's `.toString()` print `"[native code]"`). That specific
// technique is about a page not being able to tell it's talking to an
// injected polyfill at all — a meaningfully stronger claim than "behaves
// like a spec-shaped EventTarget", and one this version doesn't make. A
// Tauri app's own bundled frontend already knows it depends on
// tauri-webusb (it's importing this package); pretending otherwise to
// *that* code has no benefit. See README.md's "Known limitations" for the
// one case where it might matter (an app embedding fully third-party remote
// content) and why v0.0.0 leaves it for a later version rather than
// guessing at the right scope for it now.

import { rpc, bufferSourceToBase64, base64ToUint8Array, onConnect, onDisconnect, type WireDevice, type WireConfiguration, type WireFilter } from "./bridge.js";

// ================================================================
// Error mapping
// ================================================================
// See error.rs's module doc comment for the full provenance of this exact
// seven-entry list — the union of fox-webusb's five, pyside6-webusb
// v0.0.4b2's `DataError` addition, and the `NotSupportedError` recognition
// gap this project's own cross-referencing of both predecessors turned up.
// `error.test.ts` independently asserts this list has exactly these seven
// entries and no others, so an addition on the Rust side that forgets this
// side fails a test here rather than silently surfacing as `NetworkError`
// the way pyside6-webusb v0.0.4b2's own still-unrecognized
// `"NotSupportedError:"` case does.
const KNOWN_ERROR_PREFIXES = [
  "SecurityError",
  "InvalidStateError",
  "NotFoundError",
  "InvalidAccessError",
  "IndexSizeError",
  "DataError",
  "NotSupportedError",
] as const;

export function throwFromRpcError(err: unknown, defaultName: string = "NetworkError"): never {
  const message = err instanceof Error ? err.message : String(err);
  for (const prefix of KNOWN_ERROR_PREFIXES) {
    if (message.startsWith(prefix + ": ")) {
      throw new DOMException(message.slice(prefix.length + 2), prefix);
    }
  }
  throw new DOMException(message, defaultName);
}

export { KNOWN_ERROR_PREFIXES };

// ================================================================
// Filter validation (client-side fast-fail; hardening.rs is authoritative)
// ================================================================

function isValidFilterShape(f: unknown): f is WireFilter {
  if (typeof f !== "object" || f === null) return false;
  const rec = f as Record<string, unknown>;
  const numOrUndef = (v: unknown) => v === undefined || typeof v === "number";
  return (
    numOrUndef(rec.vendorId) &&
    numOrUndef(rec.productId) &&
    numOrUndef(rec.classCode) &&
    numOrUndef(rec.subclassCode) &&
    numOrUndef(rec.protocolCode) &&
    (rec.serialNumber === undefined || typeof rec.serialNumber === "string")
  );
}

function checkFilters(filters: unknown, argName: string): WireFilter[] {
  if (!Array.isArray(filters)) {
    throw new TypeError(`${argName} must be an array`);
  }
  for (const f of filters) {
    if (!isValidFilterShape(f)) {
      throw new TypeError(`${argName} contains an invalid USBDeviceFilter`);
    }
  }
  return filters as WireFilter[];
}

// ================================================================
// Descriptor data classes (spec-shaped, constructed from a WireDevice)
// ================================================================

export class USBEndpoint {
  readonly endpointNumber: number;
  readonly direction: "in" | "out";
  readonly type: "bulk" | "interrupt" | "isochronous";
  readonly packetSize: number;

  constructor(wire: { endpointNumber: number; direction: "in" | "out"; type: "bulk" | "interrupt" | "isochronous"; packetSize: number }) {
    this.endpointNumber = wire.endpointNumber;
    this.direction = wire.direction;
    this.type = wire.type;
    this.packetSize = wire.packetSize;
  }

  get [Symbol.toStringTag](): string {
    return "USBEndpoint";
  }
}

export class USBAlternateInterface {
  readonly alternateSetting: number;
  readonly interfaceClass: number;
  readonly interfaceSubclass: number;
  readonly interfaceProtocol: number;
  readonly interfaceName: string | null;
  readonly endpoints: ReadonlyArray<USBEndpoint>;
  /** Non-spec, tauri-webusb-specific: surfaced so a UI (or careful page
   * code) can tell *why* `claimInterface()` might be about to fail, without
   * needing its own copy of the protected-class table. Mirrors what the
   * chooser window already shows the person — see `hardening.rs`. */
  readonly interfaceProtected: boolean;

  constructor(wire: WireDevice["configurations"][number]["interfaces"][number]["alternates"][number]) {
    this.alternateSetting = wire.alternateSetting;
    this.interfaceClass = wire.interfaceClass;
    this.interfaceSubclass = wire.interfaceSubclass;
    this.interfaceProtocol = wire.interfaceProtocol;
    this.interfaceName = wire.interfaceName;
    this.interfaceProtected = wire.interfaceProtected;
    this.endpoints = wire.endpoints.map((e) => new USBEndpoint(e));
  }

  get [Symbol.toStringTag](): string {
    return "USBAlternateInterface";
  }
}

export class USBInterface {
  readonly interfaceNumber: number;
  readonly alternates: ReadonlyArray<USBAlternateInterface>;
  #device: USBDevice;

  constructor(device: USBDevice, wire: WireDevice["configurations"][number]["interfaces"][number]) {
    this.#device = device;
    this.interfaceNumber = wire.interfaceNumber;
    this.alternates = wire.alternates.map((a) => new USBAlternateInterface(a));
  }

  get claimed(): boolean {
    return this.#device._isInterfaceClaimed(this.interfaceNumber);
  }

  get alternate(): USBAlternateInterface {
    const setting = this.#device._activeAlternateFor(this.interfaceNumber);
    const found = this.alternates.find((a) => a.alternateSetting === setting);
    if (found) return found;
    const first = this.alternates[0];
    if (!first) {
      // A well-formed USB descriptor always has at least one alternate
      // setting (0) per interface — `descriptor_from_open_device` in
      // bridge.rs only ever produces an `InterfaceDescriptor` because it
      // found at least one `InterfaceAltSetting` to build it from. Reaching
      // this means the device's own descriptors are malformed in a way
      // nothing upstream caught; surfacing that clearly beats returning
      // something type-unsafe.
      throw new DOMException(`interface ${this.interfaceNumber} has no alternate settings at all`, "NotFoundError");
    }
    return first;
  }

  get [Symbol.toStringTag](): string {
    return "USBInterface";
  }
}

export class USBConfiguration {
  readonly configurationValue: number;
  readonly configurationName: string | null;
  readonly interfaces: ReadonlyArray<USBInterface>;

  constructor(device: USBDevice, wire: WireConfiguration) {
    this.configurationValue = wire.configurationValue;
    this.configurationName = wire.configurationName;
    this.interfaces = wire.interfaces.map((i) => new USBInterface(device, i));
  }

  get [Symbol.toStringTag](): string {
    return "USBConfiguration";
  }
}

// ================================================================
// Transfer result classes
// ================================================================

export class USBInTransferResult {
  readonly data: DataView;
  readonly status: "ok" | "stall" | "babble";

  constructor(data: DataView, status: "ok" | "stall" | "babble") {
    this.data = data;
    this.status = status;
  }

  get [Symbol.toStringTag](): string {
    return "USBInTransferResult";
  }
}

export class USBOutTransferResult {
  readonly bytesWritten: number;
  readonly status: "ok" | "stall" | "babble";

  constructor(bytesWritten: number, status: "ok" | "stall" | "babble") {
    this.bytesWritten = bytesWritten;
    this.status = status;
  }

  get [Symbol.toStringTag](): string {
    return "USBOutTransferResult";
  }
}

export class USBIsochronousInTransferPacket {
  readonly data: DataView | undefined;
  readonly status: "ok" | "stall" | "babble";

  constructor(data: DataView | undefined, status: "ok" | "stall" | "babble") {
    this.data = data;
    this.status = status;
  }

  get [Symbol.toStringTag](): string {
    return "USBIsochronousInTransferPacket";
  }
}

export class USBIsochronousInTransferResult {
  readonly data: DataView | undefined;
  readonly packets: ReadonlyArray<USBIsochronousInTransferPacket>;

  constructor(data: DataView | undefined, packets: USBIsochronousInTransferPacket[]) {
    this.data = data;
    this.packets = packets;
  }

  get [Symbol.toStringTag](): string {
    return "USBIsochronousInTransferResult";
  }
}

export class USBIsochronousOutTransferPacket {
  readonly bytesWritten: number;
  readonly status: "ok" | "stall" | "babble";

  constructor(bytesWritten: number, status: "ok" | "stall" | "babble") {
    this.bytesWritten = bytesWritten;
    this.status = status;
  }

  get [Symbol.toStringTag](): string {
    return "USBIsochronousOutTransferPacket";
  }
}

export class USBIsochronousOutTransferResult {
  readonly packets: ReadonlyArray<USBIsochronousOutTransferPacket>;

  constructor(packets: USBIsochronousOutTransferPacket[]) {
    this.packets = packets;
  }

  get [Symbol.toStringTag](): string {
    return "USBIsochronousOutTransferResult";
  }
}

// ================================================================
// USBDevice
// ================================================================
// Per spec, `USBDevice` is a plain (non-`EventTarget`) class — `connect`/
// `disconnect` events fire on `navigator.usb` itself, carrying a `device`
// property, never on the `USBDevice` instance directly. Only `USB` below
// extends `EventTarget`.

export class USBDevice {
  #wire: WireDevice;
  #handle: number | null = null;
  #claimedInterfaces = new Set<number>();
  #activeAlternate = new Map<number, number>();

  /** @internal constructed only by this module (getDevices/requestDevice
   * results, hotplug events) — never exposed as a public constructor a page
   * could call itself, matching spec (`[Exposed=Window] interface USBDevice`
   * has no constructor at all). */
  constructor(wire: WireDevice) {
    this.#wire = wire;
  }

  /** @internal */
  _updateWire(wire: WireDevice): void {
    this.#wire = wire;
  }

  /** @internal used by USBInterface's `claimed` getter. */
  _isInterfaceClaimed(interfaceNumber: number): boolean {
    return this.#claimedInterfaces.has(interfaceNumber);
  }

  /** @internal used by USBInterface's `alternate` getter. */
  _activeAlternateFor(interfaceNumber: number): number {
    return this.#activeAlternate.get(interfaceNumber) ?? 0;
  }

  get usbVersionMajor(): number { return this.#wire.usbVersionMajor; }
  get usbVersionMinor(): number { return this.#wire.usbVersionMinor; }
  get usbVersionSubminor(): number { return this.#wire.usbVersionSubminor; }
  get deviceClass(): number { return this.#wire.deviceClass; }
  get deviceSubclass(): number { return this.#wire.deviceSubclass; }
  get deviceProtocol(): number { return this.#wire.deviceProtocol; }
  get vendorId(): number { return this.#wire.vendorId; }
  get productId(): number { return this.#wire.productId; }
  get deviceVersionMajor(): number { return this.#wire.deviceVersionMajor; }
  get deviceVersionMinor(): number { return this.#wire.deviceVersionMinor; }
  get deviceVersionSubminor(): number { return this.#wire.deviceVersionSubminor; }
  get manufacturerName(): string | null { return this.#wire.manufacturerName; }
  get productName(): string | null { return this.#wire.productName; }
  get serialNumber(): string | null { return this.#wire.serialNumber; }
  get opened(): boolean { return this.#handle !== null; }

  get configurations(): ReadonlyArray<USBConfiguration> {
    return this.#wire.configurations.map((c) => new USBConfiguration(this, c));
  }

  get configuration(): USBConfiguration | null {
    const value = this.#wire.activeConfigurationValue;
    if (value === null) return null;
    const wireCfg = this.#wire.configurations.find((c) => c.configurationValue === value);
    return wireCfg ? new USBConfiguration(this, wireCfg) : null;
  }

  private requireOpenHandle(): number {
    if (this.#handle === null) {
      throw new DOMException("the device must be open()ed before calling this method", "InvalidStateError");
    }
    return this.#handle;
  }

  async open(): Promise<void> {
    if (this.#handle !== null) return; // spec: open() on an already-open device is a no-op
    try {
      // `serialNumber` disambiguates multiple simultaneously-connected
      // devices sharing one vendorId/productId pair — see `bridge::open_device`'s
      // doc comment on the Rust side. This is *not* a new parameter page code
      // supplies: real `USBDevice.open()` takes no arguments at all per spec,
      // and this object already carries its own serialNumber (if the device
      // reports one) from whichever `getDevices()`/`requestDevice()` call
      // produced it — passed through here transparently.
      const result = await rpc.open(this.#wire.vendorId, this.#wire.productId, this.#wire.serialNumber ?? undefined);
      this.#handle = result.handle;
      this.#wire = result.descriptor;
    } catch (e) {
      throwFromRpcError(e);
    }
  }

  async close(): Promise<void> {
    if (this.#handle === null) return;
    const handle = this.#handle;
    this.#handle = null;
    this.#claimedInterfaces.clear();
    this.#activeAlternate.clear();
    try {
      await rpc.close(handle);
    } catch (e) {
      throwFromRpcError(e);
    }
  }

  async forget(): Promise<void> {
    if (this.#handle === null) {
      // Spec's forget() works even on a not-currently-open device in real
      // Chrome (it revokes the permission regardless of open state) — but
      // this plugin's backend keys the revoke off a live handle (see
      // bridge.rs's `forget_device`) purely for implementation simplicity.
      // Rather than silently doing nothing here (which would be a real,
      // observable behavior gap from spec), this is one of the few places
      // v0.0.0 surfaces its own limitation as an explicit rejection instead
      // of guessing — see README.md's "Known limitations".
      throw new DOMException(
        "forget() on a device that is not currently open is not supported in this version of " +
          "tauri-webusb; call open() first, or use the trusted management API's " +
          "revokeOriginGrant() from your app's own settings UI instead.",
        "InvalidStateError",
      );
    }
    const handle = this.#handle;
    this.#handle = null;
    this.#claimedInterfaces.clear();
    this.#activeAlternate.clear();
    try {
      await rpc.forget(handle);
    } catch (e) {
      throwFromRpcError(e);
    }
  }

  async selectConfiguration(configurationValue: number): Promise<void> {
    const handle = this.requireOpenHandle();
    try {
      await rpc.selectConfiguration(handle, configurationValue);
      this.#claimedInterfaces.clear();
      this.#activeAlternate.clear();
      const fresh = await rpc.getDevices();
      const match = fresh.find((d) => d.vendorId === this.#wire.vendorId && d.productId === this.#wire.productId);
      if (match) this.#wire = match;
    } catch (e) {
      throwFromRpcError(e);
    }
  }

  async claimInterface(interfaceNumber: number): Promise<void> {
    const handle = this.requireOpenHandle();
    try {
      await rpc.claimInterface(handle, interfaceNumber);
      this.#claimedInterfaces.add(interfaceNumber);
    } catch (e) {
      throwFromRpcError(e);
    }
  }

  async releaseInterface(interfaceNumber: number): Promise<void> {
    const handle = this.requireOpenHandle();
    try {
      await rpc.releaseInterface(handle, interfaceNumber);
      this.#claimedInterfaces.delete(interfaceNumber);
      this.#activeAlternate.delete(interfaceNumber);
    } catch (e) {
      throwFromRpcError(e);
    }
  }

  async selectAlternateInterface(interfaceNumber: number, alternateSetting: number): Promise<void> {
    const handle = this.requireOpenHandle();
    try {
      await rpc.selectAlternateInterface(handle, interfaceNumber, alternateSetting);
      this.#activeAlternate.set(interfaceNumber, alternateSetting);
    } catch (e) {
      throwFromRpcError(e);
    }
  }

  async reset(): Promise<void> {
    const handle = this.requireOpenHandle();
    try {
      await rpc.resetDevice(handle);
      this.#claimedInterfaces.clear();
      this.#activeAlternate.clear();
    } catch (e) {
      throwFromRpcError(e);
    }
  }

  async clearHalt(direction: "in" | "out", endpointNumber: number): Promise<void> {
    checkEndpointNumber(endpointNumber);
    const handle = this.requireOpenHandle();
    try {
      await rpc.clearHalt(handle, endpointNumber, direction);
    } catch (e) {
      throwFromRpcError(e);
    }
  }

  async controlTransferIn(setup: USBControlTransferParameters, length: number): Promise<USBInTransferResult> {
    const handle = this.requireOpenHandle();
    try {
      const result = await rpc.controlTransferIn(handle, setup, length);
      warnIfPresent(result.warning);
      return new USBInTransferResult(wrapDataView(result.data), result.status);
    } catch (e) {
      return throwFromRpcError(e);
    }
  }

  async controlTransferOut(setup: USBControlTransferParameters, data?: BufferSource): Promise<USBOutTransferResult> {
    const handle = this.requireOpenHandle();
    const b64 = data ? bufferSourceToBase64(data) : "";
    try {
      const result = await rpc.controlTransferOut(handle, setup, b64);
      warnIfPresent(result.warning);
      return new USBOutTransferResult(result.bytesWritten, result.status);
    } catch (e) {
      return throwFromRpcError(e);
    }
  }

  async transferIn(endpointNumber: number, length: number): Promise<USBInTransferResult> {
    checkEndpointNumber(endpointNumber);
    const handle = this.requireOpenHandle();
    try {
      const result = await rpc.transferIn(handle, endpointNumber, length);
      warnIfPresent(result.warning);
      return new USBInTransferResult(wrapDataView(result.data), result.status);
    } catch (e) {
      return throwFromRpcError(e);
    }
  }

  async transferOut(endpointNumber: number, data: BufferSource): Promise<USBOutTransferResult> {
    checkEndpointNumber(endpointNumber);
    const handle = this.requireOpenHandle();
    try {
      const result = await rpc.transferOut(handle, endpointNumber, bufferSourceToBase64(data));
      warnIfPresent(result.warning);
      return new USBOutTransferResult(result.bytesWritten, result.status);
    } catch (e) {
      return throwFromRpcError(e);
    }
  }

  async isochronousTransferIn(endpointNumber: number, packetLengths: number[]): Promise<USBIsochronousInTransferResult> {
    checkEndpointNumber(endpointNumber);
    const handle = this.requireOpenHandle();
    try {
      const wirePackets = await rpc.isochronousTransferIn(handle, endpointNumber, packetLengths);
      // Combine every packet's bytes into one shared ArrayBuffer and hand
      // each packet a `DataView` slice of *that* buffer — matches the
      // fox-webusb v0.0.0a0 fix (see this file's own header comment and
      // `error.rs`'s doc comment): each packet carries its own `data`, not
      // just a `length`, and the top-level `.data` is the concatenation of
      // all of them, exactly like real Chrome.
      const totalLength = wirePackets.reduce((sum, p) => sum + (p.status === "ok" ? base64ToUint8Array(p.data).byteLength : 0), 0);
      const combined = new Uint8Array(totalLength);
      let offset = 0;
      const packets = wirePackets.map((p) => {
        if (p.status !== "ok") return new USBIsochronousInTransferPacket(undefined, p.status);
        const bytes = base64ToUint8Array(p.data);
        combined.set(bytes, offset);
        const view = new DataView(combined.buffer, offset, bytes.byteLength);
        offset += bytes.byteLength;
        return new USBIsochronousInTransferPacket(view, p.status);
      });
      return new USBIsochronousInTransferResult(new DataView(combined.buffer), packets);
    } catch (e) {
      return throwFromRpcError(e);
    }
  }

  async isochronousTransferOut(endpointNumber: number, data: BufferSource, packetLengths: number[]): Promise<USBIsochronousOutTransferResult> {
    checkEndpointNumber(endpointNumber);
    const handle = this.requireOpenHandle();
    try {
      const wirePackets = await rpc.isochronousTransferOut(handle, endpointNumber, bufferSourceToBase64(data), packetLengths);
      const packets = wirePackets.map((p) => new USBIsochronousOutTransferPacket(p.bytesWritten, p.status));
      return new USBIsochronousOutTransferResult(packets);
    } catch (e) {
      return throwFromRpcError(e);
    }
  }

  get [Symbol.toStringTag](): string {
    return "USBDevice";
  }
}

function wrapDataView(base64: string): DataView {
  const bytes = base64ToUint8Array(base64);
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function checkEndpointNumber(endpointNumber: number): void {
  if (!Number.isInteger(endpointNumber) || endpointNumber < 1 || endpointNumber > 15) {
    throw new TypeError("endpointNumber must be an integer between 1 and 15");
  }
}

function warnIfPresent(warning: string | undefined): void {
  if (warning) {
    // eslint-disable-next-line no-console
    console.warn(`[tauri-webusb] ${warning}`);
  }
}

export interface USBControlTransferParameters {
  requestType: "standard" | "class" | "vendor";
  recipient: "device" | "interface" | "endpoint" | "other";
  request: number;
  value: number;
  index: number;
}

// ================================================================
// USBConnectionEvent
// ================================================================

export class USBConnectionEvent extends Event {
  #device: USBDevice;

  constructor(type: "connect" | "disconnect", eventInitDict: { device: USBDevice }) {
    super(type);
    this.#device = eventInitDict.device;
  }

  get device(): USBDevice {
    return this.#device;
  }

  get [Symbol.toStringTag](): string {
    return "USBConnectionEvent";
  }
}

// ================================================================
// USB (navigator.usb)
// ================================================================

export class USB extends EventTarget {
  #onconnect: ((this: USB, ev: USBConnectionEvent) => unknown) | null = null;
  #ondisconnect: ((this: USB, ev: USBConnectionEvent) => unknown) | null = null;
  #knownDevices = new Map<string, USBDevice>(); // keyed by "vendorId:productId" — see hotplug.rs's module doc comment on this same identity simplification

  /** @internal called once by `index.ts`'s `install()`. */
  _startHotplugListeners(): void {
    onConnect((wire) => {
      const device = this.#trackDevice(wire);
      this.dispatchEvent(new USBConnectionEvent("connect", { device }));
    });
    onDisconnect((wire) => {
      const device = this.#trackDevice(wire);
      this.dispatchEvent(new USBConnectionEvent("disconnect", { device }));
    });
  }

  #trackDevice(wire: WireDevice): USBDevice {
    const key = `${wire.vendorId}:${wire.productId}`;
    const existing = this.#knownDevices.get(key);
    if (existing) {
      existing._updateWire(wire);
      return existing;
    }
    const created = new USBDevice(wire);
    this.#knownDevices.set(key, created);
    return created;
  }

  async getDevices(): Promise<USBDevice[]> {
    try {
      const wireDevices = await rpc.getDevices();
      return wireDevices.map((w) => this.#trackDevice(w));
    } catch (e) {
      return throwFromRpcError(e);
    }
  }

  async requestDevice(options?: { filters?: unknown; exclusionFilters?: unknown }): Promise<USBDevice> {
    if (!navigator.userActivation?.isActive) {
      throw new DOMException("requestDevice() requires a user gesture (e.g. a click handler)", "SecurityError");
    }
    const filters = checkFilters(options?.filters ?? [], "filters");
    const exclusionFilters = checkFilters(options?.exclusionFilters ?? [], "exclusionFilters");
    try {
      // 🛡️ security_report/VULNERABILITY_REPORT.md finding No.2 (see
      // `gesture.rs`'s module doc comment): this check above is necessary
      // but not sufficient on its own, since it runs in the page's own JS
      // context — any other script on the page (or a direct
      // `invoke("plugin:webusb|request_device", ...)` call, bypassing this
      // polyfill entirely) could skip it. Minting the token *here*, right
      // after confirming activation is genuinely active, and having Rust
      // require and consume it before ever showing the chooser window, is
      // what actually enforces this rather than merely asking nicely.
      const gestureToken = await rpc.mintGestureToken();
      const wire = await rpc.requestDevice(filters, exclusionFilters, gestureToken);
      return this.#trackDevice(wire);
    } catch (e) {
      return throwFromRpcError(e);
    }
  }

  get onconnect(): ((this: USB, ev: USBConnectionEvent) => unknown) | null {
    return this.#onconnect;
  }
  set onconnect(handler: ((this: USB, ev: USBConnectionEvent) => unknown) | null) {
    if (this.#onconnect) this.removeEventListener("connect", this.#onconnect as EventListener);
    this.#onconnect = handler;
    if (handler) this.addEventListener("connect", handler as EventListener);
  }

  get ondisconnect(): ((this: USB, ev: USBConnectionEvent) => unknown) | null {
    return this.#ondisconnect;
  }
  set ondisconnect(handler: ((this: USB, ev: USBConnectionEvent) => unknown) | null) {
    if (this.#ondisconnect) this.removeEventListener("disconnect", this.#ondisconnect as EventListener);
    this.#ondisconnect = handler;
    if (handler) this.addEventListener("disconnect", handler as EventListener);
  }

  get [Symbol.toStringTag](): string {
    return "USB";
  }
}
