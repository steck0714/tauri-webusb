// webusb-polyfill.d.ts
// ====================
// Standalone global type declarations for `navigator.usb`, for page code
// that never explicitly imports `tauri-plugin-webusb-api` (the normal case
// — the polyfill installs itself via a Tauri webview init script; see
// guest-js/src/index.ts's doc comment). Reference this file directly
// (`/// <reference types="tauri-plugin-webusb-api/types/webusb-polyfill" />`)
// or add it to your tsconfig's `"types"` array to get full editor support
// on `navigator.usb` without importing anything.
//
// This mirrors both predecessors' own `types/webusb-polyfill.d.ts` — same
// purpose, same standalone-global-declarations approach, so page code
// written against either of those needs no changes here either. One shape
// fix carried forward: `fox-webusb` v0.0.0a0 found (and fixed) that its own
// `USBIsochronousInTransferResult.packets` was typed as a bespoke
// `{length, status}` inline object literal instead of actually using the
// `USBIsochronousInTransferPacket` interface declared two lines above it —
// which itself correctly specifies `{data, status}`. That fix is already
// applied below (`packets: ReadonlyArray<USBIsochronousInTransferPacket>`).

interface USBDeviceFilter {
  vendorId?: number;
  productId?: number;
  classCode?: number;
  subclassCode?: number;
  protocolCode?: number;
  serialNumber?: string;
}

interface USBDeviceRequestOptions {
  filters: USBDeviceFilter[];
  exclusionFilters?: USBDeviceFilter[];
}

type USBDirection = "in" | "out";
type USBEndpointType = "bulk" | "interrupt" | "isochronous";
type USBRequestType = "standard" | "class" | "vendor";
type USBRecipient = "device" | "interface" | "endpoint" | "other";
type USBTransferStatus = "ok" | "stall" | "babble";

interface USBControlTransferParameters {
  requestType: USBRequestType;
  recipient: USBRecipient;
  request: number;
  value: number;
  index: number;
}

interface USBEndpoint {
  readonly endpointNumber: number;
  readonly direction: USBDirection;
  readonly type: USBEndpointType;
  readonly packetSize: number;
}

interface USBAlternateInterface {
  readonly alternateSetting: number;
  readonly interfaceClass: number;
  readonly interfaceSubclass: number;
  readonly interfaceProtocol: number;
  readonly interfaceName: string | null;
  readonly endpoints: ReadonlyArray<USBEndpoint>;
  /** Non-spec, tauri-webusb-specific — see hardening.rs. `true` when this
   * alternate declares one of the protected interface classes (Audio, HID,
   * Mass Storage, Hub, Smart Card, Video, Audio/Video, Wireless
   * Controller); `claimInterface()` on the owning `USBInterface` will
   * reject with a `SecurityError` regardless of what this flag says — it's
   * informational, not itself the enforcement. */
  readonly interfaceProtected: boolean;
}

interface USBInterface {
  readonly interfaceNumber: number;
  readonly alternate: USBAlternateInterface;
  readonly alternates: ReadonlyArray<USBAlternateInterface>;
  readonly claimed: boolean;
}

interface USBConfiguration {
  readonly configurationValue: number;
  readonly configurationName: string | null;
  readonly interfaces: ReadonlyArray<USBInterface>;
}

interface USBInTransferResult {
  readonly data?: DataView;
  readonly status: USBTransferStatus;
}

interface USBOutTransferResult {
  readonly bytesWritten: number;
  readonly status: USBTransferStatus;
}

interface USBIsochronousInTransferPacket {
  readonly data?: DataView;
  readonly status: USBTransferStatus;
}

interface USBIsochronousInTransferResult {
  readonly data?: DataView;
  readonly packets: ReadonlyArray<USBIsochronousInTransferPacket>;
}

interface USBIsochronousOutTransferPacket {
  readonly bytesWritten: number;
  readonly status: USBTransferStatus;
}

interface USBIsochronousOutTransferResult {
  readonly packets: ReadonlyArray<USBIsochronousOutTransferPacket>;
}

interface USBDevice {
  readonly usbVersionMajor: number;
  readonly usbVersionMinor: number;
  readonly usbVersionSubminor: number;
  readonly deviceClass: number;
  readonly deviceSubclass: number;
  readonly deviceProtocol: number;
  readonly vendorId: number;
  readonly productId: number;
  readonly deviceVersionMajor: number;
  readonly deviceVersionMinor: number;
  readonly deviceVersionSubminor: number;
  readonly manufacturerName: string | null;
  readonly productName: string | null;
  readonly serialNumber: string | null;
  readonly configuration: USBConfiguration | null;
  readonly configurations: ReadonlyArray<USBConfiguration>;
  readonly opened: boolean;

  open(): Promise<void>;
  close(): Promise<void>;
  forget(): Promise<void>;
  selectConfiguration(configurationValue: number): Promise<void>;
  claimInterface(interfaceNumber: number): Promise<void>;
  releaseInterface(interfaceNumber: number): Promise<void>;
  selectAlternateInterface(interfaceNumber: number, alternateSetting: number): Promise<void>;
  controlTransferIn(setup: USBControlTransferParameters, length: number): Promise<USBInTransferResult>;
  controlTransferOut(setup: USBControlTransferParameters, data?: BufferSource): Promise<USBOutTransferResult>;
  clearHalt(direction: USBDirection, endpointNumber: number): Promise<void>;
  transferIn(endpointNumber: number, length: number): Promise<USBInTransferResult>;
  transferOut(endpointNumber: number, data: BufferSource): Promise<USBOutTransferResult>;
  isochronousTransferIn(endpointNumber: number, packetLengths: number[]): Promise<USBIsochronousInTransferResult>;
  isochronousTransferOut(endpointNumber: number, data: BufferSource, packetLengths: number[]): Promise<USBIsochronousOutTransferResult>;
  reset(): Promise<void>;
}

interface USBConnectionEvent extends Event {
  readonly device: USBDevice;
}

interface USBEventMap {
  connect: USBConnectionEvent;
  disconnect: USBConnectionEvent;
}

interface USB extends EventTarget {
  onconnect: ((this: USB, ev: USBConnectionEvent) => unknown) | null;
  ondisconnect: ((this: USB, ev: USBConnectionEvent) => unknown) | null;

  getDevices(): Promise<USBDevice[]>;
  requestDevice(options?: USBDeviceRequestOptions): Promise<USBDevice>;

  addEventListener<K extends keyof USBEventMap>(
    type: K,
    listener: (this: USB, ev: USBEventMap[K]) => unknown,
    options?: boolean | AddEventListenerOptions,
  ): void;
  addEventListener(type: string, listener: EventListenerOrEventListenerObject, options?: boolean | AddEventListenerOptions): void;
  removeEventListener<K extends keyof USBEventMap>(
    type: K,
    listener: (this: USB, ev: USBEventMap[K]) => unknown,
    options?: boolean | EventListenerOptions,
  ): void;
  removeEventListener(type: string, listener: EventListenerOrEventListenerObject, options?: boolean | EventListenerOptions): void;
}

interface Navigator {
  readonly usb: USB;
}

interface UserActivation {
  readonly hasBeenActive: boolean;
  readonly isActive: boolean;
}

interface Navigator {
  readonly userActivation: UserActivation;
}
