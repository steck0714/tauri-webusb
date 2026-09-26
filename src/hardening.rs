//! hardening.rs
//! ============
//! The actual WebUSB security model, translated from `hardening.py`
//! (`fox-webusb`/`pyside6-webusb`) into backend-independent Rust: every
//! function here takes plain data (`models::*`) and returns plain data or a
//! `bool`/`Option` — nothing in this file talks to `nusb`, a live device
//! handle, or Tauri. `bridge.rs` is the only module that bridges the gap
//! between "what `nusb` gives us" and the `models::DeviceDescriptor`/etc.
//! shapes this file operates on. That split is what makes it possible to
//! unit-test every rule below with hand-built struct literals, no fake/mock
//! USB backend required — see the `tests` module.
//!
//! ## Why this needs to exist at all (unchanged from both predecessors)
//!
//! WebUSB is a WICG Draft, implemented only by Chromium-family browsers.
//! Firefox's official standards-position is `negative` ("harmful") and
//! Safari/WebKit similarly has no implementation
//! (mozilla/standards-positions#100). Chromium itself layers several
//! defenses on top of plain per-origin permission grants, and this module
//! reproduces the two that are meaningfully implementable outside the
//! browser itself:
//!
//! 1. **Protected interface classes** — Audio / HID / Mass Storage / Hub /
//!    Smart Card / Video / Audio-Video / Wireless Controller. `claimInterface()`
//!    on any of these is rejected outright, which structurally prevents raw
//!    access to security keys, keyboards, mice, storage, etc. even once an
//!    origin has been granted the device as a whole.
//! 2. **A blocklist** of known security-key `(vendorId, productId)` pairs,
//!    ported from Chromium's `usb_blocklist.cc`. This is explicitly a
//!    second, narrower layer — (1) is what actually matters, since it closes
//!    off entire device classes rather than enumerating specific PIDs.
//!
//! Secure-context and user-activation checks ((3)/(4) in Chromium's model)
//! live on the JS side (`guest-js/src/polyfill.ts`), since those concepts
//! (`window.isSecureContext`, `navigator.userActivation`) only exist there.
//!
//! ## Provenance
//!
//! - Protected interface class table: WebUSB spec's own "Protected interface
//!   classes" list (WICG/webusb, `index.bs`).
//! - Blocklist: `chrome/browser/usb/usb_blocklist.cc`, vendor/product pairs
//!   only, as ported unchanged through `pyside6-webusb` → `fox-webusb` → here.
//!   Same caveat as both predecessors documented: Chromium's real list moves;
//!   this is one layer of defense-in-depth, not the load-bearing one.
//! - Transfer-size policy: `pyside6-webusb` v0.0.4b2's own cross-check against
//!   real Blink source (`usb_device.cc`, `kUsbTransferLengthLimit`), which is
//!   *not* yet in `fox-webusb` (ported from the older v0.0.4b0, before that
//!   pass). See the constants below for the specifics tauri-webusb carries
//!   forward from v0.0.4b2 rather than from fox-webusb's older, simpler
//!   hard-reject-at-64MiB/16MiB scheme.

use crate::error::WebUsbError;
use crate::models::{
    AlternateInterfaceDescriptor, ControlRecipient, ControlRequestType, DeviceDescriptor,
    Direction, EndpointDescriptor, EndpointType, UsbDeviceFilter,
};

// ================================================================
// 1) Protected interface classes
// ================================================================

/// `(class code, human-readable name)`. The name is surfaced in
/// `SecurityError` messages only — not used for matching.
pub const PROTECTED_INTERFACE_CLASSES: &[(u8, &str)] = &[
    (0x01, "Audio"),
    (0x03, "HID (Human Interface Device: most security keys/keyboards/mice)"),
    (0x08, "Mass Storage"),
    (0x09, "Hub"),
    (0x0B, "Smart Card (CCID)"),
    (0x0E, "Video"),
    (0x10, "Audio/Video"),
    (0xE0, "Wireless Controller (Bluetooth/wireless USB adapters etc.)"),
];

/// Should `claimInterface()` for this `bInterfaceClass` be rejected?
pub fn is_protected_interface_class(b_interface_class: u8) -> bool {
    PROTECTED_INTERFACE_CLASSES.iter().any(|&(c, _)| c == b_interface_class)
}

/// Human-readable name for a protected class, for error messages. Returns
/// `"Unknown"` for a class that isn't actually protected — callers should
/// have already checked `is_protected_interface_class` first; this never
/// itself decides policy.
pub fn protected_class_name(b_interface_class: u8) -> &'static str {
    PROTECTED_INTERFACE_CLASSES
        .iter()
        .find(|&&(c, _)| c == b_interface_class)
        .map(|&(_, name)| name)
        .unwrap_or("Unknown")
}

// ================================================================
// 2) Known security-key blocklist (defense-in-depth layer 2)
// ================================================================

/// `(vendorId, productId)` pairs ported from Chromium's `usb_blocklist.cc`.
/// Almost all of these devices present as HID and would already be blocked
/// by `is_protected_interface_class` — this list exists for the narrower
/// case of a device speaking CTAP-like security-key semantics over a
/// non-HID interface.
pub const KNOWN_SECURITY_KEY_BLOCKLIST: &[(u16, u16)] = &[
    (0x096e, 0x0850), (0x096e, 0x0852), (0x096e, 0x0853), (0x096e, 0x0854),
    (0x096e, 0x0856), (0x096e, 0x0858), (0x096e, 0x085a), (0x096e, 0x085b),
    (0x096e, 0x0880),
    (0x09c3, 0x0023),
    (0x1050, 0x0010), (0x1050, 0x0018), (0x1050, 0x0030),
    (0x1050, 0x0110), (0x1050, 0x0111), (0x1050, 0x0112), (0x1050, 0x0113),
    (0x1050, 0x0114), (0x1050, 0x0115), (0x1050, 0x0116), (0x1050, 0x0120),
    (0x1050, 0x0200), (0x1050, 0x0211),
    (0x1050, 0x0401), (0x1050, 0x0402), (0x1050, 0x0403), (0x1050, 0x0404),
    (0x1050, 0x0405), (0x1050, 0x0406), (0x1050, 0x0407), (0x1050, 0x0410),
    (0x10c4, 0x8acf),
    (0x18d1, 0x5026),
    (0x1a44, 0x00bb),
    (0x1d50, 0x60fc),
    (0x1e0d, 0xf1ae), (0x1e0d, 0xf1d0),
    (0x1ea8, 0xf025),
    (0x20a0, 0x4287),
    (0x24dc, 0x0101),
    (0x2581, 0xf1d0),
    (0x2abe, 0x1002),
    (0x2ccf, 0x0880),
];

pub fn is_blocklisted_device(vendor_id: u16, product_id: u16) -> bool {
    KNOWN_SECURITY_KEY_BLOCKLIST.contains(&(vendor_id, product_id))
}

pub fn device_is_fully_blocked(device: &DeviceDescriptor) -> bool {
    is_blocklisted_device(device.vendor_id, device.product_id)
}

// ================================================================
// 3) BCD version decoding (bcdUSB / bcdDevice -> major.minor.subminor)
// ================================================================

/// Splits a USB descriptor BCD value (e.g. `0x0210`) into
/// `(major, minor, subminor)` = `(2, 1, 0)`, matching
/// `USBDevice.usbVersionMajor`/etc.'s decomposition per spec.
pub fn bcd_to_version(bcd_value: u16) -> (u8, u8, u8) {
    let major = ((bcd_value >> 8) & 0xFF) as u8;
    let minor = ((bcd_value >> 4) & 0x0F) as u8;
    let subminor = (bcd_value & 0x0F) as u8;
    (major, minor, subminor)
}

// ================================================================
// 4) requestDevice()/getDevices() filter matching (WebUSB spec §5)
// ================================================================
// Ported directly from the three spec algorithms ("A USB device device
// matches a device filter filter" / "A USB interface interface matches an
// interface filter filter" / "A USBDeviceFilter filter is valid"), same as
// both predecessors. `guest-js` does its own shallow shape check
// (`isValidFilterShape`) to fail fast with a `TypeError` for obviously
// malformed filters; this is the authoritative check.

/// "A USBDeviceFilter filter is valid" (spec). A lower-specificity field
/// without the field that would give it meaning is invalid — e.g.
/// `productId` without `vendorId`.
pub fn is_valid_usb_device_filter(filter: &UsbDeviceFilter) -> bool {
    if filter.product_id.is_some() && filter.vendor_id.is_none() {
        return false;
    }
    if filter.subclass_code.is_some() && filter.class_code.is_none() {
        return false;
    }
    if filter.protocol_code.is_some() && filter.subclass_code.is_none() {
        return false;
    }
    true
}

/// Every `(interfaceClass, interfaceSubclass, interfaceProtocol)` triplet
/// across *all* of this device's configurations (not just the active one) —
/// matches `_device_interface_class_tuples` in both predecessors. Walking
/// every configuration, not just the active one, matters for `classCode`
/// filter matching below: the spec's device-matches-filter algorithm checks
/// every interface, regardless of which configuration is currently active.
fn all_interface_class_tuples(device: &DeviceDescriptor) -> Vec<(u8, u8, u8)> {
    device
        .configurations
        .iter()
        .flat_map(|cfg| cfg.interfaces.iter())
        .flat_map(|iface| iface.alternates.iter())
        .map(|alt: &AlternateInterfaceDescriptor| {
            (alt.interface_class, alt.interface_subclass, alt.interface_protocol)
        })
        .collect()
}

fn interface_matches_filter(triplet: (u8, u8, u8), filter: &UsbDeviceFilter) -> bool {
    let (class, sub, proto) = triplet;
    if let Some(want) = filter.class_code {
        if class != want {
            return false;
        }
    }
    if let Some(want) = filter.subclass_code {
        if sub != want {
            return false;
        }
    }
    if let Some(want) = filter.protocol_code {
        if proto != want {
            return false;
        }
    }
    true
}

/// "A USB device device matches a device filter filter" (spec), ported
/// as-is. A `classCode` filter matches if *either* the device's own
/// `bDeviceClass` (+ sub/protocol) matches, *or* any single interface across
/// any configuration matches — the latter is what lets a composite device
/// declaring `bDeviceClass = 0xFF` (vendor-specific) at the device level
/// still be found by a `classCode` filter naming its real per-interface
/// class.
pub fn device_matches_usb_filter(device: &DeviceDescriptor, filter: &UsbDeviceFilter) -> bool {
    if let Some(want) = filter.vendor_id {
        if device.vendor_id != want {
            return false;
        }
    }
    if let Some(want) = filter.product_id {
        if device.product_id != want {
            return false;
        }
    }
    if let Some(want) = &filter.serial_number {
        if device.serial_number.as_deref() != Some(want.as_str()) {
            return false;
        }
    }
    if let Some(want_class) = filter.class_code {
        let tuples = all_interface_class_tuples(device);
        if tuples.iter().any(|&t| interface_matches_filter(t, filter)) {
            return true; // spec: any one matching interface is enough
        }
        if device.device_class != want_class {
            return false;
        }
        if let Some(want_sub) = filter.subclass_code {
            if device.device_subclass != want_sub {
                return false;
            }
        }
        if let Some(want_proto) = filter.protocol_code {
            if device.device_protocol != want_proto {
                return false;
            }
        }
    }
    true
}

/// Matches if `device` satisfies *any* filter in `filters`. An empty filter
/// list matches nothing — per spec, and matching real Chromium: a site that
/// wants "any device, no filtering" must pass `filters: [{}]` (one filter
/// object with no fields set, which matches unconditionally), not an empty
/// array.
pub fn device_matches_any_usb_filter(device: &DeviceDescriptor, filters: &[UsbDeviceFilter]) -> bool {
    if filters.is_empty() {
        return false;
    }
    filters.iter().any(|f| device_matches_usb_filter(device, f))
}

// ================================================================
// 5) Transfer-size policy
// ================================================================
// Ported from pyside6-webusb v0.0.4b2 (NOT fox-webusb's older, simpler
// scheme — see module doc comment). Two independent thresholds with two
// different jobs:
//
//   - CHROME_TRANSFER_WARN_LENGTH (32 MiB): a *reference* figure, matching
//     real Chrome's kUsbTransferLengthLimit. This is Chrome's own
//     operational choice, not a WebUSB spec requirement, so exceeding it
//     does not fail the call here — it succeeds, with a `warning` string
//     attached to the result (surfaced to the page as `console.warn()`; see
//     `models::InTransferResult`/`OutTransferResult`). tauri-webusb is
//     WebUSB-*compatible*, not a byte-for-byte Chrome clone, and this is the
//     one place that distinction is actually load-bearing.
//   - HOST_SAFETY_MAX_TRANSFER_LENGTH (512 MiB): the actual hard ceiling,
//     entirely unrelated to Chrome-matching. Exists purely so a pathological
//     `transferIn(length)` request can't force this process into an
//     unbounded allocation. This is what `BULK_TRANSFER_MAX_LENGTH` and
///    `ISOCHRONOUS_TRANSFER_MAX_TOTAL_LENGTH` actually equal.
pub const CHROME_TRANSFER_WARN_LENGTH: u64 = 32 * 1024 * 1024;
pub const HOST_SAFETY_MAX_TRANSFER_LENGTH: u64 = 512 * 1024 * 1024;
pub const BULK_TRANSFER_MAX_LENGTH: u64 = HOST_SAFETY_MAX_TRANSFER_LENGTH;
pub const ISOCHRONOUS_TRANSFER_MAX_TOTAL_LENGTH: u64 = HOST_SAFETY_MAX_TRANSFER_LENGTH;

/// `controlTransferIn`'s `length` is a WebIDL `unsigned short` per spec —
/// this is a hard structural ceiling (65535), not a Chrome policy choice,
/// so unlike the two constants above it is never subject to the
/// warn-instead-of-reject treatment.
pub const CONTROL_TRANSFER_MAX_LENGTH: u32 = 0xFFFF;

/// `None` if `actual_length` is within Chrome's real reference limit;
/// otherwise a message quoting Chrome's own rejection text (for context)
/// and stating plainly that this is tauri-webusb, not Chrome, and does not
/// enforce that limit. Never itself a reason to fail the call — see the
/// module doc comment.
pub fn chrome_transfer_limit_warning(actual_length: u64) -> Option<String> {
    if actual_length <= CHROME_TRANSFER_WARN_LENGTH {
        return None;
    }
    Some(format!(
        "this transfer is {actual_length} bytes, over the {CHROME_TRANSFER_WARN_LENGTH}-byte \
         limit real Chrome enforces here (Chrome rejects with DataError: \"The data buffer \
         exceeded supported maximum size of {CHROME_TRANSFER_WARN_LENGTH} bytes\"). \
         tauri-webusb is not Chrome and does not enforce that limit — this transfer is \
         proceeding. (This implementation's own hard ceiling is {HOST_SAFETY_MAX_TRANSFER_LENGTH} bytes.)"
    ))
}

// ================================================================
// 6) Transfer timeout scaling
// ================================================================
// WebUSB's transferIn/transferOut/controlTransferIn/controlTransferOut
// expose no "timeout" concept to JS at all — the caller is entitled to
// expect the call waits however long it takes. This implementation still
// has to pick *some* internal timeout to hand `nusb`, on pain of a wedged
// worker task blocking forever against an unresponsive device. A fixed
// short timeout would abort legitimate large transfers (WebADB-style file
// pushes can be several MB) before they finish on a slow link; no timeout
// at all risks a permanently stuck task. This scales the timeout by a
// conservative assumed minimum throughput, floored and capped.
const TRANSFER_TIMEOUT_MIN_MS: u64 = 5_000;
const TRANSFER_TIMEOUT_MAX_MS: u64 = 120_000;
/// 100 KB/s, a deliberately conservative "this link is slow but not dead"
/// assumption.
const TRANSFER_ASSUMED_MIN_THROUGHPUT_BYTES_PER_MS: u64 = 100;

pub fn scaled_transfer_timeout_ms(payload_size_bytes: u64) -> u64 {
    let scaled = TRANSFER_TIMEOUT_MIN_MS + (payload_size_bytes / TRANSFER_ASSUMED_MIN_THROUGHPUT_BYTES_PER_MS);
    scaled.min(TRANSFER_TIMEOUT_MAX_MS)
}

// ================================================================
// 7) Descriptor-tree shaping helpers used while building a DeviceDescriptor
// ================================================================
// `bridge.rs` is responsible for actually walking a live `nusb` device and
// producing the raw (class, subclass, protocol, packet size, ...) values;
// these two small pure helpers are the part of that process that encodes an
// actual spec rule, so they live here rather than in `bridge.rs`, and are
// unit-tested here.

/// Per spec (`USBAlternateInterface` construction algorithm): endpoint
/// descriptors for the Control transfer type never appear in
/// `USBAlternateInterface.endpoints` — control transfers go through
/// `controlTransferIn`/`controlTransferOut`, addressed by recipient, not
/// through an `USBEndpoint` at all. `bmAttributes`' low 2 bits `00` signal
/// Control; this returns `true` for exactly that case so callers can skip
/// it while walking a live interface's endpoint list.
pub fn is_control_endpoint(bm_attributes: u8) -> bool {
    (bm_attributes & 0x03) == 0x00
}

/// Maps a descriptor's endpoint-type bits (`bmAttributes & 0x03`) and
/// direction bit (`bEndpointAddress & 0x80`) into this crate's
/// `EndpointType`/`Direction` enums. Returns `None` for the Control type
/// (see `is_control_endpoint` — callers should have already filtered these
/// out) rather than guessing.
pub fn classify_endpoint(bm_attributes: u8, b_endpoint_address: u8) -> Option<(EndpointType, Direction)> {
    let endpoint_type = match bm_attributes & 0x03 {
        0x01 => EndpointType::Isochronous,
        0x02 => EndpointType::Bulk,
        0x03 => EndpointType::Interrupt,
        _ => return None, // 0x00 = Control
    };
    let direction = if (b_endpoint_address & 0x80) != 0 { Direction::In } else { Direction::Out };
    Some((endpoint_type, direction))
}

/// Is `endpoint` actually the isochronous type? Used by
/// `isochronousTransferIn`/`Out` to reject a call aimed at a non-isochronous
/// endpoint with `InvalidAccessError`, independent of whatever the caller
/// claims.
pub fn is_isochronous_endpoint(endpoint: &EndpointDescriptor) -> bool {
    endpoint.endpoint_type == EndpointType::Isochronous
}

// ================================================================
// 8) Interface-class resolution against the *active* configuration
// ================================================================
// Ported from `hardening.py`'s `interface_class_for()`. `bridge.rs`'s
// `interface_alternates()` (a different, complementary helper) returns
// *every* alternate setting for an interface number so a caller can make
// its own decision; this instead resolves down to a single "the" class,
// with two different meanings depending on whether the caller knows which
// alternate setting is actually current.

/// Resolves `interface_number`'s `bInterfaceClass` within the device's
/// *active* configuration only — never a non-active one, since a
/// multi-configuration device could coincidentally reuse the same
/// interface number for something else entirely in a configuration it
/// isn't currently running.
///
/// - `Some(alt)`: the class of the *exact* `(interface_number, alt)` pair,
///   or `None` if no such alternate setting exists. For a caller that
///   genuinely knows which alternate setting is (or is about to become)
///   selected: `claim_interface` (alternate setting 0 — the only one a
///   bare `claimInterface()` call ever activates, per spec) and
///   `select_alternate_interface` (the specific alternate being switched
///   to).
/// - `None` (conservative/fail-safe mode): scans *every* alternate setting
///   sharing this interface number. If any one of them is a protected
///   class, returns that class — regardless of which one is actually
///   selected right now — so `is_protected_interface_class` on the result
///   is `true` even if the *current* alternate setting happens to be
///   benign. Only when none of them are protected does it fall back to
///   the first match's class. `resolve_control_transfer_target` below
///   uses this mode for its `recipient == Interface` (and `class`
///   request-type) checks: a raw control transfer's `index` carries no
///   "currently selected alternate setting" concept at all — control
///   transfers address endpoint 0, not a specific alternate setting — so
///   there is no single correct alternate to check precisely, and
///   treating any protected alternate as disqualifying is the fail-safe
///   choice (see `security_report/VULNERABILITY_REPORT.md` finding No.1
///   in the reference `pyside6-webusb` project, and this module's own
///   tests below).
pub fn interface_class_for(descriptor: &DeviceDescriptor, interface_number: u8, alternate_setting: Option<u8>) -> Option<u8> {
    let active_value = descriptor.active_configuration_value?;
    let active_cfg = descriptor.configurations.iter().find(|c| c.configuration_value == active_value)?;
    let iface = active_cfg.interfaces.iter().find(|i| i.interface_number == interface_number)?;
    match alternate_setting {
        Some(alt) => iface.alternates.iter().find(|a| a.alternate_setting == alt).map(|a| a.interface_class),
        None => match iface.alternates.iter().find(|a| is_protected_interface_class(a.interface_class)) {
            Some(protected) => Some(protected.interface_class),
            None => iface.alternates.first().map(|a| a.interface_class),
        },
    }
}

/// `(interfaceNumber, alternateSetting, interfaceClass)` for every
/// alternate setting, on any interface, that declares an endpoint at this
/// exact address (`bEndpointAddress` — direction bit included) within the
/// device's *active* configuration. Used only by
/// `resolve_control_transfer_target`'s `recipient == Endpoint` handling
/// below; deliberately returns every match rather than the first, since
/// that check needs to know whether *any* of them is a protected class,
/// not just whichever happens to be findable first.
fn interfaces_owning_endpoint_address(descriptor: &DeviceDescriptor, endpoint_address: u8) -> Vec<(u8, u8, u8)> {
    let Some(active_value) = descriptor.active_configuration_value else { return Vec::new() };
    let Some(active_cfg) = descriptor.configurations.iter().find(|c| c.configuration_value == active_value) else {
        return Vec::new();
    };
    let mut owners = Vec::new();
    for iface in &active_cfg.interfaces {
        for alt in &iface.alternates {
            let declares_it = alt.endpoints.iter().any(|ep| {
                let direction_bit = if ep.direction == Direction::In { 0x80 } else { 0x00 };
                (ep.endpoint_number | direction_bit) == endpoint_address
            });
            if declares_it {
                owners.push((iface.interface_number, alt.alternate_setting, alt.interface_class));
            }
        }
    }
    owners
}

/// The standard (`bmRequestType` type `00`) request codes the WebUSB spec's
/// "check the validity of the control transfer parameters" algorithm
/// allows through `controlTransferIn`/`Out` at all: `GET_STATUS` (`0x00`),
/// `GET_DESCRIPTOR` (`0x06`), `GET_CONFIGURATION` (`0x08`),
/// `GET_INTERFACE` (`0x0A`), `SYNCH_FRAME` (`0x0C`). Every other standard
/// request (`SET_ADDRESS`, `SET_CONFIGURATION`, `SET_INTERFACE`, ...) would
/// let a page renegotiate device/interface state this plugin itself is
/// separately tracking (`claimed`/`active_alternate`) out from under it, or
/// simply has no legitimate role reachable through this API at all.
pub fn is_allowed_standard_control_request(request: u8) -> bool {
    matches!(request, 0x00 | 0x06 | 0x08 | 0x0A | 0x0C)
}

/// Ported from `bridge.py`'s `_control_transfer_validation_error()` — the
/// part of the WebUSB spec's "check the validity of the control transfer
/// parameters" algorithm that `nusb` itself does not perform.
///
/// `nusb`'s `Interface::endpoint()` (used for bulk/interrupt transfers — see
/// `bridge.rs`'s `resolve_transfer_endpoint`) is naturally scoped to
/// whichever specific claimed interface it's called on, because it looks up
/// the requested endpoint address in *that interface's own* current
/// descriptor. `Interface::control_in`/`control_out` have no equivalent
/// scoping: they accept *any* `recipient`/`index`, submitted on endpoint 0,
/// regardless of which claimed interface's handle happened to issue the
/// call — on every platform this plugin targets except Windows' WinUSB,
/// which only constrains the narrower `recipient == Interface` case (and
/// only to "the index's low byte matches whichever interface you're
/// calling through", not "matches a claimed, non-protected interface").
///
/// Without this check, a page could `claimInterface()` any single benign
/// interface and then send a `class`/`vendor` control transfer with
/// `recipient: 'interface'` or `'endpoint'` naming a *different*,
/// unclaimed, protected interface (HID, Mass Storage, ...) — a complete
/// bypass of `claimInterface()`'s own protected-class check, on every
/// non-Windows platform. See `security_report/VULNERABILITY_REPORT.md`
/// finding No.1 in the reference `pyside6-webusb` project this crate was
/// ported from, and this module's own tests below for the exact scenario.
///
/// Returns:
/// - `Ok(None)`: no interface-specific target. Safe to submit through
///   *any* already-claimed interface's handle (`bridge.rs` picks one —
///   see `any_claimed_interface`), or through `Device::control_in`/`_out`
///   directly where `nusb` offers it. This is the outcome for
///   `recipient == Device` or `Other`, unless `requestType == "class"`
///   (checked regardless of recipient, matching `bridge.py`).
/// - `Ok(Some(interface_number))`: safe to submit, and specifically
///   through *this* claimed interface's own handle — matters for
///   `recipient == Interface` on Windows (see `bridge.rs`'s call site);
///   harmless to also do on every other platform.
/// - `Err(_)`: reject the transfer outright, with the exact
///   `DOMException` kind `bridge.py`'s own version of this check used for
///   the equivalent case.
///
/// `is_claimed`/`active_alternate_of` are closures rather than a
/// `HashMap`/`HashSet` reference so this stays exercisable with trivial
/// hand-built test doubles (see below) without pulling `bridge.rs`'s
/// `nusb`-backed `OpenSession` shape into this module at all —
/// `active_alternate_of` should return `0` for an interface it has no
/// entry for, matching `bridge.py`'s own `alt_settings.get(iface_num, 0)`
/// (alternate setting 0 is always the spec-defined default before
/// `selectAlternateInterface()` is ever called).
pub fn resolve_control_transfer_target(
    descriptor: &DeviceDescriptor,
    is_claimed: impl Fn(u8) -> bool,
    active_alternate_of: impl Fn(u8) -> u8,
    request_type: ControlRequestType,
    recipient: ControlRecipient,
    request: u8,
    direction_in: bool,
    index: u16,
) -> Result<Option<u8>, WebUsbError> {
    if request_type == ControlRequestType::Standard {
        if !direction_in {
            return Err(WebUsbError::security("standard requests are not allowed for controlTransferOut"));
        }
        if !is_allowed_standard_control_request(request) {
            return Err(WebUsbError::security(format!(
                "standard request {request:#04x} is not one of the requests allowed by the WebUSB \
                 spec (GET_STATUS/GET_DESCRIPTOR/GET_CONFIGURATION/GET_INTERFACE/SYNCH_FRAME)"
            )));
        }
    }

    // Checked regardless of `recipient` — a `class` request whose
    // `recipient` is `Device`/`Other` has no interface-specific target at
    // all (falls through to `Ok(None)` below), but one whose `index`
    // *does* name a protected interface must still be rejected even if
    // `recipient` technically says otherwise, matching `bridge.py` exactly.
    if request_type == ControlRequestType::Class {
        let iface_number = (index & 0xFF) as u8;
        if let Some(iface_class) = interface_class_for(descriptor, iface_number, None) {
            if is_protected_interface_class(iface_class) {
                return Err(WebUsbError::security(format!(
                    "interface {iface_number} is class {iface_class:#04x} ('{}'), a protected interface \
                     class, and cannot receive class-specific control requests",
                    protected_class_name(iface_class)
                )));
            }
        }
    }

    match recipient {
        ControlRecipient::Interface => {
            let iface_number = (index & 0xFF) as u8;
            let iface_class = interface_class_for(descriptor, iface_number, None)
                .ok_or_else(|| WebUsbError::not_found(format!("interface {iface_number} was not found on this device")))?;
            if is_protected_interface_class(iface_class) {
                return Err(WebUsbError::security(format!(
                    "interface {iface_number} is class {iface_class:#04x} ('{}'), a protected interface class",
                    protected_class_name(iface_class)
                )));
            }
            if !is_claimed(iface_number) {
                return Err(WebUsbError::invalid_state(format!("interface {iface_number} has not been claimed")));
            }
            Ok(Some(iface_number))
        }
        ControlRecipient::Endpoint => {
            let endpoint_address = (index & 0xFF) as u8;
            let owners = interfaces_owning_endpoint_address(descriptor, endpoint_address);
            if owners.is_empty() {
                return Err(WebUsbError::not_found(format!("endpoint {endpoint_address:#04x} was not found on this device")));
            }
            // 🛡️ Fail-safe, same reasoning as the `None`-mode of
            // `interface_class_for` above: if *any* alternate setting that
            // declares this endpoint address is a protected class, reject
            // outright, even if the one currently selected is not.
            if let Some(&(_, _, protected_class)) = owners.iter().find(|&&(_, _, cls)| is_protected_interface_class(cls)) {
                return Err(WebUsbError::security(format!(
                    "endpoint {endpoint_address:#04x} belongs to interface class {protected_class:#04x} \
                     ('{}'), a protected interface class",
                    protected_class_name(protected_class)
                )));
            }
            let owner_number = owners
                .iter()
                .find(|&&(iface_num, alt_num, _)| active_alternate_of(iface_num) == alt_num)
                .or_else(|| owners.first())
                .map(|&(iface_num, _, _)| iface_num)
                .expect("owners is non-empty, checked above");
            if !is_claimed(owner_number) {
                return Err(WebUsbError::invalid_state(format!(
                    "interface {owner_number} owning endpoint {endpoint_address:#04x} has not been claimed"
                )));
            }
            Ok(Some(owner_number))
        }
        ControlRecipient::Device | ControlRecipient::Other => Ok(None),
    }
}

/// Real Chrome's `USBDevice::EnsureEndpointAvailable()` (confirmed against
/// `third_party/blink/renderer/modules/webusb/usb_device.cc`) rejects any
/// `endpointNumber` outside `1..=15` with `IndexSizeError` before even
/// looking for the endpoint: `0` is reserved for control transfers (not
/// reachable through `transferIn`/`Out`/`clearHalt` at all — see
/// `USBControlTransferParameters` instead), and only 4 bits of endpoint
/// number exist in the first place.
pub fn is_valid_transfer_endpoint_number(endpoint_number: u8) -> bool {
    (1..=15).contains(&endpoint_number)
}

/// Ported from `bridge.py`'s `_endpoint_available_or_error()` (itself
/// citing real Chrome's `USBDevice::EnsureEndpointAvailable()`): the
/// precondition `transferIn`/`Out` and `clearHalt` must all check before
/// touching a device at all — the target endpoint must belong to an
/// interface that is both currently claimed *and* currently sitting at the
/// one alternate setting that actually declares it.
///
/// Without this, a page could read/write a protected (HID, Mass Storage,
/// ...) interface's bulk/interrupt endpoints having never called
/// `claimInterface()` at all — a complete bypass of its protected-class
/// check for every operation *except* control transfers, which is a
/// different, narrower bypass already covered by
/// `resolve_control_transfer_target` above. See
/// `security_report/VULNERABILITY_REPORT.md` finding No.1 in the reference
/// `pyside6-webusb` project (the same finding as
/// `resolve_control_transfer_target`'s doc comment, extended to a second,
/// independent code path both predecessors originally missed there too).
///
/// Deliberately searches *only* claimed interfaces at their current
/// alternate setting and folds every failure into the same `NotFoundError`
/// — unlike `resolve_control_transfer_target`'s endpoint-recipient branch,
/// this does not distinguish "no such endpoint anywhere on the device"
/// from "that endpoint exists, but on an interface you haven't claimed (or
/// haven't switched to the right alternate setting for)": both look
/// identical to the caller, matching `bridge.py`'s own choice here (the two
/// checks were independently hardened at different points in that
/// project's history and ended up with two different, both intentional,
/// error-shape choices for a similar-looking scenario — see that
/// function's own doc comment).
///
/// Returns the owning interface number and a clone of its endpoint
/// descriptor (type, packet size) together, resolved from the exact same
/// (interface, alternate setting) pair, so a caller can never end up using
/// one interface's claim to submit a transfer shaped by a *different*
/// interface's — possibly different — descriptor for the same nominal
/// endpoint number.
pub fn resolve_transfer_endpoint_owner(
    descriptor: &DeviceDescriptor,
    is_claimed: impl Fn(u8) -> bool,
    active_alternate_of: impl Fn(u8) -> u8,
    endpoint_address: u8,
) -> Result<(u8, EndpointDescriptor), WebUsbError> {
    let not_found = || {
        WebUsbError::not_found(format!(
            "endpoint {endpoint_address:#04x} is not part of a claimed and selected alternate interface"
        ))
    };
    // Matches `bridge.py` distinguishing "no configuration selected at
    // all" (`InvalidStateError`) from "that endpoint isn't reachable given
    // the current claims/alternate settings" (`NotFoundError`) below —
    // different `DOMException` names for two genuinely different
    // situations, even though both ultimately mean "this transfer can't
    // proceed".
    let Some(active_value) = descriptor.active_configuration_value else {
        return Err(WebUsbError::invalid_state("the device must have a configuration selected"));
    };
    let Some(active_cfg) = descriptor.configurations.iter().find(|c| c.configuration_value == active_value) else {
        return Err(WebUsbError::invalid_state("the device must have a configuration selected"));
    };
    for iface in &active_cfg.interfaces {
        if !is_claimed(iface.interface_number) {
            continue;
        }
        let current_alt = active_alternate_of(iface.interface_number);
        let Some(alt) = iface.alternates.iter().find(|a| a.alternate_setting == current_alt) else { continue };
        let found = alt.endpoints.iter().find(|ep| {
            let direction_bit = if ep.direction == Direction::In { 0x80 } else { 0x00 };
            (ep.endpoint_number | direction_bit) == endpoint_address
        });
        if let Some(ep) = found {
            return Ok((iface.interface_number, ep.clone()));
        }
    }
    Err(not_found())
}

// ================================================================
// 9) Device-supplied string sanitization
// ================================================================
// Ported from `hardening.py`'s `sanitize_device_string()`, added in
// pyside6-webusb v0.0.4b3 as the fix for
// `security_report/VULNERABILITY_REPORT.md` finding No.3: manufacturer/
// product/serial/configuration/interface-name strings come straight from
// the connected USB device's own string descriptors — entirely under a
// potentially hostile device's control, and more so than an error message
// (which at least passes through this implementation's own formatting
// first — see `error.rs`'s `sanitize_message`). Two independent attacks
// this closes:
//
//   - Bidi-override spoofing: U+202A-U+202E (LRE/RLE/PDF/LRO/RLO) and
//     U+2066-U+2069 (LRI/RLI/FSI/PDI) can reorder how surrounding
//     characters *display* without changing the underlying text — the same
//     family of trick used to disguise filenames (e.g. making "cod.exe"
//     display as "exe.doc"), applicable here to a device name shown in the
//     chooser window (`chooser-ui/index.html`) or any UI a consuming app
//     builds from `getDevices()`/`requestDevice()`'s result.
//   - Unbounded length: nothing before this stopped a device from
//     returning a multi-megabyte string descriptor, which would otherwise
//     flow straight into `DeviceDescriptor`, then JSON, then a UI.
//
// Unlike pyside6-webusb's chooser (a native `QLabel` that separately needed
// `setTextFormat(Qt.TextFormat.PlainText)` to stop interpreting a device
// string as rich text/HTML at all), `chooser-ui/index.html` here already
// only ever inserts these strings via `Node.textContent` — never
// `innerHTML` — so there is no analogous markup-injection angle to close.
// Sanitizing here is still worthwhile in its own right: it's the *one*
// place that benefits every consumer (the chooser window, any UI the
// embedding app itself builds from `USBDevice`/`USBConfiguration`/
// `USBInterface`, any log line), matching `hardening.py`'s own reasoning
// for sanitizing at the source rather than only at whichever one call site
// happened to prompt the finding.

/// Same nine code points `hardening.py` strips: U+202A-U+202E (bidi
/// override/embedding) and U+2066-U+2069 (bidi isolate).
const BIDI_OVERRIDE_CHARS: [char; 9] =
    ['\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}'];

/// Conservative ceiling, well past any real USB string descriptor's
/// practical length (a one-byte `bLength` caps the underlying UTF-16LE
/// descriptor at 253 bytes of text to begin with) — this exists for
/// devices that don't honor that, not for any legitimate one. Matches
/// `hardening.py`'s `_DEVICE_STRING_MAX_LEN`.
pub const DEVICE_STRING_MAX_LEN: usize = 255;

/// Sanitizes one USB-device-supplied string (`manufacturerName`,
/// `productName`, `serialNumber`, `configurationName`, `interfaceName`) for
/// safe display and JSON transport: strips every C0 (U+0000-U+001F) and C1
/// (U+007F-U+009F) control character, strips the bidi-override/isolate
/// characters above, then truncates to `max_len` *characters* (not UTF-8
/// bytes) with a trailing `…` if anything was actually cut.
pub fn sanitize_device_string(value: &str, max_len: usize) -> String {
    let cleaned: String = value
        .chars()
        .filter(|&ch| !matches!(ch, '\u{0000}'..='\u{001F}' | '\u{007F}'..='\u{009F}'))
        .filter(|ch| !BIDI_OVERRIDE_CHARS.contains(ch))
        .collect();
    if cleaned.chars().count() > max_len {
        let mut truncated: String = cleaned.chars().take(max_len).collect();
        truncated.push('…');
        truncated
    } else {
        cleaned
    }
}

/// Convenience wrapper for the common `Option<String>` shape every actual
/// device-supplied name field has: `None` means the device has no such
/// descriptor at all (a meaningful, legitimate value — iManufacturer/etc.
/// being `0` — not something to sanitize into an empty string), so it
/// passes straight through.
pub fn sanitize_device_string_opt(value: Option<String>) -> Option<String> {
    value.map(|v| sanitize_device_string(&v, DEVICE_STRING_MAX_LEN))
}

// ================================================================
// 10) Request-shape bounds (resource-exhaustion defense-in-depth)
// ================================================================
// Ported from pyside6-webusb v0.0.5.post5's "hardened options and base64
// payload boundaries": every one of these bounds a worst-case allocation
// or iteration count *before* doing it, rather than only checking the
// result afterward. None of these are WebUSB spec requirements — Chrome
// itself has no documented limit on filter-array length, for instance —
// they exist purely so a single malicious/buggy call can't force this
// process into an unbounded allocation, matching section 5's
// `HOST_SAFETY_MAX_TRANSFER_LENGTH` in spirit.

/// `requestDevice()`'s `filters`/`exclusionFilters` are each capped at this
/// many entries. Real pages pass a handful (single digits); this is
/// generous headroom over that, not a realistic legitimate value — without
/// *some* cap, `commands.rs` would happily deserialize (and then
/// `hardening::device_matches_any_usb_filter` would iterate) an
/// attacker-sized array on every call to `getDevices()`/`requestDevice()`.
pub const MAX_DEVICE_FILTERS: usize = 64;

/// `isochronousTransferIn`/`Out`'s `packetLengths` array is capped at this
/// many entries. Real USB isochronous scheduling tops out at a few hundred
/// packets per transfer at most (one microframe per 125µs/1ms, batched);
/// this is generous headroom over that. Bounding the *count* matters
/// independently of bounding the *sum* (already enforced via
/// `ISOCHRONOUS_TRANSFER_MAX_TOTAL_LENGTH`) — a `Vec` of a million `0`-byte
/// packet lengths sums to zero but still costs real memory and iteration
/// time to build and walk.
pub const MAX_ISOCHRONOUS_PACKETS: usize = 4096;

/// The longest a base64-encoded `transferOut`/`controlTransferOut`/
/// `isochronousTransferOut` payload string is allowed to be, *before*
/// attempting to decode it. Base64 inflates size by 4/3; checking the
/// *encoded* string's length against this bound (rather than only checking
/// the *decoded* byte count afterward, against
/// `HOST_SAFETY_MAX_TRANSFER_LENGTH`) means a call carrying an
/// attacker-sized base64 string gets rejected before this process commits
/// to allocating and decoding it at all. The `+ 4` covers base64's own
/// padding characters at the smallest possible margin; the real slack here
/// is `/ 3 * 4` rounding generously.
pub const MAX_BASE64_PAYLOAD_CHARS: usize = ((HOST_SAFETY_MAX_TRANSFER_LENGTH as usize) / 3) * 4 + 4;

// ================================================================
// 11) Gesture-token policy (requestDevice() user-activation proof)
// ================================================================
// Ported from `bridge.py`'s `mintGestureToken()`/`_consume_gesture_token()`,
// added in pyside6-webusb v0.0.4b3 as the fix for
// `security_report/VULNERABILITY_REPORT.md` finding No.2's user-gesture
// half (the filter-validity half is `is_valid_usb_device_filter` above,
// already enforced server-side in this crate from the start — see
// `commands.rs`). The actual token cache lives in `gesture.rs`, which
// needs `tokio::sync::Mutex` and `std::time::Instant` and so doesn't belong
// in this dependency-free module — these are just the tunable policy
// constants, kept here alongside every other security-relevant constant in
// the crate rather than buried in the module that happens to enforce them.
//
// `guest-js/src/polyfill.ts`'s `requestDevice()` already checks
// `navigator.userActivation.isActive` before calling into Rust at all —
// but that check runs in the *page's own JS context*, which any other
// script on the same page (or a direct `invoke("plugin:webusb|request_device",
// ...)` call bypassing the polyfill entirely — Tauri's IPC bridge is
// reachable from any script in a webview holding the `webusb:default`
// capability, not gated behind importing this package) can simply skip.
// `mint_gesture_token` (a separate command, in the same permission set —
// see `permissions/default.toml`) is what `polyfill.ts` calls *at* the
// moment it confirms a real user activation is active; `request_device`
// then requires and consumes that exact token server-side before ever
// showing the chooser window. This raises the bar substantially without
// being a perfect guarantee against a sufficiently determined scripted
// attacker that also mints its own token via the same bypass — matching
// `bridge.py`'s own documented caveat for the identical limitation.
pub const GESTURE_TOKEN_TTL_SECS: u64 = 5;
pub const GESTURE_TOKEN_CACHE_CAP: usize = 64;

// ================================================================
// 12) Per-origin open-handle cap (security_report finding No.6)
// ================================================================
// Ported from `bridge.py`'s `_MAX_OPEN_HANDLES_PER_ORIGIN`, added in
// pyside6-webusb v0.0.4b3: an ordinary page holding one legitimate grant
// could otherwise grow this plugin's session table without bound just by
// calling `device.open()` in a loop and never closing the results — no
// bypass of any kind needed. That consumes memory in the *host
// application's own process* (this plugin lives in-process with the
// consuming Tauri app, unlike a browser tab's separately-sandboxed
// renderer), so it isn't bounded by anything else already in place.
/// Generous headroom over any legitimate use `bridge.py`'s own audit fix
/// identified — see `bridge.rs`'s `open_device` for the LRU-eviction
/// policy this backs (opening past the cap evicts that origin's *oldest*
/// still-open handle rather than failing the new `open()` call, matching
/// `bridge.py` exactly).
pub const MAX_OPEN_HANDLES_PER_ORIGIN: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;

    // ---- protected interface classes ----

    #[test]
    fn all_eight_protected_classes_are_flagged() {
        for &(class, _name) in PROTECTED_INTERFACE_CLASSES {
            assert!(is_protected_interface_class(class), "class {class:#04x} should be protected");
        }
        assert_eq!(PROTECTED_INTERFACE_CLASSES.len(), 8);
    }

    #[test]
    fn vendor_specific_class_is_not_protected() {
        assert!(!is_protected_interface_class(0xFF));
    }

    #[test]
    fn cdc_data_class_is_not_protected() {
        // 0x0A = CDC-Data, a common, unprotected class (serial-over-USB
        // devices like microcontrollers/ADB) — a regression here would
        // accidentally lock out huge swaths of legitimate WebUSB hardware.
        assert!(!is_protected_interface_class(0x0A));
    }

    #[test]
    fn protected_class_name_is_known_for_protected_classes_and_unknown_otherwise() {
        assert_eq!(protected_class_name(0x03), "HID (Human Interface Device: most security keys/keyboards/mice)");
        assert_eq!(protected_class_name(0xFF), "Unknown");
    }

    // ---- blocklist ----

    #[test]
    fn blocklist_matches_known_pair() {
        assert!(is_blocklisted_device(0x1050, 0x0407));
    }

    #[test]
    fn blocklist_does_not_match_unrelated_pair() {
        assert!(!is_blocklisted_device(0x1050, 0xdead));
        assert!(!is_blocklisted_device(0x9999, 0x0407));
    }

    #[test]
    fn blocklist_is_vendor_and_product_specific_not_vendor_alone() {
        // 0x096e has several blocklisted PIDs but not all of them.
        assert!(is_blocklisted_device(0x096e, 0x0850));
        assert!(!is_blocklisted_device(0x096e, 0x0001));
    }

    fn minimal_device(vendor_id: u16, product_id: u16) -> DeviceDescriptor {
        DeviceDescriptor {
            vendor_id, product_id,
            manufacturer_name: None, product_name: None, serial_number: None,
            device_class: 0, device_subclass: 0, device_protocol: 0,
            usb_version_major: 2, usb_version_minor: 0, usb_version_subminor: 0,
            device_version_major: 1, device_version_minor: 0, device_version_subminor: 0,
            configurations: vec![],
            active_configuration_value: None,
            connect_count: None,
        }
    }

    #[test]
    fn device_is_fully_blocked_delegates_to_blocklist() {
        assert!(device_is_fully_blocked(&minimal_device(0x1050, 0x0407)));
        assert!(!device_is_fully_blocked(&minimal_device(0x1050, 0x9999)));
    }

    // ---- BCD ----

    #[test]
    fn bcd_decodes_standard_usb_2_1_0() {
        assert_eq!(bcd_to_version(0x0210), (2, 1, 0));
    }

    #[test]
    fn bcd_decodes_usb_1_1_0() {
        assert_eq!(bcd_to_version(0x0110), (1, 1, 0));
    }

    #[test]
    fn bcd_decodes_zero() {
        assert_eq!(bcd_to_version(0x0000), (0, 0, 0));
    }

    #[test]
    fn bcd_decodes_usb_3_2_1_with_nonzero_subminor() {
        assert_eq!(bcd_to_version(0x0321), (3, 2, 1));
    }

    // ---- filter validity ----

    #[test]
    fn empty_filter_is_valid() {
        assert!(is_valid_usb_device_filter(&UsbDeviceFilter::default()));
    }

    #[test]
    fn product_id_without_vendor_id_is_invalid() {
        let f = UsbDeviceFilter { product_id: Some(1), ..Default::default() };
        assert!(!is_valid_usb_device_filter(&f));
    }

    #[test]
    fn vendor_and_product_id_together_is_valid() {
        let f = UsbDeviceFilter { vendor_id: Some(1), product_id: Some(2), ..Default::default() };
        assert!(is_valid_usb_device_filter(&f));
    }

    #[test]
    fn subclass_without_class_is_invalid() {
        let f = UsbDeviceFilter { subclass_code: Some(1), ..Default::default() };
        assert!(!is_valid_usb_device_filter(&f));
    }

    #[test]
    fn protocol_without_subclass_is_invalid_even_with_class_present() {
        let f = UsbDeviceFilter { class_code: Some(1), protocol_code: Some(1), ..Default::default() };
        assert!(!is_valid_usb_device_filter(&f));
    }

    #[test]
    fn fully_specified_class_hierarchy_is_valid() {
        let f = UsbDeviceFilter {
            class_code: Some(1), subclass_code: Some(2), protocol_code: Some(3), ..Default::default()
        };
        assert!(is_valid_usb_device_filter(&f));
    }

    // ---- filter matching ----

    fn device_with_interface(device_class: u8, iface_class: u8, iface_sub: u8, iface_proto: u8) -> DeviceDescriptor {
        let mut d = minimal_device(0x1234, 0x5678);
        d.device_class = device_class;
        d.configurations.push(ConfigurationDescriptor {
            configuration_value: 1,
            configuration_name: None,
            interfaces: vec![InterfaceDescriptor {
                interface_number: 0,
                alternates: vec![AlternateInterfaceDescriptor {
                    alternate_setting: 0,
                    interface_class: iface_class,
                    interface_subclass: iface_sub,
                    interface_protocol: iface_proto,
                    interface_protected: is_protected_interface_class(iface_class),
                    interface_name: None,
                    endpoints: vec![],
                }],
            }],
        });
        d
    }

    #[test]
    fn matches_on_vendor_and_product_id() {
        let d = minimal_device(0x1234, 0x5678);
        let f = UsbDeviceFilter { vendor_id: Some(0x1234), product_id: Some(0x5678), ..Default::default() };
        assert!(device_matches_usb_filter(&d, &f));
    }

    #[test]
    fn rejects_on_product_id_mismatch() {
        let d = minimal_device(0x1234, 0x5678);
        let f = UsbDeviceFilter { vendor_id: Some(0x1234), product_id: Some(0x0000), ..Default::default() };
        assert!(!device_matches_usb_filter(&d, &f));
    }

    #[test]
    fn matches_on_serial_number() {
        let mut d = minimal_device(1, 2);
        d.serial_number = Some("SN123".into());
        let f = UsbDeviceFilter { serial_number: Some("SN123".into()), ..Default::default() };
        assert!(device_matches_usb_filter(&d, &f));
    }

    #[test]
    fn serial_number_mismatch_rejects_even_if_other_fields_absent() {
        let mut d = minimal_device(1, 2);
        d.serial_number = Some("SN123".into());
        let f = UsbDeviceFilter { serial_number: Some("OTHER".into()), ..Default::default() };
        assert!(!device_matches_usb_filter(&d, &f));
    }

    #[test]
    fn missing_serial_number_on_device_does_not_match_a_serial_filter() {
        let d = minimal_device(1, 2); // serial_number: None
        let f = UsbDeviceFilter { serial_number: Some("SN123".into()), ..Default::default() };
        assert!(!device_matches_usb_filter(&d, &f));
    }

    #[test]
    fn class_filter_matches_device_level_class() {
        let d = device_with_interface(0x08, 0xFF, 0, 0); // device class itself is Mass Storage
        let f = UsbDeviceFilter { class_code: Some(0x08), ..Default::default() };
        assert!(device_matches_usb_filter(&d, &f));
    }

    #[test]
    fn class_filter_matches_via_composite_device_interface_class() {
        // Device declares 0xFF (vendor-specific) at the device level (as
        // composite devices commonly do) but has an interface claiming a
        // real class — the spec's "any interface matches" fallback must
        // still find it.
        let d = device_with_interface(0xFF, 0x0A, 0x00, 0x00); // interface class = CDC-Data
        let f = UsbDeviceFilter { class_code: Some(0x0A), ..Default::default() };
        assert!(device_matches_usb_filter(&d, &f));
    }

    #[test]
    fn class_filter_with_subclass_and_protocol_narrows_interface_match() {
        let d = device_with_interface(0xFF, 0x0A, 0x01, 0x02);
        let matching = UsbDeviceFilter {
            class_code: Some(0x0A), subclass_code: Some(0x01), protocol_code: Some(0x02), ..Default::default()
        };
        let non_matching = UsbDeviceFilter {
            class_code: Some(0x0A), subclass_code: Some(0x01), protocol_code: Some(0x99), ..Default::default()
        };
        assert!(device_matches_usb_filter(&d, &matching));
        assert!(!device_matches_usb_filter(&d, &non_matching));
    }

    #[test]
    fn class_filter_rejects_when_neither_device_nor_any_interface_matches() {
        let d = device_with_interface(0xFF, 0x0A, 0, 0);
        let f = UsbDeviceFilter { class_code: Some(0x03), ..Default::default() }; // looking for HID
        assert!(!device_matches_usb_filter(&d, &f));
    }

    #[test]
    fn any_filter_empty_list_matches_nothing() {
        let d = minimal_device(1, 2);
        assert!(!device_matches_any_usb_filter(&d, &[]));
    }

    #[test]
    fn any_filter_single_empty_object_matches_everything() {
        let d = minimal_device(1, 2);
        assert!(device_matches_any_usb_filter(&d, &[UsbDeviceFilter::default()]));
    }

    #[test]
    fn any_filter_matches_if_any_one_of_several_filters_matches() {
        let d = minimal_device(1, 2);
        let filters = vec![
            UsbDeviceFilter { vendor_id: Some(999), ..Default::default() },
            UsbDeviceFilter { vendor_id: Some(1), ..Default::default() },
        ];
        assert!(device_matches_any_usb_filter(&d, &filters));
    }

    // ---- transfer-size policy ----

    #[test]
    fn no_warning_at_or_under_chrome_limit() {
        assert!(chrome_transfer_limit_warning(CHROME_TRANSFER_WARN_LENGTH).is_none());
        assert!(chrome_transfer_limit_warning(1024).is_none());
    }

    #[test]
    fn warning_one_byte_over_chrome_limit() {
        let w = chrome_transfer_limit_warning(CHROME_TRANSFER_WARN_LENGTH + 1);
        assert!(w.is_some());
        assert!(w.unwrap().contains("not Chrome"));
    }

    #[test]
    fn host_safety_ceiling_is_well_above_chrome_reference_limit() {
        assert!(HOST_SAFETY_MAX_TRANSFER_LENGTH > CHROME_TRANSFER_WARN_LENGTH);
        assert_eq!(BULK_TRANSFER_MAX_LENGTH, HOST_SAFETY_MAX_TRANSFER_LENGTH);
        assert_eq!(ISOCHRONOUS_TRANSFER_MAX_TOTAL_LENGTH, HOST_SAFETY_MAX_TRANSFER_LENGTH);
    }

    #[test]
    fn control_transfer_max_length_matches_webidl_unsigned_short() {
        assert_eq!(CONTROL_TRANSFER_MAX_LENGTH, 65535);
    }

    // ---- timeout scaling ----

    #[test]
    fn tiny_transfer_gets_minimum_timeout() {
        assert_eq!(scaled_transfer_timeout_ms(0), TRANSFER_TIMEOUT_MIN_MS);
        assert_eq!(scaled_transfer_timeout_ms(10), TRANSFER_TIMEOUT_MIN_MS);
    }

    #[test]
    fn huge_transfer_is_capped_at_maximum_timeout() {
        assert_eq!(scaled_transfer_timeout_ms(u64::MAX / 2), TRANSFER_TIMEOUT_MAX_MS);
    }

    #[test]
    fn timeout_scales_with_payload_size() {
        let small = scaled_transfer_timeout_ms(1_000);
        let large = scaled_transfer_timeout_ms(1_000_000);
        assert!(large > small);
        assert!(large <= TRANSFER_TIMEOUT_MAX_MS);
    }

    // ---- endpoint classification ----

    #[test]
    fn control_endpoint_bits_are_detected() {
        assert!(is_control_endpoint(0b0000_0000));
        assert!(!is_control_endpoint(0b0000_0001)); // isochronous
        assert!(!is_control_endpoint(0b0000_0010)); // bulk
        assert!(!is_control_endpoint(0b0000_0011)); // interrupt
    }

    #[test]
    fn classify_endpoint_returns_none_for_control() {
        assert_eq!(classify_endpoint(0b00, 0x81), None);
    }

    #[test]
    fn classify_endpoint_maps_bulk_in() {
        assert_eq!(classify_endpoint(0b10, 0x81), Some((EndpointType::Bulk, Direction::In)));
    }

    #[test]
    fn classify_endpoint_maps_bulk_out() {
        assert_eq!(classify_endpoint(0b10, 0x01), Some((EndpointType::Bulk, Direction::Out)));
    }

    #[test]
    fn classify_endpoint_maps_interrupt_and_isochronous() {
        assert_eq!(classify_endpoint(0b11, 0x83), Some((EndpointType::Interrupt, Direction::In)));
        assert_eq!(classify_endpoint(0b01, 0x02), Some((EndpointType::Isochronous, Direction::Out)));
    }

    #[test]
    fn is_isochronous_endpoint_checks_the_type_field() {
        let iso = EndpointDescriptor { endpoint_number: 1, direction: Direction::In, endpoint_type: EndpointType::Isochronous, packet_size: 1024 };
        let bulk = EndpointDescriptor { endpoint_number: 1, direction: Direction::In, endpoint_type: EndpointType::Bulk, packet_size: 512 };
        assert!(is_isochronous_endpoint(&iso));
        assert!(!is_isochronous_endpoint(&bulk));
    }

    // ---- test fixtures: a composite device shaped for the alternate-setting
    // class confusion scenario (security_report/VULNERABILITY_REPORT.md No.1)
    // -- interface 0's alternate setting 0 is innocuous vendor-specific with a
    // bulk IN endpoint at 0x81; alternate setting 1 of that *same* interface
    // number is HID (protected) with an interrupt IN endpoint at 0x82.
    // Interface 5 exists purely as an "another benign, claimable interface"
    // control. ----

    fn alt(alternate_setting: u8, class: u8, protected: bool, endpoints: Vec<EndpointDescriptor>) -> AlternateInterfaceDescriptor {
        AlternateInterfaceDescriptor {
            alternate_setting,
            interface_class: class,
            interface_subclass: 0,
            interface_protocol: 0,
            interface_protected: protected,
            interface_name: None,
            endpoints,
        }
    }

    fn ep(number: u8, direction: Direction, endpoint_type: EndpointType) -> EndpointDescriptor {
        EndpointDescriptor { endpoint_number: number, direction, endpoint_type, packet_size: 64 }
    }

    fn confused_composite_device() -> DeviceDescriptor {
        DeviceDescriptor {
            vendor_id: 0x1234,
            product_id: 0x5678,
            manufacturer_name: None,
            product_name: None,
            serial_number: None,
            device_class: 0,
            device_subclass: 0,
            device_protocol: 0,
            usb_version_major: 2,
            usb_version_minor: 0,
            usb_version_subminor: 0,
            device_version_major: 1,
            device_version_minor: 0,
            device_version_subminor: 0,
            active_configuration_value: Some(1),
            connect_count: None,
            configurations: vec![ConfigurationDescriptor {
                configuration_value: 1,
                configuration_name: None,
                interfaces: vec![
                    InterfaceDescriptor {
                        interface_number: 0,
                        alternates: vec![
                            alt(0, 0xFF, false, vec![ep(1, Direction::In, EndpointType::Bulk)]), // 0x81, benign
                            alt(1, 0x03, true, vec![ep(2, Direction::In, EndpointType::Interrupt)]), // 0x82, HID
                        ],
                    },
                    InterfaceDescriptor { interface_number: 5, alternates: vec![alt(0, 0xFF, false, vec![])] },
                ],
            }],
        }
    }

    // ---- interface_class_for ----

    #[test]
    fn interface_class_for_specific_alt_returns_that_alts_class_only() {
        let d = confused_composite_device();
        assert_eq!(interface_class_for(&d, 0, Some(0)), Some(0xFF));
        assert_eq!(interface_class_for(&d, 0, Some(1)), Some(0x03));
    }

    #[test]
    fn interface_class_for_specific_nonexistent_alt_is_none() {
        let d = confused_composite_device();
        assert_eq!(interface_class_for(&d, 0, Some(9)), None);
    }

    #[test]
    fn interface_class_for_none_mode_is_conservative_about_any_protected_alt() {
        let d = confused_composite_device();
        // Alternate setting 0 alone is benign, but alternate setting 1 of the
        // *same* interface number is HID -- fail-safe mode must surface that,
        // not whichever alternate happens to be first.
        assert_eq!(interface_class_for(&d, 0, None), Some(0x03));
    }

    #[test]
    fn interface_class_for_none_mode_falls_back_to_first_when_none_protected() {
        let d = confused_composite_device();
        assert_eq!(interface_class_for(&d, 5, None), Some(0xFF));
    }

    #[test]
    fn interface_class_for_nonexistent_interface_is_none() {
        let d = confused_composite_device();
        assert_eq!(interface_class_for(&d, 99, None), None);
    }

    // ---- resolve_control_transfer_target: the actual security_report No.1 scenario ----

    #[test]
    fn control_transfer_endpoint_recipient_rejects_the_hidden_hid_endpoint() {
        let d = confused_composite_device();
        // Interface 0 is claimed and currently sitting at alternate setting 0
        // (the benign one) -- exactly the state after a legitimate
        // `claimInterface(0)` with no `selectAlternateInterface()` call.
        let is_claimed = |n: u8| n == 0;
        let active_alt = |n: u8| if n == 0 { 0 } else { 0 };
        let err = resolve_control_transfer_target(
            &d, is_claimed, active_alt, ControlRequestType::Vendor, ControlRecipient::Endpoint, 0x01, true, 0x82,
        )
        .expect_err("endpoint 0x82 only exists under HID alternate setting 1 and must be rejected");
        assert_eq!(err.kind, crate::error::ErrorKind::Security);
        assert!(err.message.contains("0x82"), "message should name the endpoint: {}", err.message);
    }

    #[test]
    fn control_transfer_endpoint_recipient_allows_the_claimed_current_alt_endpoint() {
        let d = confused_composite_device();
        let is_claimed = |n: u8| n == 0;
        let active_alt = |_: u8| 0;
        let target = resolve_control_transfer_target(
            &d, is_claimed, active_alt, ControlRequestType::Vendor, ControlRecipient::Endpoint, 0x01, true, 0x81,
        )
        .expect("endpoint 0x81 belongs to the claimed, currently-selected, non-protected alternate 0");
        assert_eq!(target, Some(0));
    }

    #[test]
    fn control_transfer_interface_recipient_rejects_interface_with_any_protected_alt() {
        let d = confused_composite_device();
        let is_claimed = |n: u8| n == 0;
        let active_alt = |_: u8| 0;
        // Targeting interface 0 directly (recipient: interface) must fail
        // even though alternate setting 0 -- the one actually selected -- is
        // itself benign, because alternate setting 1 is HID. This is the
        // conservative (fail-safe) half of the fix: claimInterface() itself
        // already refuses to claim interface 0 at all in tauri-webusb's own
        // `claim_interface` (see bridge.rs), so this case would only be
        // reachable at all through some other implementation's more
        // permissive claim policy -- exercised here purely to confirm this
        // function's own check doesn't depend on that.
        let err = resolve_control_transfer_target(
            &d, is_claimed, active_alt, ControlRequestType::Vendor, ControlRecipient::Interface, 0x01, true, 0,
        )
        .expect_err("interface 0 has a protected alternate setting");
        assert_eq!(err.kind, crate::error::ErrorKind::Security);
    }

    #[test]
    fn control_transfer_interface_recipient_rejects_unclaimed_interface() {
        let d = confused_composite_device();
        let is_claimed = |_: u8| false; // nothing claimed at all
        let active_alt = |_: u8| 0;
        let err = resolve_control_transfer_target(
            &d, is_claimed, active_alt, ControlRequestType::Vendor, ControlRecipient::Interface, 0x01, true, 5,
        )
        .expect_err("interface 5 exists and is benign but was never claimed");
        assert_eq!(err.kind, crate::error::ErrorKind::InvalidState);
    }

    #[test]
    fn control_transfer_interface_recipient_reports_nonexistent_interface_as_not_found() {
        let d = confused_composite_device();
        let err = resolve_control_transfer_target(
            &d, |_| true, |_| 0, ControlRequestType::Vendor, ControlRecipient::Interface, 0x01, true, 42,
        )
        .expect_err("interface 42 does not exist on this device");
        assert_eq!(err.kind, crate::error::ErrorKind::NotFound);
    }

    #[test]
    fn control_transfer_endpoint_recipient_reports_nonexistent_endpoint_as_not_found() {
        let d = confused_composite_device();
        let err = resolve_control_transfer_target(
            &d, |_| true, |_| 0, ControlRequestType::Vendor, ControlRecipient::Endpoint, 0x01, true, 0xEE,
        )
        .expect_err("no endpoint at address 0xEE exists anywhere on this device");
        assert_eq!(err.kind, crate::error::ErrorKind::NotFound);
    }

    #[test]
    fn control_transfer_class_request_is_checked_regardless_of_recipient() {
        let d = confused_composite_device();
        // recipient == device, but requestType == class and index still
        // names the protected interface -- bridge.py checks this
        // unconditionally, independent of what `recipient` itself says.
        let err = resolve_control_transfer_target(
            &d, |_| true, |n| if n == 0 { 1 } else { 0 }, ControlRequestType::Class, ControlRecipient::Device, 0x01, true, 0,
        )
        .expect_err("index names interface 0, currently at the HID alternate setting");
        assert_eq!(err.kind, crate::error::ErrorKind::Security);
    }

    #[test]
    fn control_transfer_device_recipient_vendor_request_has_no_interface_check() {
        let d = confused_composite_device();
        let target = resolve_control_transfer_target(
            &d, |_| false, |_| 0, ControlRequestType::Vendor, ControlRecipient::Device, 0x01, true, 0,
        )
        .expect("device-recipient vendor requests never need an interface to be claimed at all");
        assert_eq!(target, None);
    }

    #[test]
    fn control_transfer_standard_out_is_always_rejected() {
        let d = confused_composite_device();
        let err = resolve_control_transfer_target(
            &d, |_| true, |_| 0, ControlRequestType::Standard, ControlRecipient::Device, 0x06, false, 0,
        )
        .expect_err("standard requests are never allowed for controlTransferOut");
        assert_eq!(err.kind, crate::error::ErrorKind::Security);
    }

    #[test]
    fn control_transfer_standard_in_rejects_requests_outside_the_allowed_set() {
        let d = confused_composite_device();
        let err = resolve_control_transfer_target(
            &d, |_| true, |_| 0, ControlRequestType::Standard, ControlRecipient::Device, 0x09, true, 0,
        )
        .expect_err("SET_CONFIGURATION (0x09) is not in the WebUSB-allowed standard request set");
        assert_eq!(err.kind, crate::error::ErrorKind::Security);
    }

    #[test]
    fn control_transfer_standard_in_allows_get_descriptor() {
        let d = confused_composite_device();
        let target = resolve_control_transfer_target(
            &d, |_| true, |_| 0, ControlRequestType::Standard, ControlRecipient::Device, 0x06, true, 0,
        )
        .expect("GET_DESCRIPTOR is allowed");
        assert_eq!(target, None);
    }

    #[test]
    fn is_allowed_standard_control_request_matches_exactly_the_five_spec_requests() {
        for allowed in [0x00, 0x06, 0x08, 0x0A, 0x0C] {
            assert!(is_allowed_standard_control_request(allowed), "{allowed:#04x} should be allowed");
        }
        for disallowed in [0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0xFF] {
            assert!(!is_allowed_standard_control_request(disallowed), "{disallowed:#04x} should not be allowed");
        }
    }

    // ---- resolve_transfer_endpoint_owner / is_valid_transfer_endpoint_number ----

    #[test]
    fn is_valid_transfer_endpoint_number_excludes_zero_and_anything_above_fifteen() {
        assert!(!is_valid_transfer_endpoint_number(0));
        for n in 1..=15u8 {
            assert!(is_valid_transfer_endpoint_number(n));
        }
        assert!(!is_valid_transfer_endpoint_number(16));
        assert!(!is_valid_transfer_endpoint_number(255));
    }

    #[test]
    fn resolve_transfer_endpoint_owner_rejects_endpoint_on_an_unclaimed_interface() {
        let d = confused_composite_device();
        // Endpoint 0x81 exists (on interface 0's benign alternate setting
        // 0), but nothing is claimed at all -- this is the bulk/interrupt-
        // transfer equivalent of the No.1 bypass: without this check, a
        // page could read/write it having never called claimInterface().
        let err = resolve_transfer_endpoint_owner(&d, |_| false, |_| 0, 0x81).expect_err("interface 0 was never claimed");
        assert_eq!(err.kind, crate::error::ErrorKind::NotFound);
    }

    #[test]
    fn resolve_transfer_endpoint_owner_rejects_endpoint_on_a_non_current_alternate_setting() {
        let d = confused_composite_device();
        // Interface 0 is claimed, but currently sitting at alternate
        // setting 1 (HID) rather than 0 -- endpoint 0x81 only exists under
        // alternate setting 0, so it must not be reachable right now even
        // though interface 0 itself is claimed.
        let err = resolve_transfer_endpoint_owner(&d, |n| n == 0, |_| 1, 0x81).expect_err("0x81 belongs to alternate setting 0, not the current alternate setting 1");
        assert_eq!(err.kind, crate::error::ErrorKind::NotFound);
    }

    #[test]
    fn resolve_transfer_endpoint_owner_accepts_the_claimed_current_alt_endpoint() {
        let d = confused_composite_device();
        let (owner, ep) = resolve_transfer_endpoint_owner(&d, |n| n == 0, |_| 0, 0x81).expect("0x81 belongs to claimed interface 0's current alternate setting 0");
        assert_eq!(owner, 0);
        assert_eq!(ep.endpoint_number, 1);
        assert_eq!(ep.direction, Direction::In);
    }

    #[test]
    fn resolve_transfer_endpoint_owner_reports_nonexistent_address_as_not_found() {
        let d = confused_composite_device();
        let err = resolve_transfer_endpoint_owner(&d, |_| true, |_| 0, 0xEE).expect_err("no endpoint at 0xEE exists anywhere");
        assert_eq!(err.kind, crate::error::ErrorKind::NotFound);
    }

    #[test]
    fn resolve_transfer_endpoint_owner_requires_an_active_configuration() {
        let mut d = confused_composite_device();
        d.active_configuration_value = None;
        let err = resolve_transfer_endpoint_owner(&d, |_| true, |_| 0, 0x81).expect_err("no configuration is active");
        assert_eq!(err.kind, crate::error::ErrorKind::InvalidState);
    }

    // ---- sanitize_device_string ----

    #[test]
    fn sanitize_device_string_strips_c0_and_c1_control_characters() {
        assert_eq!(sanitize_device_string("a\u{0000}b\u{001f}c\u{007f}d\u{009e}e", 255), "abcde");
    }

    #[test]
    fn sanitize_device_string_strips_bidi_override_characters() {
        // U+202E RIGHT-TO-LEFT OVERRIDE embedded in an otherwise-plain name.
        let spoofed = format!("cod{}exe", '\u{202E}');
        assert_eq!(sanitize_device_string(&spoofed, 255), "codexe");
    }

    #[test]
    fn sanitize_device_string_leaves_ordinary_text_untouched() {
        assert_eq!(sanitize_device_string("Acme Widget Pro", 255), "Acme Widget Pro");
    }

    #[test]
    fn sanitize_device_string_truncates_with_ellipsis() {
        let long = "x".repeat(300);
        let got = sanitize_device_string(&long, 255);
        assert_eq!(got.chars().count(), 256); // 255 + the ellipsis character
        assert!(got.ends_with('…'));
    }

    #[test]
    fn sanitize_device_string_opt_passes_none_through_untouched() {
        assert_eq!(sanitize_device_string_opt(None), None);
    }

    #[test]
    fn sanitize_device_string_opt_sanitizes_the_inner_string() {
        assert_eq!(sanitize_device_string_opt(Some("a\x00b".to_string())), Some("ab".to_string()));
    }
}
