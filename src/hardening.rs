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

use crate::models::{
    AlternateInterfaceDescriptor, DeviceDescriptor, Direction, EndpointDescriptor, EndpointType,
    UsbDeviceFilter,
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
}
