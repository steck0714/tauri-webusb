//! models.rs
//! =========
//! Plain, `nusb`-independent data structures for everything that crosses the
//! Rust↔JS boundary or that `hardening.rs`'s pure logic operates on.
//!
//! Both Python predecessors ran their hardening/filter-matching/descriptor-
//! building logic directly against `pyusb` device objects (`dev.idVendor`,
//! `for intf in cfg`, etc.) — `hardening.py`'s functions all take a `dev`
//! parameter typed only by duck typing. That's idiomatic Python but doesn't
//! translate cleanly to Rust, and it has a real cost even in Python:
//! `tests/fake_usb.py` in both source projects has to hand-build objects
//! shaped enough like `usb.core.Device`/`usb.core.Configuration`/etc. to fool
//! the duck typing.
//!
//! tauri-webusb introduces one extra, deliberate layer instead: a small set
//! of plain structs (this module) that mirror the shape of the *real* WebUSB
//! JS objects (`USBDevice`, `USBConfiguration`, ...) one-to-one, expressed in
//! serde-friendly Rust. `bridge.rs` is the only module that talks to `nusb`
//! directly; it converts `nusb`'s descriptor types into these structs once,
//! at the boundary. Every other module — most importantly `hardening.rs`,
//! where the actual security decisions live — only ever sees these structs.
//! That means `hardening.rs`'s tests can build a `DeviceDescriptor` by hand
//! with a plain struct literal, no fake/mock USB backend required at all.
//!
//! Field names are `camelCase` on the wire (via `#[serde(rename_all =
//! "camelCase")]`) to match `types/webusb-polyfill.d.ts` and both
//! predecessors' JSON shape exactly, while staying idiomatic `snake_case` in
//! Rust source.

use serde::{Deserialize, Serialize};

// ================================================================
// Device / configuration / interface / endpoint descriptors
// ================================================================
// Mirrors USBDevice / USBConfiguration / USBInterface / USBAlternateInterface
// / USBEndpoint from types/webusb-polyfill.d.ts. `hardening.rs::build_device_descriptor`
// is the only place that constructs a `DeviceDescriptor` from a live `nusb`
// device; everything downstream (chooser UI, `getDevices()`/`requestDevice()`
// responses, hotplug event payloads) just serializes one of these.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceDescriptor {
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer_name: Option<String>,
    pub product_name: Option<String>,
    pub serial_number: Option<String>,

    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,

    pub usb_version_major: u8,
    pub usb_version_minor: u8,
    pub usb_version_subminor: u8,
    pub device_version_major: u8,
    pub device_version_minor: u8,
    pub device_version_subminor: u8,

    #[serde(default)]
    pub configurations: Vec<ConfigurationDescriptor>,
    /// `bConfigurationValue` of whichever configuration the device is
    /// *currently* set to (i.e. `GET_CONFIGURATION`), independent of which
    /// entry happens to be first in `configurations`. `None` when it
    /// couldn't be read (the device hasn't been configured yet, or the read
    /// itself failed) — the JS side falls back to `configurations[0]` in
    /// that case, exactly like both predecessors.
    pub active_configuration_value: Option<u8>,

    /// Present only on entries returned from the device chooser's live-
    /// refresh list (`request_device_chooser`), never on `getDevices()` /
    /// `requestDevice()`'s final resolved device. Mirrors
    /// `known_devices[].connectCount` from `settings_store.rs`, used purely
    /// to sort/annotate the chooser UI ("connected 3x before").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_count: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationDescriptor {
    pub configuration_value: u8,
    pub configuration_name: Option<String>,
    #[serde(default)]
    pub interfaces: Vec<InterfaceDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceDescriptor {
    pub interface_number: u8,
    #[serde(default)]
    pub alternates: Vec<AlternateInterfaceDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AlternateInterfaceDescriptor {
    pub alternate_setting: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub interface_protected: bool,
    pub interface_name: Option<String>,
    #[serde(default)]
    pub endpoints: Vec<EndpointDescriptor>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EndpointType {
    Bulk,
    Interrupt,
    Isochronous,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EndpointDescriptor {
    pub endpoint_number: u8,
    pub direction: Direction,
    #[serde(rename = "type")]
    pub endpoint_type: EndpointType,
    pub packet_size: u16,
}

// ================================================================
// Control transfer request type / recipient
// ================================================================
// `USBControlTransferParameters.requestType`/`.recipient` are spec-defined
// strings (not the raw `bmRequestType` byte a real USB SETUP packet uses —
// that's `combine_request_type` in `bridge.rs`'s job, once these are known
// valid). Decoding them into a small closed enum here, rather than passing
// `&str` around, is what lets `hardening::resolve_control_transfer_target`
// match exhaustively instead of needing a fallback arm for "some other
// string" at every call site.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRequestType {
    Standard,
    Class,
    Vendor,
}

impl ControlRequestType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "standard" => Some(Self::Standard),
            "class" => Some(Self::Class),
            "vendor" => Some(Self::Vendor),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRecipient {
    Device,
    Interface,
    Endpoint,
    Other,
}

impl ControlRecipient {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "device" => Some(Self::Device),
            "interface" => Some(Self::Interface),
            "endpoint" => Some(Self::Endpoint),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

// ================================================================
// requestDevice() / getDevices() filters
// ================================================================
// Mirrors USBDeviceFilter. Every field optional; presence/absence is
// semantically meaningful (an absent field imposes no constraint), so this
// must NOT derive a `Default`-filling deserializer that turns "absent" into
// e.g. `vendorId: 0` — `Option<T>` with `#[serde(default)]` per field is what
// gives us that.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct UsbDeviceFilter {
    #[serde(default)]
    pub vendor_id: Option<u16>,
    #[serde(default)]
    pub product_id: Option<u16>,
    #[serde(default)]
    pub class_code: Option<u8>,
    #[serde(default)]
    pub subclass_code: Option<u8>,
    #[serde(default)]
    pub protocol_code: Option<u8>,
    #[serde(default)]
    pub serial_number: Option<String>,
}

// ================================================================
// Transfer results
// ================================================================
// Mirrors USBTransferStatus + the four *TransferResult shapes. These are
// what a *successful* dispatch returns; STALL is folded in here as
// `TransferStatus::Stall` (a *resolved* value) rather than an `Err` — per
// spec, and per both predecessors, STALL/babble never reject the returned
// promise. See `bridge.rs` for where that distinction is actually made.

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransferStatus {
    Ok,
    Stall,
    Babble,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTransferResult {
    pub status: TransferStatus,
    /// Base64-encoded payload bytes (empty string for stall/babble, exactly
    /// like both predecessors — see `hardening.rs` doc comments on why
    /// babble can't recover partial data through this transport either).
    pub data: String,
    /// Set only when this transfer exceeded `CHROME_TRANSFER_WARN_LENGTH`
    /// (see `hardening.rs`); forwarded to the page as a `console.warn()`
    /// rather than a rejection. Carries pyside6-webusb v0.0.4b2's
    /// "WebUSB-compatible, not a Chrome clone" policy forward — see that
    /// module's doc comment for the full reasoning.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutTransferResult {
    pub status: TransferStatus,
    pub bytes_written: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IsochronousInPacket {
    pub status: TransferStatus,
    /// Base64-encoded slice for *this* packet only. Unlike the pre-v0.0.0a0
    /// `fox-webusb` shape (`{length, status}`, no data), and matching the
    /// fix that release made after noticing its own `.d.ts` already declared
    /// `{data, status}` per packet: each packet here does carry its own
    /// data, so the guest-js side can build every packet's `DataView` as a
    /// slice of one shared combined `ArrayBuffer` without a second round
    /// trip.
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IsochronousOutPacket {
    pub status: TransferStatus,
    pub bytes_written: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_descriptor_round_trips_camel_case_json() {
        let d = DeviceDescriptor {
            vendor_id: 0x1234,
            product_id: 0xabcd,
            manufacturer_name: Some("Acme".into()),
            product_name: None,
            serial_number: None,
            device_class: 0,
            device_subclass: 0,
            device_protocol: 0,
            usb_version_major: 2,
            usb_version_minor: 1,
            usb_version_subminor: 0,
            device_version_major: 1,
            device_version_minor: 0,
            device_version_subminor: 0,
            configurations: vec![],
            active_configuration_value: Some(1),
            connect_count: None,
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["vendorId"], 0x1234);
        assert_eq!(json["productId"], 0xabcd);
        assert_eq!(json["manufacturerName"], "Acme");
        assert_eq!(json["productName"], serde_json::Value::Null);
        assert_eq!(json["activeConfigurationValue"], 1);
        // connectCount omitted entirely (skip_serializing_if), not present as null:
        assert!(json.get("connectCount").is_none());

        let back: DeviceDescriptor = serde_json::from_value(json).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn filter_absent_fields_stay_none_not_zero() {
        let f: UsbDeviceFilter = serde_json::from_str("{}").unwrap();
        assert_eq!(f.vendor_id, None);
        assert_eq!(f.product_id, None);
    }

    #[test]
    fn filter_partial_json_only_sets_given_fields() {
        let f: UsbDeviceFilter = serde_json::from_str(r#"{"vendorId": 4660}"#).unwrap();
        assert_eq!(f.vendor_id, Some(4660));
        assert_eq!(f.class_code, None);
    }

    #[test]
    fn endpoint_type_and_direction_serialize_lowercase() {
        let ep = EndpointDescriptor {
            endpoint_number: 1,
            direction: Direction::In,
            endpoint_type: EndpointType::Bulk,
            packet_size: 64,
        };
        let json = serde_json::to_value(&ep).unwrap();
        assert_eq!(json["direction"], "in");
        assert_eq!(json["type"], "bulk");
    }

    #[test]
    fn transfer_status_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&TransferStatus::Ok).unwrap(), "\"ok\"");
        assert_eq!(serde_json::to_string(&TransferStatus::Stall).unwrap(), "\"stall\"");
        assert_eq!(serde_json::to_string(&TransferStatus::Babble).unwrap(), "\"babble\"");
    }

    #[test]
    fn in_transfer_result_omits_warning_when_none() {
        let r = InTransferResult { status: TransferStatus::Ok, data: "".into(), warning: None };
        let json = serde_json::to_value(&r).unwrap();
        assert!(json.get("warning").is_none());
    }

    #[test]
    fn control_request_type_parses_the_three_spec_strings() {
        assert_eq!(ControlRequestType::parse("standard"), Some(ControlRequestType::Standard));
        assert_eq!(ControlRequestType::parse("class"), Some(ControlRequestType::Class));
        assert_eq!(ControlRequestType::parse("vendor"), Some(ControlRequestType::Vendor));
        assert_eq!(ControlRequestType::parse("Standard"), None, "case-sensitive, matches the wire shape exactly");
        assert_eq!(ControlRequestType::parse("bogus"), None);
    }

    #[test]
    fn control_recipient_parses_the_four_spec_strings() {
        assert_eq!(ControlRecipient::parse("device"), Some(ControlRecipient::Device));
        assert_eq!(ControlRecipient::parse("interface"), Some(ControlRecipient::Interface));
        assert_eq!(ControlRecipient::parse("endpoint"), Some(ControlRecipient::Endpoint));
        assert_eq!(ControlRecipient::parse("other"), Some(ControlRecipient::Other));
        assert_eq!(ControlRecipient::parse("bogus"), None);
    }
}
