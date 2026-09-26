//! bridge.rs
//! =========
//! The session manager: everything that actually touches a live USB device.
//! `hardening.rs` decides *whether* an operation is allowed; this module is
//! what carries it out via `nusb`, and is the only module in this crate with
//! an `nusb` dependency at all — see `models.rs`'s doc comment for why that
//! split exists.
//!
//! ## A note on verification (please read before changing the nusb-facing code)
//!
//! This crate was written in a sandboxed environment whose only available
//! Rust toolchain is `rustc`/`cargo` **1.75.0** (installed via `apt`; no
//! `rustup`/network access to fetch a newer one — see `README.md`'s
//! "Development environment" section). `nusb` itself requires Rust **1.79+**,
//! and current `tauri` requires newer still. That means **this file could
//! not be compiled in the environment it was written in.** Its `nusb` call
//! shapes are instead based on `nusb` 0.2.x's published documentation and
//! real downstream usage (`probe-rs`, `rockusb`) read at the time of writing
//! (Sept 2026) — cited inline wherever a specific shape mattered. This is
//! the same category of gap both source projects were transparent about for
//! their own untestable-in-sandbox areas (real hardware, for both; a few
//! Windows-specific native-messaging behaviors for `fox-webusb`, until real
//! testing feedback came in for its v0.0.0a0). Concretely, this means: if
//! something here doesn't compile against the `nusb` version actually
//! resolved by `Cargo.lock`, the most likely culprit is a small
//! method-name/signature drift in **`descriptor_from_device` below** (the
//! function that walks live descriptors) or in **`run_in_transfer`/
//! `run_out_transfer`** (the actual transfer submission) — those three are
//! where the API surface was least directly confirmed. Everything in
//! `hardening.rs`, `error.rs`, `models.rs`, `origin.rs`, and
//! `settings_logic.rs` has no such caveat: those have no `nusb`/`tauri`
//! dependency and their test suites did run, for real, in this environment.

use crate::error::WebUsbError;
use crate::hardening;
use crate::models::*;
use crate::settings_store::SettingsStore;
use nusb::transfer::{Buffer, Bulk, ControlIn, ControlOut, ControlType, Direction as NusbDirection, Interrupt, Recipient};
use nusb::{Device, DeviceInfo, Interface};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

// ================================================================
// Descriptor building (the live-device -> models::DeviceDescriptor boundary)
// ================================================================

/// Walks a `DeviceInfo` (not-yet-open enumeration record) and produces this
/// crate's own `DeviceDescriptor`, without opening the device. Everything
/// downstream — filter matching, protected-class checks, what gets sent to
/// the chooser UI and to JS — only ever sees the result of this function (or
/// `descriptor_from_open_device` below), never `nusb` types directly.
///
/// `nusb::DeviceInfo` already carries the device descriptor's own basic
/// fields without opening the device (this is what backs `getDevices()`'s
/// "no permission prompt, no open() call" requirement — enumerating and
/// doing an initial filter pass must work before anything is opened).
/// Getting the *full* configuration tree (all configurations, not just the
/// active one — needed for `classCode` filter matching per
/// `hardening::device_matches_usb_filter`'s doc comment) requires actually
/// opening the device briefly, which `descriptor_from_open_device` does.
/// Both predecessors' `pyusb`-based approach had this same asymmetry
/// (`usb.core.find()` gives you basic fields immediately; walking
/// `for cfg in dev` triggers control transfers under the hood) — the split
/// between this function and `descriptor_from_open_device` mirrors that:
/// this one for a cheap enumeration-only pass, the other once a device is a
/// serious candidate (matched a filter, or is about to be opened for real)
/// and the full tree is worth the extra open.
fn descriptor_from_device_info(info: &DeviceInfo) -> DeviceDescriptor {
    let (usb_major, usb_minor, usb_sub) = hardening::bcd_to_version(info.device_version());

    DeviceDescriptor {
        vendor_id: info.vendor_id(),
        product_id: info.product_id(),
        // 🛡️ security_report/VULNERABILITY_REPORT.md finding No.3 (see
        // `hardening::sanitize_device_string`'s doc comment): these three
        // strings come straight from the connected device's own string
        // descriptors, sanitized here — once, at the source — rather than
        // at whichever call site happens to display them.
        manufacturer_name: hardening::sanitize_device_string_opt(info.manufacturer_string().map(str::to_string)),
        product_name: hardening::sanitize_device_string_opt(info.product_string().map(str::to_string)),
        serial_number: hardening::sanitize_device_string_opt(info.serial_number().map(str::to_string)),
        device_class: info.class(),
        device_subclass: info.subclass(),
        device_protocol: info.protocol(),
        usb_version_major: usb_major,
        usb_version_minor: usb_minor,
        usb_version_subminor: usb_sub,
        // 🔍 `DeviceInfo::device_version()` is `bcdUSB` (the USB *spec
        // version* the device claims conformance with) reused here as a
        // placeholder for `bcdDevice` (the vendor's own free-form
        // device/firmware version number) too, since the latter isn't
        // reliably known to be readable pre-open across `nusb` versions.
        // `descriptor_from_open_device` overwrites `device_version_*` with
        // the real `bcdDevice` once the device is actually open. A device
        // never reaches JS through the enumeration-only path alone (see
        // this function's doc comment), so this placeholder never actually
        // ships — it exists only so this function produces a complete,
        // valid `DeviceDescriptor` on its own.
        device_version_major: usb_major,
        device_version_minor: usb_minor,
        device_version_subminor: usb_sub,
        configurations: vec![],
        active_configuration_value: None,
        connect_count: None,
    }
}

/// The full pass: opens the device (briefly, if not already held open by an
/// existing session — see `open_device` below for the case where it is),
/// walks every configuration/interface/alternate/endpoint, and fills in
/// `configurations` + `active_configuration_value` + the real `bcdDevice`
/// version. This is the only function in the crate that decides
/// `interfaceProtected` for each alternate — via
/// `hardening::is_protected_interface_class` — so that value is trustworthy
/// wherever it's read downstream (the chooser UI dims/annotates protected
/// interfaces for the person's benefit, but `claimInterface`'s actual
/// enforcement independently re-checks against `hardening.rs` at claim time
/// rather than trusting this cached flag — see `claim_interface` below).
async fn descriptor_from_open_device(device: &Device, base: DeviceDescriptor) -> Result<DeviceDescriptor, WebUsbError> {
    let mut configurations = Vec::new();

    // `Device::configurations()` yields one `Configuration` descriptor view
    // per `bNumConfigurations` — this does not change which configuration is
    // *active*, it is purely descriptor reading.
    for cfg in device.configurations() {
        let configuration_value = cfg.configuration_value();
        let configuration_name = hardening::sanitize_device_string_opt(cfg.description_string().map(str::to_string));

        let mut interfaces_by_number: HashMap<u8, Vec<AlternateInterfaceDescriptor>> = HashMap::new();
        for alt in cfg.interface_alt_settings() {
            let interface_number = alt.interface_number();
            let interface_class = alt.class();
            let interface_subclass = alt.subclass();
            let interface_protocol = alt.protocol();

            let mut endpoints = Vec::new();
            for ep in alt.endpoints() {
                // 🔧 Corrected against the real `nusb` 0.2.7 source
                // (`descriptors.rs`): `EndpointDescriptor::transfer_type()`
                // returns `nusb::descriptors::TransferType`, a plain data
                // enum — *not* `nusb::transfer::EndpointType`, which is a
                // type-level marker *trait* (used only for the generic
                // `Endpoint<EpType, Dir>`/`Interface::endpoint::<EpType,
                // Dir>()` below) with no variants of its own at all. The
                // original draft of this match matched on the trait's name
                // as if it were this enum — impossible to have compiled as
                // written; this was one of the specific corrections this
                // crate's security-hardening pass made after downloading
                // and reading the real crate source directly (`static.
                // crates.io/crates/nusb/nusb-0.2.7.crate`) rather than
                // continuing to write against a remembered/assumed shape —
                // see README.md's "Development environment" note.
                let endpoint_type = match ep.transfer_type() {
                    nusb::descriptors::TransferType::Bulk => EndpointType::Bulk,
                    nusb::descriptors::TransferType::Interrupt => EndpointType::Interrupt,
                    nusb::descriptors::TransferType::Isochronous => EndpointType::Isochronous,
                    // Control-type endpoint descriptors don't belong in
                    // `USBAlternateInterface.endpoints` per spec — see
                    // `hardening::is_control_endpoint`'s doc comment. A
                    // compliant device never declares endpoint 0 as an
                    // explicit descriptor here, but skip defensively rather
                    // than trust every device to be well-formed.
                    nusb::descriptors::TransferType::Control => continue,
                };
                let direction = match ep.direction() {
                    NusbDirection::In => Direction::In,
                    NusbDirection::Out => Direction::Out,
                };
                endpoints.push(EndpointDescriptor {
                    endpoint_number: ep.address() & 0x0F,
                    direction,
                    endpoint_type,
                    packet_size: ep.max_packet_size() as u16,
                });
            }

            interfaces_by_number.entry(interface_number).or_default().push(AlternateInterfaceDescriptor {
                alternate_setting: alt.alternate_setting(),
                interface_class,
                interface_subclass,
                interface_protocol,
                interface_protected: hardening::is_protected_interface_class(interface_class),
                interface_name: hardening::sanitize_device_string_opt(alt.description_string().map(str::to_string)),
                endpoints,
            });
        }

        let mut interface_numbers: Vec<u8> = interfaces_by_number.keys().copied().collect();
        interface_numbers.sort_unstable();
        let interfaces = interface_numbers
            .into_iter()
            .map(|n| InterfaceDescriptor { interface_number: n, alternates: interfaces_by_number.remove(&n).unwrap_or_default() })
            .collect();

        configurations.push(ConfigurationDescriptor { configuration_value, configuration_name, interfaces });
    }

    let active_configuration_value = device.active_configuration().ok().map(|c| c.configuration_value());
    let (dev_major, dev_minor, dev_sub) = hardening::bcd_to_version(device.device_version());

    Ok(DeviceDescriptor {
        configurations,
        active_configuration_value,
        device_version_major: dev_major,
        device_version_minor: dev_minor,
        device_version_subminor: dev_sub,
        ..base
    })
}

// ================================================================
// Session state: open handles
// ================================================================

struct OpenSession {
    origin: String,
    vendor_id: u16,
    product_id: u16,
    device: Device,
    /// Snapshot taken at open time, refreshed on every `selectConfiguration`.
    /// This is what `claimInterface`'s protected-class check and
    /// `isochronousTransferIn/Out`'s endpoint-type check read — no
    /// descriptor re-walk needed on every single call.
    descriptor: DeviceDescriptor,
    claimed: HashMap<u8, Interface>,
    active_alternate: HashMap<u8, u8>,
    /// Non-blocking `try_lock()` only — mirrors both predecessors' per-handle
    /// lock giving `InvalidStateError` ("busy") rather than queueing when a
    /// second call for the same handle arrives while the first is still in
    /// flight. WebUSB itself has no notion of "queue my calls on this
    /// device" and a queued-forever call would be a worse experience than
    /// an immediate, actionable rejection.
    ///
    /// `Arc`-wrapped so `with_session` can `clone()` the handle (bumping a
    /// refcount, not touching `OpenSession` itself) and drop its own borrow
    /// of `session` *before* acquiring the lock — a bare `Mutex<()>` here
    /// would leave the guard `try_lock()` returns borrowed from `session`
    /// itself, which conflicts with the `&mut OpenSession` `with_session`
    /// still needs to hand to its caller's closure for the rest of the
    /// operation. Confirmed against a real (if `nusb`/`tauri`-stubbed)
    /// `cargo build` — the very first version of this field, a plain
    /// `Mutex<()>`, did not actually compile as written.
    op_lock: Arc<Mutex<()>>,
}

#[derive(Default)]
pub struct SessionRegistry {
    next_handle: AtomicU32,
    sessions: Mutex<HashMap<u32, OpenSession>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self { next_handle: AtomicU32::new(1), sessions: Mutex::new(HashMap::new()) }
    }

    fn alloc_handle(&self) -> u32 {
        self.next_handle.fetch_add(1, Ordering::Relaxed)
    }
}

// ================================================================
// Enumeration (getDevices / requestDevice's candidate list)
// ================================================================

/// One already-`nusb`-enumerated candidate, cheap descriptor only (see
/// `descriptor_from_device_info`'s doc comment on the pre-/post-open
/// distinction) — used for filter matching before deciding which candidates
/// are even worth the cost of a full open+descriptor-walk.
struct Candidate {
    info: DeviceInfo,
    descriptor: DeviceDescriptor,
}

async fn enumerate() -> Result<Vec<Candidate>, WebUsbError> {
    let iter = nusb::list_devices()
        .await
        .map_err(|e| WebUsbError::not_found(format!("could not enumerate USB devices: {e}")))?;
    Ok(iter.map(|info| { let descriptor = descriptor_from_device_info(&info); Candidate { info, descriptor } }).collect())
}

/// `getDevices()`: only ever returns devices the origin was *previously*
/// granted (via a prior `requestDevice()` chooser selection) — this call
/// alone never grants anything new, and never shows the chooser. Matches
/// spec and both predecessors exactly.
pub async fn list_granted_devices(settings: &SettingsStore, origin: &str) -> Result<Vec<DeviceDescriptor>, WebUsbError> {
    let granted_pairs = settings.read(|d| d.granted_pairs_for_origin(origin)).await;
    if granted_pairs.is_empty() {
        return Ok(vec![]);
    }
    let candidates = enumerate().await?;
    let mut result = Vec::new();
    for c in candidates {
        let pair = (c.info.vendor_id(), c.info.product_id());
        if !granted_pairs.contains(&pair) {
            continue;
        }
        if hardening::device_is_fully_blocked(&c.descriptor) {
            continue; // granted in the past, now blocklisted: don't resurrect it
        }
        result.push(full_descriptor_for_candidate(&c).await?);
    }
    Ok(result)
}

async fn full_descriptor_for_candidate(c: &Candidate) -> Result<DeviceDescriptor, WebUsbError> {
    // Opened only long enough to read descriptors, then dropped — this does
    // *not* create a session/handle. `nusb::Device` closes on drop.
    let device = c
        .info
        .open()
        .await
        .map_err(|e| WebUsbError::not_found(format!("could not open device to read its descriptors: {e}")))?;
    descriptor_from_open_device(&device, c.descriptor.clone()).await
}

/// Every currently-connected candidate matching any of `filters` and none of
/// `exclusion_filters`, excluding protected/blocklisted devices — the
/// chooser's live-refresh list. `hardening::device_matches_usb_filter` needs
/// the *full* descriptor tree (interface classes), so every candidate here
/// gets the full open+walk treatment, not just the ones that end up
/// matching — there's no cheaper way to know whether a composite device's
/// interfaces satisfy a `classCode` filter without reading them.
pub async fn candidates_for_chooser(
    filters: &[UsbDeviceFilter],
    exclusion_filters: &[UsbDeviceFilter],
) -> Result<Vec<DeviceDescriptor>, WebUsbError> {
    let candidates = enumerate().await?;
    let mut result = Vec::new();
    for c in candidates {
        if hardening::device_is_fully_blocked(&c.descriptor) {
            continue;
        }
        let full = full_descriptor_for_candidate(&c).await?;
        if !hardening::device_matches_any_usb_filter(&full, filters) {
            continue;
        }
        if !exclusion_filters.is_empty() && hardening::device_matches_any_usb_filter(&full, exclusion_filters) {
            continue;
        }
        result.push(full);
    }
    Ok(result)
}

// ================================================================
// Open / close
// ================================================================

pub async fn open_device(
    settings: &SettingsStore,
    sessions: &SessionRegistry,
    origin: &str,
    vendor_id: u16,
    product_id: u16,
    serial_number: Option<String>,
) -> Result<(u32, DeviceDescriptor), WebUsbError> {
    if !settings.read(|d| d.is_origin_granted(origin, vendor_id, product_id)).await {
        return Err(WebUsbError::security(format!(
            "origin has not been granted access to device {vendor_id:#06x}:{product_id:#06x} \
             (call requestDevice() first)"
        )));
    }
    let candidates = enumerate().await?;
    // `USBDevice.open()` takes no arguments of its own per spec — the
    // object already carries whichever serial number it was constructed
    // with, from `requestDevice()`/`getDevices()` (see `commands.rs`'s
    // `open` command and `guest-js/src/polyfill.ts`'s `USBDevice.open()`,
    // which both thread it through transparently, invisible to page code).
    // When one is present, prefer the exact (vendorId, productId,
    // serialNumber) match over merely the first vendor/product ID match:
    // multiple simultaneously-connected devices sharing one VID/PID pair
    // are common enough in practice (identical peripherals from the same
    // manufacturer) that always picking "whichever happens to enumerate
    // first" can silently open the wrong physical unit. Falls back to the
    // first VID/PID match — rather than failing outright — when no
    // candidate's serial matches (a stale/no-longer-reported serial
    // shouldn't make an otherwise-connected, previously-granted device
    // unopenable), matching `bridge.py`'s own `_find_usb_device` exactly.
    let wanted_serial = serial_number.as_deref().filter(|s| !s.is_empty());
    let candidate = wanted_serial
        .and_then(|serial| {
            candidates.iter().position(|c| c.info.vendor_id() == vendor_id && c.info.product_id() == product_id && c.info.serial_number() == Some(serial))
        })
        .or_else(|| candidates.iter().position(|c| c.info.vendor_id() == vendor_id && c.info.product_id() == product_id))
        .map(|i| candidates.into_iter().nth(i).expect("index was just found in this same Vec"))
        .ok_or_else(|| WebUsbError::not_found("device is not currently connected"))?;
    if hardening::device_is_fully_blocked(&candidate.descriptor) {
        return Err(WebUsbError::security("this device is on the security-key blocklist and cannot be opened"));
    }

    // 🛡️ security_report/VULNERABILITY_REPORT.md finding No.6: cap how many
    // handles a single origin can hold open at once, evicting that origin's
    // *oldest* handle to make room rather than failing this `open()` call —
    // see `hardening::MAX_OPEN_HANDLES_PER_ORIGIN`'s doc comment. Checked
    // (and, if needed, acted on) before doing the real, potentially
    // expensive device open below, exactly mirroring `bridge.py`'s own
    // ordering.
    {
        let mut guard = sessions.sessions.lock().await;
        if guard.values().filter(|s| s.origin == origin).count() >= hardening::MAX_OPEN_HANDLES_PER_ORIGIN {
            // Handles allocate monotonically (`SessionRegistry::alloc_handle`),
            // so the smallest handle value among this origin's own entries
            // is unambiguously its oldest — no separate insertion-order
            // tracking needed.
            if let Some(&oldest) = guard.iter().filter(|(_, s)| s.origin == origin).map(|(h, _)| h).min() {
                guard.remove(&oldest); // drop -> nusb::Device closes the device
            }
        }
    }

    let device = candidate
        .info
        .open()
        .await
        .map_err(|e| WebUsbError::invalid_state(format!("failed to open device: {e}")))?;
    let descriptor = descriptor_from_open_device(&device, candidate.descriptor).await?;

    let now = now_iso8601();
    settings
        .mutate(|d| {
            d.record_device_usage(vendor_id, product_id, descriptor.product_name.clone(), descriptor.manufacturer_name.clone(), &now);
            ((), true)
        })
        .await
        .map_err(|e| WebUsbError::invalid_state(format!("device was opened but its usage record could not be saved: {e}")))?;

    let handle = sessions.alloc_handle();
    let session = OpenSession {
        origin: origin.to_string(),
        vendor_id,
        product_id,
        device,
        descriptor: descriptor.clone(),
        claimed: HashMap::new(),
        active_alternate: HashMap::new(),
        op_lock: Arc::new(Mutex::new(())),
    };
    sessions.sessions.lock().await.insert(handle, session);
    Ok((handle, descriptor))
}

pub async fn close_device(sessions: &SessionRegistry, origin: &str, handle: u32) -> Result<(), WebUsbError> {
    let mut guard = sessions.sessions.lock().await;
    // Deliberately `Ok(())` in every case — including a handle that exists
    // but belongs to a *different* origin — rather than only for "already
    // closed"/"never existed". `USBDevice.close()` is spec-idempotent (no
    // error for an already-closed device), and every *other* handle-scoped
    // operation in this module already makes "wrong origin" and "handle
    // doesn't exist at all" indistinguishable by giving both the exact same
    // `NotFoundError` (see `not_found_handle`'s doc comment) — but that
    // approach doesn't transfer cleanly to `close`, since idempotency means
    // "doesn't exist" must succeed, and success and failure are trivially
    // distinguishable from each other. Handle IDs are small, guessable,
    // monotonically-increasing integers reachable from any script with IPC
    // access (see `gesture.rs`'s module doc comment on that same threat
    // model generally) — an attacker distinguishing "some *other* origin
    // currently has a handle numbered N open" from "no handle numbered N
    // exists" by which of the two outcomes `close(N)` gave them would be a
    // (low-severity, but free to close) cross-origin existence leak this
    // module doesn't have anywhere else. Only actually remove the entry
    // when the origin matches; silently no-op otherwise.
    if let Some(s) = guard.get(&handle) {
        if s.origin == origin {
            guard.remove(&handle); // drop -> nusb::Device closes the device
        }
    }
    Ok(())
}

fn not_found_handle() -> WebUsbError {
    // Deliberately identical whether the handle never existed or belongs to
    // a different origin — see the module doc comment on why that's
    // `NotFoundError`, not `SecurityError`.
    WebUsbError::not_found("no such open device handle for this origin")
}

// ================================================================
// The "run this against a locked, origin-checked session" helper
// ================================================================
// Every operation below (selectConfiguration, claim/release, transfers...)
// starts with the same three checks: does this handle exist, does it belong
// to `origin`, is nobody already mid-operation on it. Centralizing that
// avoids the copy-pasted-six-times version of this that `bridge.py`
// explicitly called out as a smell it was trying to avoid with its
// dispatch-table design.
//
// `f` is boxed (`Pin<Box<dyn Future>>`) rather than a plain `async fn`
// generic parameter purely to keep this helper's own signature simple to
// write against a borrowed `&mut OpenSession` with a lifetime tied to the
// registry lock guard — the boxing costs one small heap allocation per
// call, which is irrelevant next to an actual USB round-trip.

async fn with_session<T>(
    sessions: &SessionRegistry,
    origin: &str,
    handle: u32,
    f: impl for<'a> FnOnce(&'a mut OpenSession) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, WebUsbError>> + Send + 'a>>,
) -> Result<T, WebUsbError> {
    let mut guard = sessions.sessions.lock().await;
    let session = guard.get_mut(&handle).ok_or_else(not_found_handle)?;
    if session.origin != origin {
        return Err(not_found_handle());
    }
    // The per-handle `op_lock` is what actually serializes concurrent calls
    // on the *same* handle; other handles remain fully concurrent with each
    // other even while one is mid-transfer (the registry lock above is only
    // held long enough to look the session up, not for the whole
    // operation — but note `guard` intentionally stays held across `f`'s
    // `.await` here for simplicity in this first version: see
    // "Known limitations" in README.md regarding cross-handle concurrency).
    // `try_lock` (not `.lock().await`) is the actual point: a second
    // concurrent call on the *same* handle fails fast with
    // `InvalidStateError` rather than silently queuing behind the first —
    // see `OpenSession::op_lock`'s doc comment. Cloning the `Arc` (cheap: a
    // refcount bump, not a lock acquisition) ends this borrow of `session`
    // before `f(session)` below needs its own — see `op_lock`'s doc comment
    // for why a bare, unwrapped `Mutex<()>` here does not compile.
    let op_lock = session.op_lock.clone();
    let _op_guard = op_lock.try_lock().map_err(|_| WebUsbError::invalid_state("this device handle is busy with another operation"))?;
    f(session).await
}

// ================================================================
// Configuration / interface lifecycle
// ================================================================

pub async fn select_configuration(sessions: &SessionRegistry, origin: &str, handle: u32, configuration_value: u8) -> Result<(), WebUsbError> {
    with_session(sessions, origin, handle, move |session| {
        Box::pin(async move {
            session
                .device
                .set_configuration(configuration_value)
                .await
                .map_err(|e| WebUsbError::invalid_state(format!("selectConfiguration failed: {e}")))?;
            session.claimed.clear();
            session.active_alternate.clear();
            session.descriptor = descriptor_from_open_device(&session.device, session.descriptor.clone()).await?;
            Ok(())
        })
    })
    .await
}

fn interface_alternates<'a>(descriptor: &'a DeviceDescriptor, interface_number: u8) -> Option<&'a [AlternateInterfaceDescriptor]> {
    let active_cfg = descriptor.active_configuration_value?;
    descriptor
        .configurations
        .iter()
        .find(|c| c.configuration_value == active_cfg)?
        .interfaces
        .iter()
        .find(|i| i.interface_number == interface_number)
        .map(|i| i.alternates.as_slice())
}

pub async fn claim_interface(sessions: &SessionRegistry, origin: &str, handle: u32, interface_number: u8) -> Result<(), WebUsbError> {
    with_session(sessions, origin, handle, move |session| {
        Box::pin(async move {
            let alternates = interface_alternates(&session.descriptor, interface_number)
                .ok_or_else(|| WebUsbError::not_found(format!("no such interface: {interface_number}")))?;
            // Re-check against `hardening.rs` at claim time, from the
            // authoritative live snapshot — never trust a cached
            // `interfaceProtected` flag the JS side might be holding from
            // an earlier read. Conservative per the module doc comment: any
            // alternate of this interface number being protected is enough
            // to refuse the whole interface.
            if let Some(alt) = alternates.iter().find(|a| a.interface_protected) {
                return Err(WebUsbError::security(format!(
                    "interface {interface_number} cannot be claimed: alternate setting {} declares \
                     protected interface class {:#04x} ({})",
                    alt.alternate_setting, alt.interface_class, hardening::protected_class_name(alt.interface_class)
                )));
            }
            if session.claimed.contains_key(&interface_number) {
                return Ok(()); // already claimed by this same handle: idempotent, matches spec
            }
            let iface = session
                .device
                .claim_interface(interface_number)
                .await
                .map_err(|e| WebUsbError::invalid_state(format!("claimInterface failed: {e}")))?;
            session.claimed.insert(interface_number, iface);
            session.active_alternate.entry(interface_number).or_insert(0);
            Ok(())
        })
    })
    .await
}

pub async fn release_interface(sessions: &SessionRegistry, origin: &str, handle: u32, interface_number: u8) -> Result<(), WebUsbError> {
    with_session(sessions, origin, handle, move |session| {
        Box::pin(async move {
            if session.claimed.remove(&interface_number).is_none() {
                return Err(WebUsbError::not_found(format!("interface {interface_number} is not claimed")));
            }
            session.active_alternate.remove(&interface_number);
            Ok(())
        })
    })
    .await
}

pub async fn select_alternate_interface(
    sessions: &SessionRegistry, origin: &str, handle: u32, interface_number: u8, alternate_setting: u8,
) -> Result<(), WebUsbError> {
    with_session(sessions, origin, handle, move |session| {
        Box::pin(async move {
            if !session.claimed.contains_key(&interface_number) {
                return Err(WebUsbError::not_found(format!("interface {interface_number} is not claimed")));
            }
            // 🛡️ security_report/VULNERABILITY_REPORT.md finding No.1,
            // `selectAlternateInterface()` half: verify the *specific*
            // target alternate setting both exists and is not itself a
            // protected interface class before actually switching to it.
            // `claim_interface` above already refuses to claim an interface
            // number where *any* alternate setting is protected — which on
            // its own is already sufficient for this to never actually
            // trigger — but checking again here, at the point that decides
            // which endpoints actually become live, means neither function
            // depends on the other's exact policy to both stay safe (see
            // `claim_interface`'s own doc comment on why it chose the more
            // conservative "any alternate" check rather than mirroring the
            // reference `pyside6-webusb` project's alternative "claim
            // checks only alternate 0, `selectAlternateInterface` checks
            // whichever alternate is targeted" split exactly).
            let alternates = interface_alternates(&session.descriptor, interface_number)
                .ok_or_else(|| WebUsbError::not_found(format!("no such interface: {interface_number}")))?;
            let target = alternates.iter().find(|a| a.alternate_setting == alternate_setting).ok_or_else(|| {
                WebUsbError::not_found(format!("interface {interface_number} has no alternate setting {alternate_setting}"))
            })?;
            if target.interface_protected {
                return Err(WebUsbError::security(format!(
                    "cannot switch interface {interface_number} to alternate setting {alternate_setting}: \
                     declares protected interface class {:#04x} ({})",
                    target.interface_class,
                    hardening::protected_class_name(target.interface_class)
                )));
            }
            let iface = session.claimed.get(&interface_number).expect("presence just confirmed above");
            iface
                .set_alt_setting(alternate_setting)
                .await
                .map_err(|e| WebUsbError::invalid_state(format!("selectAlternateInterface failed: {e}")))?;
            session.active_alternate.insert(interface_number, alternate_setting);
            Ok(())
        })
    })
    .await
}

pub async fn reset_device(sessions: &SessionRegistry, origin: &str, handle: u32) -> Result<(), WebUsbError> {
    with_session(sessions, origin, handle, move |session| {
        Box::pin(async move {
            session.device.reset().await.map_err(|e| WebUsbError::invalid_state(format!("reset failed: {e}")))?;
            session.claimed.clear();
            session.active_alternate.clear();
            Ok(())
        })
    })
    .await
}

pub async fn clear_halt(sessions: &SessionRegistry, origin: &str, handle: u32, endpoint_number: u8, direction: Direction) -> Result<(), WebUsbError> {
    with_session(sessions, origin, handle, move |session| {
        Box::pin(async move {
            // 🛡️ security_report/VULNERABILITY_REPORT.md finding No.1 (see
            // `resolve_transfer_endpoint`'s doc comment): `clearHalt` needs
            // the exact same "belongs to a claimed interface's currently
            // selected alternate setting" check `transferIn`/`Out` do, not
            // just "some interface, any interface, is claimed" — clearing a
            // stall condition on an endpoint the page never claimed is
            // unauthorized state manipulation of hardware it was never
            // granted, independent of whether any actual data changes
            // hands. `bridge.py`'s own `clearHalt` performs the identical
            // check via the same underlying helper it uses for bulk/
            // interrupt transfers.
            let (iface, _ep_desc) = resolve_transfer_endpoint(session, endpoint_number, direction)?;
            let addr = endpoint_address(endpoint_number, direction);
            iface
                .clear_halt(addr)
                .await
                .map_err(|e| WebUsbError::invalid_state(format!("clearHalt failed: {e}")))?;
            Ok(())
        })
    })
    .await
}

/// `USBDevice.forget()`: an origin voluntarily gives up its own access to
/// this specific device. Self-service only — this is not the trusted-only
/// `revoke_origin_grant` command (see `commands.rs`), it's scoped to
/// exactly the calling origin and exactly this handle's device, and needs
/// no elevated permission since an origin giving up its own access can
/// never affect any other origin.
pub async fn forget_device(settings: &SettingsStore, sessions: &SessionRegistry, origin: &str, handle: u32) -> Result<(), WebUsbError> {
    let (vendor_id, product_id) = {
        let guard = sessions.sessions.lock().await;
        let session = guard.get(&handle).ok_or_else(not_found_handle)?;
        if session.origin != origin {
            return Err(not_found_handle());
        }
        (session.vendor_id, session.product_id)
    };
    settings
        .mutate(|d| (d.revoke_origin_grant(origin, vendor_id, product_id), true))
        .await
        .map_err(|e| WebUsbError::invalid_state(format!("access was not revoked: {e}")))?;
    close_device(sessions, origin, handle).await
}

fn endpoint_address(endpoint_number: u8, direction: Direction) -> u8 {
    match direction {
        Direction::In => endpoint_number | 0x80,
        Direction::Out => endpoint_number & 0x7F,
    }
}

// ================================================================
// Control transfers
// ================================================================

fn combine_request_type(request_type: &str, recipient: &str) -> Result<(ControlType, Recipient, ControlRequestType, ControlRecipient), WebUsbError> {
    let (control_type, request_type_kind) = match request_type {
        "standard" => (ControlType::Standard, ControlRequestType::Standard),
        "class" => (ControlType::Class, ControlRequestType::Class),
        "vendor" => (ControlType::Vendor, ControlRequestType::Vendor),
        other => return Err(WebUsbError::not_found(format!("unknown requestType {other:?}"))), // JS-side already TypeErrors on this; defensive only
    };
    let (recipient, recipient_kind) = match recipient {
        "device" => (Recipient::Device, ControlRecipient::Device),
        "interface" => (Recipient::Interface, ControlRecipient::Interface),
        "endpoint" => (Recipient::Endpoint, ControlRecipient::Endpoint),
        "other" => (Recipient::Other, ControlRecipient::Other),
        other => return Err(WebUsbError::not_found(format!("unknown recipient {other:?}"))),
    };
    Ok((control_type, recipient, request_type_kind, recipient_kind))
}

pub struct ControlSetup {
    pub request_type: String,
    pub recipient: String,
    pub request: u8,
    pub value: u16,
    pub index: u16,
}

pub async fn control_transfer_in(
    sessions: &SessionRegistry, origin: &str, handle: u32, setup: ControlSetup, length: u32,
) -> Result<InTransferResult, WebUsbError> {
    if length > hardening::CONTROL_TRANSFER_MAX_LENGTH {
        return Err(WebUsbError::index_size(format!(
            "length {length} exceeds the maximum control transfer length of {} bytes",
            hardening::CONTROL_TRANSFER_MAX_LENGTH
        )));
    }
    let (control_type, recipient, request_type_kind, recipient_kind) = combine_request_type(&setup.request_type, &setup.recipient)?;
    with_session(sessions, origin, handle, move |session| {
        Box::pin(async move {
            // 🛡️ security_report/VULNERABILITY_REPORT.md finding No.1: `nusb`
            // itself does not check whether `recipient`/`index` names a
            // claimed, non-protected interface/endpoint — see
            // `hardening::resolve_control_transfer_target`'s doc comment for
            // exactly why, and why this check cannot be skipped just because
            // *some* interface happens to already be claimed.
            let target = hardening::resolve_control_transfer_target(
                &session.descriptor,
                |n| session.claimed.contains_key(&n),
                |n| session.active_alternate.get(&n).copied().unwrap_or(0),
                request_type_kind,
                recipient_kind,
                setup.request,
                true, // direction_in
                setup.index,
            )?;
            // Device/Other-recipient transfers still require *some* claimed
            // interface as the vehicle `nusb` submits them through on every
            // platform (see this function's own module-level context above:
            // `nusb::Device::control_in`/`_out` exist and would avoid this
            // requirement on every platform except Windows, but requiring a
            // claim unconditionally keeps this one code path correct on
            // every platform rather than branching on `cfg(windows)` — a
            // pre-existing, deliberate simplification carried forward here,
            // not a new restriction introduced by this fix. `recipient ==
            // Interface`/`Endpoint` transfers are, independent of that
            // simplification, now always issued through the *specific*
            // claimed interface `resolve_control_transfer_target` names —
            // this also happens to be exactly what Windows' WinUSB backend
            // itself additionally requires for `recipient == Interface`
            // (the index's low byte must match the interface you're calling
            // through, or it returns `InvalidArgument`).
            let iface = match target {
                Some(iface_num) => session
                    .claimed
                    .get(&iface_num)
                    .expect("resolve_control_transfer_target only names an interface number it was told is claimed"),
                None => any_claimed_interface(session)?,
            };
            let timeout = Duration::from_millis(hardening::scaled_transfer_timeout_ms(length as u64));
            let completion = iface
                .control_in(
                    ControlIn { control_type, recipient, request: setup.request, value: setup.value, index: setup.index, length: length as u16 },
                    timeout,
                )
                .await;
            transfer_completion_to_in_result(completion.status, completion.buffer.as_slice(), length as u64)
        })
    })
    .await
}

pub async fn control_transfer_out(
    sessions: &SessionRegistry, origin: &str, handle: u32, setup: ControlSetup, data: Vec<u8>,
) -> Result<OutTransferResult, WebUsbError> {
    if data.len() as u32 > hardening::CONTROL_TRANSFER_MAX_LENGTH {
        return Err(WebUsbError::index_size(format!(
            "data length {} exceeds the maximum control transfer length of {} bytes",
            data.len(), hardening::CONTROL_TRANSFER_MAX_LENGTH
        )));
    }
    let (control_type, recipient, request_type_kind, recipient_kind) = combine_request_type(&setup.request_type, &setup.recipient)?;
    let data_len = data.len() as u64;
    with_session(sessions, origin, handle, move |session| {
        Box::pin(async move {
            let target = hardening::resolve_control_transfer_target(
                &session.descriptor,
                |n| session.claimed.contains_key(&n),
                |n| session.active_alternate.get(&n).copied().unwrap_or(0),
                request_type_kind,
                recipient_kind,
                setup.request,
                false, // direction_in
                setup.index,
            )?;
            let iface = match target {
                Some(iface_num) => session
                    .claimed
                    .get(&iface_num)
                    .expect("resolve_control_transfer_target only names an interface number it was told is claimed"),
                None => any_claimed_interface(session)?,
            };
            let timeout = Duration::from_millis(hardening::scaled_transfer_timeout_ms(data_len));
            let completion = iface
                .control_out(ControlOut { control_type, recipient, request: setup.request, value: setup.value, index: setup.index, data: &data }, timeout)
                .await;
            transfer_completion_to_out_result(completion.status, completion.actual_len as u32, data_len)
        })
    })
    .await
}

fn any_claimed_interface(session: &OpenSession) -> Result<&Interface, WebUsbError> {
    session.claimed.values().next().ok_or_else(|| WebUsbError::invalid_state("no interface is currently claimed"))
}

// ================================================================
// Bulk / interrupt transfers
// ================================================================

/// Resolves `endpoint_number`/`direction` to the *specific* claimed
/// interface that currently owns it, together with its descriptor (type,
/// packet size) — see `hardening::resolve_transfer_endpoint_owner`'s doc
/// comment for why this only ever considers claimed interfaces at their
/// currently-selected alternate setting (`security_report/
/// VULNERABILITY_REPORT.md` finding No.1). This replaces what used to be
/// two independent, inconsistent lookups here: a global, claim-unaware
/// `find_endpoint()` search (for the descriptor) plus a separate
/// `any_claimed_interface()` call (for *some* claimed interface's handle,
/// regardless of whether it was actually the one owning this endpoint) —
/// harmless by accident only because `nusb`'s own `Interface::endpoint()`
/// happens to re-scope to whichever specific interface object it's called
/// on and so silently failed shut for a genuinely cross-interface call,
/// but was still a real functional bug for any device with more than one
/// simultaneously claimed interface (whichever interface
/// `any_claimed_interface` happened to return first was the only one
/// `transferIn`/`Out` could ever actually use, regardless of which
/// interface the requested endpoint number really belonged to).
fn resolve_transfer_endpoint<'a>(
    session: &'a OpenSession, endpoint_number: u8, direction: Direction,
) -> Result<(&'a Interface, EndpointDescriptor), WebUsbError> {
    if !hardening::is_valid_transfer_endpoint_number(endpoint_number) {
        return Err(WebUsbError::index_size(format!("endpoint number {endpoint_number} is out of range (must be 1-15)")));
    }
    let addr = endpoint_address(endpoint_number, direction);
    let (owner_number, ep_desc) = hardening::resolve_transfer_endpoint_owner(
        &session.descriptor,
        |n| session.claimed.contains_key(&n),
        |n| session.active_alternate.get(&n).copied().unwrap_or(0),
        addr,
    )?;
    let iface = session
        .claimed
        .get(&owner_number)
        .expect("resolve_transfer_endpoint_owner only ever names an interface number it was told is claimed");
    Ok((iface, ep_desc))
}

/// nusb requires an IN request's buffer length to be an exact multiple of
/// the endpoint's max packet size (nusb 0.2, changelog: "Bulk and Interrupt
/// IN transfers that are not a multiple of the max packet size return an
/// error"). WebUSB's `transferIn(endpointNumber, length)` accepts any
/// `length`. This reconciles the two: submit a buffer rounded *up* to the
/// next multiple of `packet_size`, then truncate whatever actually came
/// back down to at most the caller's original `length` — so a device that
/// answers with a short packet still returns exactly what it sent (nothing
/// invented), while a device that fills the rounded-up buffer never hands
/// the page more bytes than it asked for.
fn round_up_to_packet_multiple(length: u32, packet_size: u16) -> u32 {
    if packet_size == 0 {
        return length; // defensive only; a real endpoint descriptor is never 0
    }
    let packet_size = packet_size as u32;
    if length % packet_size == 0 {
        length.max(packet_size) // a 0-length IN request is still a valid one-packet probe
    } else {
        ((length / packet_size) + 1) * packet_size
    }
}

pub async fn transfer_in(sessions: &SessionRegistry, origin: &str, handle: u32, endpoint_number: u8, length: u32) -> Result<InTransferResult, WebUsbError> {
    if length as u64 > hardening::BULK_TRANSFER_MAX_LENGTH {
        return Err(WebUsbError::data_error(format!(
            "requested length {length} exceeds this implementation's {}-byte transfer ceiling",
            hardening::BULK_TRANSFER_MAX_LENGTH
        )));
    }
    with_session(sessions, origin, handle, move |session| {
        Box::pin(async move {
            let (iface, ep_desc) = resolve_transfer_endpoint(session, endpoint_number, Direction::In)?;
            if ep_desc.endpoint_type == EndpointType::Isochronous {
                return Err(WebUsbError::invalid_access("use isochronousTransferIn() for an isochronous endpoint"));
            }
            let submit_len = round_up_to_packet_multiple(length, ep_desc.packet_size);
            let timeout = Duration::from_millis(hardening::scaled_transfer_timeout_ms(length as u64));
            let addr = endpoint_address(endpoint_number, Direction::In);

            let (status, buf, actual_len) = if ep_desc.endpoint_type == EndpointType::Interrupt {
                let mut ep = iface
                    .endpoint::<Interrupt, nusb::transfer::In>(addr)
                    .map_err(|e| WebUsbError::not_found(format!("endpoint {endpoint_number} unavailable: {e}")))?;
                run_in_transfer(&mut ep, submit_len, timeout).await
            } else {
                let mut ep = iface
                    .endpoint::<Bulk, nusb::transfer::In>(addr)
                    .map_err(|e| WebUsbError::not_found(format!("endpoint {endpoint_number} unavailable: {e}")))?;
                run_in_transfer(&mut ep, submit_len, timeout).await
            };
            let usable = actual_len.min(length as usize);
            transfer_completion_to_in_result(status, &buf.as_slice()[..usable], length as u64)
        })
    })
    .await
}

pub async fn transfer_out(sessions: &SessionRegistry, origin: &str, handle: u32, endpoint_number: u8, data: Vec<u8>) -> Result<OutTransferResult, WebUsbError> {
    if data.len() as u64 > hardening::BULK_TRANSFER_MAX_LENGTH {
        return Err(WebUsbError::data_error(format!(
            "data length {} exceeds this implementation's {}-byte transfer ceiling",
            data.len(), hardening::BULK_TRANSFER_MAX_LENGTH
        )));
    }
    let data_len = data.len() as u64;
    with_session(sessions, origin, handle, move |session| {
        Box::pin(async move {
            let (iface, ep_desc) = resolve_transfer_endpoint(session, endpoint_number, Direction::Out)?;
            if ep_desc.endpoint_type == EndpointType::Isochronous {
                return Err(WebUsbError::invalid_access("use isochronousTransferOut() for an isochronous endpoint"));
            }
            let timeout = Duration::from_millis(hardening::scaled_transfer_timeout_ms(data_len));
            let addr = endpoint_address(endpoint_number, Direction::Out);

            let (status, actual_len) = if ep_desc.endpoint_type == EndpointType::Interrupt {
                let mut ep = iface
                    .endpoint::<Interrupt, nusb::transfer::Out>(addr)
                    .map_err(|e| WebUsbError::not_found(format!("endpoint {endpoint_number} unavailable: {e}")))?;
                run_out_transfer(&mut ep, data, timeout).await
            } else {
                let mut ep = iface
                    .endpoint::<Bulk, nusb::transfer::Out>(addr)
                    .map_err(|e| WebUsbError::not_found(format!("endpoint {endpoint_number} unavailable: {e}")))?;
                run_out_transfer(&mut ep, data, timeout).await
            };
            transfer_completion_to_out_result(status, actual_len, data_len)
        })
    })
    .await
}

/// Submits one IN transfer and waits for it, with a timeout that cancels the
/// transfer rather than leaving it (and the endpoint) permanently wedged —
/// see the module doc comment: this uses the genuinely-async
/// `submit`/`next_complete().await` pair wrapped in `tokio::time::timeout`
/// rather than `Endpoint::transfer_blocking` (whose name indicates it blocks
/// the calling OS thread, which would be a real problem called directly from
/// an async Tauri command — every command in this plugin runs on Tauri's
/// shared async runtime, and a genuinely thread-blocking call there stalls
/// unrelated work, not just this one request).
async fn run_in_transfer<K>(ep: &mut nusb::Endpoint<K, nusb::transfer::In>, submit_len: u32, timeout: Duration) -> (Result<(), nusb::transfer::TransferError>, Buffer, usize)
where
    K: nusb::transfer::EndpointType + nusb::transfer::BulkOrInterrupt,
{
    ep.submit(Buffer::new(submit_len as usize));
    match tokio::time::timeout(timeout, ep.next_complete()).await {
        Ok(completion) => (completion.status, completion.buffer, completion.actual_len),
        Err(_elapsed) => {
            ep.cancel_all();
            let drained = ep.next_complete().await;
            (Err(nusb::transfer::TransferError::Cancelled), drained.buffer, drained.actual_len)
        }
    }
}

async fn run_out_transfer<K>(ep: &mut nusb::Endpoint<K, nusb::transfer::Out>, data: Vec<u8>, timeout: Duration) -> (Result<(), nusb::transfer::TransferError>, u32)
where
    K: nusb::transfer::EndpointType + nusb::transfer::BulkOrInterrupt,
{
    let mut buf = Buffer::new(data.len());
    buf.extend_from_slice(&data);
    ep.submit(buf);
    match tokio::time::timeout(timeout, ep.next_complete()).await {
        Ok(completion) => (completion.status, completion.actual_len as u32),
        Err(_elapsed) => {
            ep.cancel_all();
            let drained = ep.next_complete().await;
            (Err(nusb::transfer::TransferError::Cancelled), drained.actual_len as u32)
        }
    }
}

/// Shared status interpretation for every transfer kind: STALL resolves
/// (per spec) rather than rejects, everything else rejects. See
/// `error.rs`'s module doc comment on why babble/overflow specifically isn't
/// distinguished here — `nusb::transfer::TransferError` currently has no
/// dedicated variant for it (confirmed against its published enum: only
/// `Cancelled | Stall | Disconnected | Fault | InvalidArgument |
/// Unknown(u32)`), unlike the `LIBUSB_ERROR_OVERFLOW` both predecessors could
/// detect through `pyusb`/libusb. A real overflow condition here surfaces as
/// `Fault` or `Unknown`, which reject as a plain `NetworkError`-shaped
/// failure (via `commands.rs`'s default fallback for any error whose kind
/// the guest-js side doesn't specifically recognize) rather than resolving
/// as `{status: "babble"}` — a deliberately honest gap for v0.0.0 rather
/// than a guessed misclassification.
fn transfer_completion_to_in_result(status: Result<(), nusb::transfer::TransferError>, data: &[u8], requested_len: u64) -> Result<InTransferResult, WebUsbError> {
    match status {
        Ok(()) => Ok(InTransferResult {
            status: TransferStatus::Ok,
            data: base64_encode(data),
            warning: hardening::chrome_transfer_limit_warning(requested_len),
        }),
        Err(nusb::transfer::TransferError::Stall) => Ok(InTransferResult { status: TransferStatus::Stall, data: String::new(), warning: None }),
        Err(nusb::transfer::TransferError::Disconnected) => Err(WebUsbError::not_found("device was disconnected during the transfer")),
        Err(e) => Err(WebUsbError::invalid_state(format!("transfer failed: {e}"))),
    }
}

fn transfer_completion_to_out_result(status: Result<(), nusb::transfer::TransferError>, actual_len: u32, requested_len: u64) -> Result<OutTransferResult, WebUsbError> {
    match status {
        Ok(()) => Ok(OutTransferResult { status: TransferStatus::Ok, bytes_written: actual_len, warning: hardening::chrome_transfer_limit_warning(requested_len) }),
        Err(nusb::transfer::TransferError::Stall) => Ok(OutTransferResult { status: TransferStatus::Stall, bytes_written: actual_len, warning: None }),
        Err(nusb::transfer::TransferError::Disconnected) => Err(WebUsbError::not_found("device was disconnected during the transfer")),
        Err(e) => Err(WebUsbError::invalid_state(format!("transfer failed: {e}"))),
    }
}

// ================================================================
// Isochronous transfers — see error.rs and hardening.rs module docs
// ================================================================
// Full validation (endpoint exists, is actually isochronous, packetLengths
// is well-formed and within limits) runs regardless, so the moment upstream
// `nusb` gains isochronous support (tracked at
// https://github.com/kevinmehall/nusb/issues/47 as of this writing), only
// the final "not supported" branch below needs to change — everything
// upstream of it already produces exactly the validated inputs a real
// implementation would need.

pub async fn isochronous_transfer_in(
    sessions: &SessionRegistry, origin: &str, handle: u32, endpoint_number: u8, packet_lengths: Vec<u32>,
) -> Result<Vec<IsochronousInPacket>, WebUsbError> {
    if packet_lengths.len() > hardening::MAX_ISOCHRONOUS_PACKETS {
        return Err(WebUsbError::data_error(format!(
            "packetLengths has {} entries, exceeding this implementation's {}-entry ceiling",
            packet_lengths.len(),
            hardening::MAX_ISOCHRONOUS_PACKETS
        )));
    }
    let total: u64 = packet_lengths.iter().map(|&l| l as u64).sum();
    if total > hardening::ISOCHRONOUS_TRANSFER_MAX_TOTAL_LENGTH {
        return Err(WebUsbError::data_error(format!(
            "total packetLengths {total} exceeds this implementation's {}-byte transfer ceiling",
            hardening::ISOCHRONOUS_TRANSFER_MAX_TOTAL_LENGTH
        )));
    }
    with_session(sessions, origin, handle, move |session| {
        Box::pin(async move {
            let (_iface, ep_desc) = resolve_transfer_endpoint(session, endpoint_number, Direction::In)?;
            if !hardening::is_isochronous_endpoint(&ep_desc) {
                return Err(WebUsbError::invalid_access(format!("endpoint {endpoint_number} is not an isochronous endpoint")));
            }
            Err(isochronous_not_supported())
        })
    })
    .await
}

pub async fn isochronous_transfer_out(
    sessions: &SessionRegistry, origin: &str, handle: u32, endpoint_number: u8, data: Vec<u8>, packet_lengths: Vec<u32>,
) -> Result<Vec<IsochronousOutPacket>, WebUsbError> {
    if packet_lengths.len() > hardening::MAX_ISOCHRONOUS_PACKETS {
        return Err(WebUsbError::data_error(format!(
            "packetLengths has {} entries, exceeding this implementation's {}-entry ceiling",
            packet_lengths.len(),
            hardening::MAX_ISOCHRONOUS_PACKETS
        )));
    }
    let total: u64 = packet_lengths.iter().map(|&l| l as u64).sum();
    if total != data.len() as u64 {
        // Real Blink behavior (confirmed by pyside6-webusb v0.0.4b2 against
        // `usb_device.cc`): a mismatch between the data buffer's length and
        // the sum of packetLengths is `DataError`, not `IndexSizeError` —
        // see `error.rs`'s module doc comment.
        return Err(WebUsbError::data_error(format!(
            "data length ({}) does not match the sum of packetLengths ({total})",
            data.len()
        )));
    }
    if total > hardening::ISOCHRONOUS_TRANSFER_MAX_TOTAL_LENGTH {
        return Err(WebUsbError::data_error(format!(
            "total packetLengths {total} exceeds this implementation's {}-byte transfer ceiling",
            hardening::ISOCHRONOUS_TRANSFER_MAX_TOTAL_LENGTH
        )));
    }
    with_session(sessions, origin, handle, move |session| {
        Box::pin(async move {
            let (_iface, ep_desc) = resolve_transfer_endpoint(session, endpoint_number, Direction::Out)?;
            if !hardening::is_isochronous_endpoint(&ep_desc) {
                return Err(WebUsbError::invalid_access(format!("endpoint {endpoint_number} is not an isochronous endpoint")));
            }
            Err(isochronous_not_supported())
        })
    })
    .await
}

fn isochronous_not_supported() -> WebUsbError {
    WebUsbError::not_supported(
        "isochronous transfers are not implemented in this version of tauri-webusb: the nusb \
         backend this plugin uses has no isochronous transfer support to call into as of this \
         writing (tracked upstream at https://github.com/kevinmehall/nusb/issues/47). A hand-rolled \
         unsafe libusb-FFI implementation was deliberately not attempted for v0.0.0 with no real \
         isochronous-capable hardware available to validate it against — see README.md's \
         'Known limitations' section.",
    )
}

// ================================================================
// misc helpers
// ================================================================

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Public wrapper so `commands.rs` (which needs an identically-formatted
/// timestamp when recording a `requestDevice()` grant) shares the exact same
/// clock/formatting logic as `open_device`'s own `record_device_usage` call,
/// rather than a second, potentially-drifting implementation.
pub fn now_iso8601_pub() -> String {
    now_iso8601()
}

fn now_iso8601() -> String {
    // A tiny, dependency-free RFC 3339 formatter for `SystemTime::now()`,
    // UTC only (this plugin has no reason to care about local timezones —
    // `grantedAt`/`lastSeenAt` are machine-readable bookkeeping, not
    // presented to the person directly). Deliberately not pulling in
    // `chrono`/`time` for what's otherwise a one-call use of this crate's
    // only timestamp need.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    let (days, time_of_day) = (secs / 86400, secs % 86400);
    let (hour, minute, second) = (time_of_day / 3600, (time_of_day % 3600) / 60, time_of_day % 60);
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's `civil_from_days` algorithm (public domain), converting
/// a day count since the Unix epoch into a proleptic-Gregorian
/// (year, month, day) triple without pulling in a chrono/time dependency.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_up_to_packet_multiple_exact_multiple_unchanged() {
        assert_eq!(round_up_to_packet_multiple(128, 64), 128);
    }

    #[test]
    fn round_up_to_packet_multiple_rounds_up() {
        assert_eq!(round_up_to_packet_multiple(10, 64), 64);
        assert_eq!(round_up_to_packet_multiple(65, 64), 128);
    }

    #[test]
    fn round_up_to_packet_multiple_zero_length_still_submits_one_packet() {
        assert_eq!(round_up_to_packet_multiple(0, 64), 64);
    }

    #[test]
    fn civil_from_days_epoch_is_1970_01_01() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn civil_from_days_known_date() {
        // 🔧 Corrected during this crate's security-hardening pass: this
        // test failed when actually run (see README.md's "Development
        // environment" note on how — against a stubbed-out `nusb`/`tauri`,
        // since this specific function needs neither). The *algorithm*
        // (Howard Hinnant's `civil_from_days`, verified against
        // http://howardhinnant.github.io/date_algorithms.html) was correct
        // all along; this test's own hand-computed expected value was off
        // by one day, confirmed independently against Python's
        // `datetime.date(1970, 1, 1) + timedelta(days=20701)`. 2026-09-05,
        // not 2026-09-04, is 20701 days after the epoch.
        assert_eq!(civil_from_days(20701), (2026, 9, 5));
    }

    #[test]
    fn endpoint_address_sets_and_clears_direction_bit() {
        assert_eq!(endpoint_address(1, Direction::In), 0x81);
        assert_eq!(endpoint_address(1, Direction::Out), 0x01);
        assert_eq!(endpoint_address(15, Direction::In), 0x8F);
    }
}
