//! commands.rs
//! ===========
//! Every `#[tauri::command]` this plugin exposes. Deliberately thin: each
//! function's job is (1) resolve the calling webview's verified origin via
//! `origin::origin_of(&webview.url())`, (2) delegate to `bridge.rs` /
//! `settings_store.rs` / `chooser.rs`, (3) shape the `Result` the way
//! `error.rs` expects. All the actual decisions happen in those other
//! modules — see each one's doc comment.
//!
//! ## Two permission tiers
//!
//! Commands are split into two `permissions/*.toml` sets (see that
//! directory's own files for the exact identifiers):
//! - **page** — the `navigator.usb` surface itself
//!   (`getDevices`/`requestDevice`/`open`/transfers/...). An app grants this
//!   to any window/webview whose content should see `navigator.usb` at all.
//! - **manage** — origin/device bookkeeping for a trusted management UI
//!   (`listGrantedOrigins`, `revokeOriginGrant`, `listKnownDevices`, ...). An
//!   app grants this *only* to its own trusted internal window, never to a
//!   window that loads third-party content — see `README.md`'s "Trust
//!   model" section for why this two-tier split, enforced by Tauri's own
//!   capability system before a command handler ever runs, replaces what
//!   `fox-webusb`/`pyside6-webusb` each built by hand
//!   (`_TRUSTED_ONLY_METHODS` + a sender-verified check inside their own
//!   dispatcher).
//!
//! Chooser-only commands (`chooser_list_candidates`, `chooser_select`,
//! `chooser_cancel`) are in neither set in the normal sense — see
//! `chooser.rs`'s module doc comment for why those are gated by the calling
//! *window's own label* rather than by origin or by capability at all.

use crate::bridge::{self, ControlSetup};
use crate::chooser;
use crate::error::WebUsbError;
use crate::models::*;
use crate::origin::origin_of;
use crate::settings_logic::{GrantedDevice, KnownDevice};
use crate::state::WebUsbState;
use tauri::{command, State, Webview};

fn require_origin<R: tauri::Runtime>(webview: &Webview<R>) -> Result<String, WebUsbError> {
    let url = webview.url().map_err(|e| WebUsbError::security(format!("could not resolve this window's URL: {e}")))?;
    origin_of(&url).ok_or_else(|| {
        WebUsbError::security(
            "WebUSB is not available for this page: it has no origin that permissions can be \
             granted against (e.g. a data: URL, or about:blank)",
        )
    })
}

// ================================================================
// Page-facing WebUSB surface (permission set: "page")
// ================================================================

#[command]
pub async fn get_devices<R: tauri::Runtime>(webview: Webview<R>, state: State<'_, WebUsbState>) -> Result<Vec<DeviceDescriptor>, WebUsbError> {
    let origin = require_origin(&webview)?;
    bridge::list_granted_devices(&state.settings, &origin).await
}

#[command]
pub async fn request_device<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    webview: Webview<R>,
    state: State<'_, WebUsbState>,
    filters: Vec<UsbDeviceFilter>,
    exclusion_filters: Vec<UsbDeviceFilter>,
) -> Result<DeviceDescriptor, WebUsbError> {
    let origin = require_origin(&webview)?;
    for f in filters.iter().chain(exclusion_filters.iter()) {
        if !crate::hardening::is_valid_usb_device_filter(f) {
            return Err(WebUsbError::not_found("one or more filters is invalid (e.g. productId without vendorId)"));
        }
    }
    let picked = chooser::run(&app, &state.chooser, &origin, filters, exclusion_filters).await?;
    let now = bridge::now_iso8601_pub();
    state.settings.mutate(|d| { d.grant_origin(&origin, picked.vendor_id, picked.product_id, &now); ((), true) }).await;
    Ok(picked)
}

#[command]
pub async fn open<R: tauri::Runtime>(webview: Webview<R>, state: State<'_, WebUsbState>, vendor_id: u16, product_id: u16) -> Result<OpenResult, WebUsbError> {
    let origin = require_origin(&webview)?;
    let (handle, descriptor) = bridge::open_device(&state.settings, &state.sessions, &origin, vendor_id, product_id).await?;
    Ok(OpenResult { handle, descriptor })
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenResult {
    pub handle: u32,
    pub descriptor: DeviceDescriptor,
}

#[command]
pub async fn close<R: tauri::Runtime>(webview: Webview<R>, state: State<'_, WebUsbState>, handle: u32) -> Result<(), WebUsbError> {
    let origin = require_origin(&webview)?;
    bridge::close_device(&state.sessions, &origin, handle).await
}

#[command]
pub async fn forget<R: tauri::Runtime>(webview: Webview<R>, state: State<'_, WebUsbState>, handle: u32) -> Result<(), WebUsbError> {
    let origin = require_origin(&webview)?;
    bridge::forget_device(&state.settings, &state.sessions, &origin, handle).await
}

#[command]
pub async fn select_configuration<R: tauri::Runtime>(webview: Webview<R>, state: State<'_, WebUsbState>, handle: u32, configuration_value: u8) -> Result<(), WebUsbError> {
    let origin = require_origin(&webview)?;
    bridge::select_configuration(&state.sessions, &origin, handle, configuration_value).await
}

#[command]
pub async fn claim_interface<R: tauri::Runtime>(webview: Webview<R>, state: State<'_, WebUsbState>, handle: u32, interface_number: u8) -> Result<(), WebUsbError> {
    let origin = require_origin(&webview)?;
    bridge::claim_interface(&state.sessions, &origin, handle, interface_number).await
}

#[command]
pub async fn release_interface<R: tauri::Runtime>(webview: Webview<R>, state: State<'_, WebUsbState>, handle: u32, interface_number: u8) -> Result<(), WebUsbError> {
    let origin = require_origin(&webview)?;
    bridge::release_interface(&state.sessions, &origin, handle, interface_number).await
}

#[command]
pub async fn select_alternate_interface<R: tauri::Runtime>(
    webview: Webview<R>, state: State<'_, WebUsbState>, handle: u32, interface_number: u8, alternate_setting: u8,
) -> Result<(), WebUsbError> {
    let origin = require_origin(&webview)?;
    bridge::select_alternate_interface(&state.sessions, &origin, handle, interface_number, alternate_setting).await
}

#[command]
pub async fn reset_device<R: tauri::Runtime>(webview: Webview<R>, state: State<'_, WebUsbState>, handle: u32) -> Result<(), WebUsbError> {
    let origin = require_origin(&webview)?;
    bridge::reset_device(&state.sessions, &origin, handle).await
}

#[command]
pub async fn clear_halt<R: tauri::Runtime>(webview: Webview<R>, state: State<'_, WebUsbState>, handle: u32, endpoint_number: u8, direction: Direction) -> Result<(), WebUsbError> {
    let origin = require_origin(&webview)?;
    bridge::clear_halt(&state.sessions, &origin, handle, endpoint_number, direction).await
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlSetupArg {
    pub request_type: String,
    pub recipient: String,
    pub request: u8,
    pub value: u16,
    pub index: u16,
}

impl From<ControlSetupArg> for ControlSetup {
    fn from(a: ControlSetupArg) -> Self {
        ControlSetup { request_type: a.request_type, recipient: a.recipient, request: a.request, value: a.value, index: a.index }
    }
}

#[command]
pub async fn control_transfer_in<R: tauri::Runtime>(
    webview: Webview<R>, state: State<'_, WebUsbState>, handle: u32, setup: ControlSetupArg, length: u32,
) -> Result<InTransferResult, WebUsbError> {
    let origin = require_origin(&webview)?;
    bridge::control_transfer_in(&state.sessions, &origin, handle, setup.into(), length).await
}

#[command]
pub async fn control_transfer_out<R: tauri::Runtime>(
    webview: Webview<R>, state: State<'_, WebUsbState>, handle: u32, setup: ControlSetupArg, data: String,
) -> Result<OutTransferResult, WebUsbError> {
    let origin = require_origin(&webview)?;
    let bytes = decode_base64(&data)?;
    bridge::control_transfer_out(&state.sessions, &origin, handle, setup.into(), bytes).await
}

#[command]
pub async fn transfer_in<R: tauri::Runtime>(webview: Webview<R>, state: State<'_, WebUsbState>, handle: u32, endpoint_number: u8, length: u32) -> Result<InTransferResult, WebUsbError> {
    let origin = require_origin(&webview)?;
    bridge::transfer_in(&state.sessions, &origin, handle, endpoint_number, length).await
}

#[command]
pub async fn transfer_out<R: tauri::Runtime>(webview: Webview<R>, state: State<'_, WebUsbState>, handle: u32, endpoint_number: u8, data: String) -> Result<OutTransferResult, WebUsbError> {
    let origin = require_origin(&webview)?;
    let bytes = decode_base64(&data)?;
    bridge::transfer_out(&state.sessions, &origin, handle, endpoint_number, bytes).await
}

#[command]
pub async fn isochronous_transfer_in<R: tauri::Runtime>(
    webview: Webview<R>, state: State<'_, WebUsbState>, handle: u32, endpoint_number: u8, packet_lengths: Vec<u32>,
) -> Result<Vec<IsochronousInPacket>, WebUsbError> {
    let origin = require_origin(&webview)?;
    bridge::isochronous_transfer_in(&state.sessions, &origin, handle, endpoint_number, packet_lengths).await
}

#[command]
pub async fn isochronous_transfer_out<R: tauri::Runtime>(
    webview: Webview<R>, state: State<'_, WebUsbState>, handle: u32, endpoint_number: u8, data: String, packet_lengths: Vec<u32>,
) -> Result<Vec<IsochronousOutPacket>, WebUsbError> {
    let origin = require_origin(&webview)?;
    let bytes = decode_base64(&data)?;
    bridge::isochronous_transfer_out(&state.sessions, &origin, handle, endpoint_number, bytes, packet_lengths).await
}

// ================================================================
// Chooser-only commands — gated by window label, see chooser.rs
// ================================================================

#[command]
pub async fn chooser_list_candidates<R: tauri::Runtime>(webview: Webview<R>, state: State<'_, WebUsbState>) -> Result<Vec<DeviceDescriptor>, WebUsbError> {
    let label = webview.label().to_string();
    let Some((filters, exclusion_filters)) = chooser::candidates_for(&state.chooser, &label).await else {
        return Err(WebUsbError::security("this window is not an active device chooser"));
    };
    bridge::candidates_for_chooser(&filters, &exclusion_filters).await
}

#[command]
pub async fn chooser_select<R: tauri::Runtime>(webview: Webview<R>, state: State<'_, WebUsbState>, vendor_id: u16, product_id: u16) -> Result<(), WebUsbError> {
    let label = webview.label().to_string();
    if chooser::submit_selection(&state.chooser, &label, vendor_id, product_id).await {
        Ok(())
    } else {
        Err(WebUsbError::security("this window is not an active device chooser"))
    }
}

#[command]
pub async fn chooser_cancel<R: tauri::Runtime>(webview: Webview<R>, state: State<'_, WebUsbState>) -> Result<(), WebUsbError> {
    let label = webview.label().to_string();
    if chooser::submit_cancel(&state.chooser, &label).await {
        Ok(())
    } else {
        Err(WebUsbError::security("this window is not an active device chooser"))
    }
}

// ================================================================
// Trusted-management surface (permission set: "manage")
// ================================================================

#[command]
pub async fn list_granted_origins(state: State<'_, WebUsbState>) -> Result<std::collections::HashMap<String, Vec<GrantedDevice>>, WebUsbError> {
    Ok(state.settings.read(|d| d.granted_origins.clone()).await)
}

#[command]
pub async fn revoke_origin_grant(state: State<'_, WebUsbState>, origin: String, vendor_id: u16, product_id: u16) -> Result<bool, WebUsbError> {
    Ok(state.settings.mutate(|d| { let removed = d.revoke_origin_grant(&origin, vendor_id, product_id); (removed, removed) }).await)
}

#[command]
pub async fn revoke_all_for_origin(state: State<'_, WebUsbState>, origin: String) -> Result<usize, WebUsbError> {
    Ok(state.settings.mutate(|d| { let n = d.revoke_all_for_origin(&origin); (n, n > 0) }).await)
}

#[command]
pub async fn list_known_devices(state: State<'_, WebUsbState>) -> Result<Vec<KnownDevice>, WebUsbError> {
    Ok(state.settings.read(|d| d.known_devices.clone()).await)
}

#[command]
pub async fn forget_known_device(state: State<'_, WebUsbState>, vendor_id: u16, product_id: u16) -> Result<bool, WebUsbError> {
    Ok(state.settings.mutate(|d| { let removed = d.forget_known_device(vendor_id, product_id); (removed, removed) }).await)
}

#[command]
pub async fn forget_all_known_devices(state: State<'_, WebUsbState>) -> Result<usize, WebUsbError> {
    Ok(state.settings.mutate(|d| { let n = d.forget_all_known_devices(); (n, n > 0) }).await)
}

// ================================================================
// misc helpers
// ================================================================

fn decode_base64(s: &str) -> Result<Vec<u8>, WebUsbError> {
    use base64::Engine;
    // NotFoundError here is a deliberate, if imperfect, choice: this can
    // only happen if the guest-js layer itself sent malformed data (a bug
    // in this plugin's own polyfill, not something a page's own JS can
    // trigger — the polyfill always base64-encodes its own `BufferSource`
    // arguments), so no DOMException name is truly "correct" for it.
    base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| WebUsbError::not_found(format!("invalid base64 payload: {e}")))
}
