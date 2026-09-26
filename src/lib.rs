//! tauri-webusb
//! ============
//! A Tauri v2 plugin porting the WebUSB API (`navigator.usb`) to Tauri
//! desktop apps, for platforms/webviews with no native WebUSB implementation
//! (which, as of this writing, is every platform Tauri targets — WebView2,
//! WKWebView, and WebKitGTK are all non-Chromium and implement no version of
//! WebUSB). See `README.md` for the full picture: architecture, security
//! model, what's ported from where, and known limitations.
//!
//! This file is intentionally just wiring: module declarations, the
//! `tauri::plugin::Builder`, command registration, and the `setup` hook that
//! loads settings and starts the hotplug watcher. Every actual decision
//! lives in one of the modules below — start with whichever doc comment
//! matches what you're looking for:
//!
//! - `error.rs` — the `DOMException` name taxonomy every command's `Result`
//!   is shaped into.
//! - `models.rs` — the backend-agnostic data shapes (`DeviceDescriptor` and
//!   friends) everything else operates on.
//! - `hardening.rs` — the actual WebUSB security model: protected interface
//!   classes, the blocklist, filter matching, transfer-size policy.
//! - `origin.rs` — how a calling webview's verified origin is derived, and
//!   why that needs no bespoke token scheme in Tauri.
//! - `settings_logic.rs` / `settings_store.rs` — persistent per-origin
//!   device grants and the known-devices history.
//! - `bridge.rs` — the actual `nusb`-backed session manager: open, claim,
//!   transfer.
//! - `chooser.rs` — the `requestDevice()` picker window.
//! - `hotplug.rs` — `onconnect`/`ondisconnect` fan-out.
//! - `commands.rs` — the `#[tauri::command]` functions tying all of the
//!   above to the guest-js layer.

mod bridge;
mod chooser;
mod commands;
mod error;
mod hardening;
mod hotplug;
mod models;
mod origin;
mod settings_logic;
mod settings_store;
mod state;

use settings_store::SettingsStore;
use state::WebUsbState;
use std::sync::Arc;
use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

/// `tauri_plugin_webusb::init()` — call this from the consuming app's
/// `tauri::Builder` chain:
///
/// ```ignore
/// tauri::Builder::default()
///     .plugin(tauri_plugin_webusb::init())
///     // ...
///     .run(tauri::generate_context!())
/// ```
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("webusb")
        .invoke_handler(tauri::generate_handler![
            commands::get_devices,
            commands::request_device,
            commands::open,
            commands::close,
            commands::forget,
            commands::select_configuration,
            commands::claim_interface,
            commands::release_interface,
            commands::select_alternate_interface,
            commands::reset_device,
            commands::clear_halt,
            commands::control_transfer_in,
            commands::control_transfer_out,
            commands::transfer_in,
            commands::transfer_out,
            commands::isochronous_transfer_in,
            commands::isochronous_transfer_out,
            commands::chooser_list_candidates,
            commands::chooser_select,
            commands::chooser_cancel,
            commands::list_granted_origins,
            commands::revoke_origin_grant,
            commands::revoke_all_for_origin,
            commands::list_known_devices,
            commands::forget_known_device,
            commands::forget_all_known_devices,
        ])
        .setup(|app, _api| {
            // `SettingsStore::init` returns `Result<_, String>` (see that
            // module's doc comment on why it's a plain String rather than a
            // custom error type: it never leaves this process, so a real
            // `std::error::Error` impl would add ceremony for no consumer).
            // Converted explicitly here, rather than via a bare `?`, since
            // this file is one of the ones this crate's README flags as not
            // compiled in the sandbox it was written in — an explicit
            // `std::io::Error::other(...)` (stable since Rust 1.74) is a
            // deliberately conservative choice that doesn't depend on
            // exactly which blanket `From` impls apply to whatever error
            // type Tauri's own `setup` hook expects in the version actually
            // being built against.
            let settings = SettingsStore::init(app.app_handle()).map_err(std::io::Error::other)?;
            let settings = Arc::new(settings);

            // The hotplug task (spawned below, living for the app's whole
            // lifetime) and every command (via `tauri::State<WebUsbState>`,
            // living for one invocation at a time) need their own
            // independent handles to the *same* underlying store — hence
            // `Arc`, cloned once here for `WebUsbState` and once more for
            // the task below.
            app.manage(WebUsbState::new(Arc::clone(&settings)));

            let app_handle = app.app_handle().clone();
            tauri::async_runtime::spawn(hotplug::run(app_handle, settings));

            Ok(())
        })
        .build()
}
