//! chooser.rs
//! ==========
//! `requestDevice()`'s picker UI: a small, dedicated `WebviewWindow` this
//! plugin creates on demand, showing a live-refreshing list of currently-
//! connected devices matching the page's requested filters, letting the
//! person pick one (or cancel).
//!
//! ## Why a real window instead of `tauri-plugin-dialog`
//!
//! Tauri's own dialog plugin covers message boxes and file/folder pickers —
//! nothing with a live-updating, multi-column, selectable list. Both
//! predecessors needed the same kind of custom UI for the same reason
//! (`pyside6-webusb`: a `QDialog` with a `QListWidget`, refreshed on a
//! `QTimer`; `fox-webusb`: a `tkinter.Toplevel` with a `Treeview`, refreshed
//! via `after(1500, refresh)`, — see `chooser_dialog.py`). A dedicated
//! `WebviewWindow` is tauri-webusb's equivalent: a real native window,
//! entirely under this plugin's control, showing HTML/CSS/JS this plugin
//! ships (`chooser-ui/index.html`) rather than anything the host app
//! provides.
//!
//! ## Why window identity instead of a shared/generic command
//!
//! The chooser window's JS needs to ask Rust for the current candidate list
//! on a refresh timer, and to report back which device (if any) the person
//! picked. Both of those need their own commands
//! (`chooser_list_candidates`, `chooser_select`, `chooser_cancel` — see
//! `commands.rs`) — but those commands must be answerable *only* by the
//! actual chooser window this plugin itself created for an actually-pending
//! `requestDevice()` call, never by an ordinary page. If `chooser_list_candidates`
//! were reachable by any page holding the plugin's normal page-facing
//! permission, a page could invoke it directly, with arbitrary filters, with
//! no `requestDevice()` call and no chooser UI ever shown at all — silently
//! reintroducing exactly the passive device-fingerprinting-without-a-user-gesture
//! problem the whole permission-prompt model exists to prevent.
//!
//! Rather than inventing a bespoke unguessable-token scheme to close that
//! hole (the way, say, `pyside6-webusb`'s `frame_origin.py` had to, absent
//! anything better — see that module's doc comment in `origin.rs`), this
//! uses something Tauri already gives for free: **window identity**. This
//! plugin picks the chooser window's label itself
//! (`tauri-webusb-chooser-{origin-hash}`) when creating it, and every
//! chooser-only command checks — via the same `tauri::Window`/`Webview`
///   dependency-injection mechanism `origin.rs` uses for `.url()` — that the
//! *calling* window's label matches the label of the currently-open chooser
//! session before doing anything. An ordinary page window has whatever
//! label the host app gave it, which cannot collide with a label this
//! plugin generates for its own window, so the check is exact and requires
//! no secrets to be generated, stored, or compared.

use crate::bridge;
use crate::hardening;
use crate::models::{DeviceDescriptor, UsbDeviceFilter};
use crate::error::WebUsbError;
use std::sync::Arc;
use tauri::{AppHandle, Manager, Runtime, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::{oneshot, Mutex};

const CHOOSER_UI_HTML: &str = include_str!("../chooser-ui/index.html");
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1200); // matches both predecessors' ~1.5s cadence, slightly snappier since there's no IPC-chunking overhead to amortize here

enum ChooserOutcome {
    Selected { vendor_id: u16, product_id: u16 },
    Cancelled,
}

struct ActiveChooser {
    window_label: String,
    origin: String,
    filters: Vec<UsbDeviceFilter>,
    exclusion_filters: Vec<UsbDeviceFilter>,
    outcome_tx: Mutex<Option<oneshot::Sender<ChooserOutcome>>>,
}

#[derive(Default)]
pub struct ChooserRegistry {
    /// One chooser at a time, globally — matches the practical constraint
    /// both predecessors had (a single native dialog window/widget), and
    /// keeps "which window may call the chooser-only commands" a single
    /// unambiguous check rather than a set.
    active: Mutex<Option<Arc<ActiveChooser>>>,
}

impl ChooserRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// `Some(origin)` the currently-open chooser (if any) belongs to, and
    /// the window label a caller must match to touch it. Used by
    /// `commands.rs`'s chooser-only commands to check the *calling*
    /// window's own label (via dependency-injected `tauri::Window`) against
    /// this before doing anything — see the module doc comment.
    async fn current(&self) -> Option<Arc<ActiveChooser>> {
        self.active.lock().await.clone()
    }
}

/// Entry point called from the `request_device` command. Blocks (as an
/// async future — no OS thread is tied up) until the person picks a device
/// or dismisses the chooser, then resolves or rejects accordingly. Only one
/// of these can be in flight at a time across the whole app; a second call
/// while one is already open gets `InvalidStateError` immediately, matching
/// both predecessors (`ChooserAlreadyOpenError` / the Tkinter dialog's own
/// single-instance assumption).
pub async fn run<R: Runtime>(
    app: &AppHandle<R>,
    chooser: &ChooserRegistry,
    origin: &str,
    filters: Vec<UsbDeviceFilter>,
    exclusion_filters: Vec<UsbDeviceFilter>,
) -> Result<DeviceDescriptor, WebUsbError> {
    let (outcome_tx, outcome_rx) = oneshot::channel();
    let window_label = format!("tauri-webusb-chooser-{}", short_hash(origin));

    {
        let mut guard = chooser.active.lock().await;
        if guard.is_some() {
            return Err(WebUsbError::invalid_state("a device chooser is already open"));
        }
        *guard = Some(Arc::new(ActiveChooser {
            window_label: window_label.clone(),
            origin: origin.to_string(),
            filters: filters.clone(),
            exclusion_filters: exclusion_filters.clone(),
            outcome_tx: Mutex::new(Some(outcome_tx)),
        }));
    }

    // Self-contained `data:` URL — see the crate-level README's
    // "Chooser window" design note for why this plugin doesn't rely on the
    // *host* app's own bundled frontend assets to serve its picker UI: a
    // reusable plugin shouldn't need every consuming app to wire its static
    // assets into their own build output. `CHOOSER_UI_HTML` is compiled
    // directly into this plugin's binary via `include_str!`.
    let data_url = format!("data:text/html;base64,{}", base64_encode(CHOOSER_UI_HTML.as_bytes()));
    let build_result = WebviewWindowBuilder::new(app, &window_label, WebviewUrl::External(data_url.parse().expect("valid data: URL")))
        .title("Select a device")
        .inner_size(480.0, 420.0)
        .resizable(true)
        .always_on_top(true)
        .build();

    let window = match build_result {
        Ok(w) => w,
        Err(e) => {
            *chooser.active.lock().await = None;
            return Err(WebUsbError::invalid_state(format!("could not open the device chooser window: {e}")));
        }
    };

    // If the person closes the window directly (titlebar close button, Alt+F4,
    // Cmd+W, ...) rather than clicking Cancel in the page itself, that must
    // still resolve the pending `requestDevice()` call (as a rejection) —
    // otherwise the page's promise would simply hang forever.
    {
        let chooser_for_close = chooser as *const ChooserRegistry as usize; // see note below
        let label_for_close = window_label.clone();
        window.on_window_event(move |event| {
            if matches!(event, tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed) {
                // SAFETY: `chooser` outlives every window this function
                // creates — the caller (`commands.rs::request_device`) holds
                // `tauri::State<WebUsbState>` for the whole lifetime of the
                // Tauri app, and this closure only ever runs while that
                // state is alive. Reconstructing the reference from a raw
                // pointer here (rather than capturing `&ChooserRegistry`
                // directly) is only needed because `on_window_event`'s
                // closure bound requires `'static`, and threading an `Arc`
                // through would mean `ChooserRegistry` itself has to be
                // `Arc`-wrapped everywhere it's used elsewhere in the crate
                // for no other reason than this one callback.
                let chooser_ref = unsafe { &*(chooser_for_close as *const ChooserRegistry) };
                let label = label_for_close.clone();
                tauri::async_runtime::spawn(async move {
                    resolve_if_matching(chooser_ref, &label, ChooserOutcome::Cancelled).await;
                });
            }
        });
    }

    // Live-refresh loop: re-runs the filter match every REFRESH_INTERVAL and
    // pushes the current candidate list to the chooser window via an
    // ordinary Tauri event (the window itself is this plugin's own trusted
    // UI, so a plain broadcast `emit` — rather than the window-identity gate
    // the *commands* need — is fine here; nothing else is listening for an
    // event on this plugin-internal channel name).
    {
        let window_for_refresh = window.clone();
        let filters_for_refresh = filters.clone();
        let exclusion_for_refresh = exclusion_filters.clone();
        tauri::async_runtime::spawn(async move {
            loop {
                match bridge::candidates_for_chooser(&filters_for_refresh, &exclusion_for_refresh).await {
                    Ok(candidates) => {
                        let _ = window_for_refresh.emit("tauri-webusb://chooser-candidates", &candidates);
                    }
                    Err(_) => { /* transient enumeration failure: try again next tick rather than tearing down the whole chooser over it */ }
                }
                tokio::time::sleep(REFRESH_INTERVAL).await;
                if !window_for_refresh.is_visible().unwrap_or(false) {
                    break; // window closed; on_window_event above already handles resolving the outcome
                }
            }
        });
    }

    let outcome = outcome_rx.await.unwrap_or(ChooserOutcome::Cancelled);
    let _ = window.close();
    *chooser.active.lock().await = None;

    match outcome {
        ChooserOutcome::Cancelled => Err(WebUsbError::not_found("no device was selected")),
        ChooserOutcome::Selected { vendor_id, product_id } => {
            // Re-validate against the *current* state rather than trusting
            // the selection payload alone: the device could have been
            // unplugged, or newly blocklisted, in the moment between the
            // person clicking and this line running.
            let candidates = bridge::candidates_for_chooser(&filters, &exclusion_filters).await?;
            let picked = candidates
                .into_iter()
                .find(|d| d.vendor_id == vendor_id && d.product_id == product_id)
                .ok_or_else(|| WebUsbError::not_found("the selected device is no longer available"))?;
            if hardening::device_is_fully_blocked(&picked) {
                return Err(WebUsbError::security("the selected device cannot be granted (blocklisted)"));
            }
            Ok(picked)
        }
    }
}

async fn resolve_if_matching(chooser: &ChooserRegistry, expected_label: &str, outcome: ChooserOutcome) {
    if let Some(active) = chooser.current().await {
        if active.window_label == expected_label {
            if let Some(tx) = active.outcome_tx.lock().await.take() {
                let _ = tx.send(outcome);
            }
        }
    }
}

// ---- called from commands.rs, gated by the calling window's own label ----

/// `None` if `caller_window_label` doesn't match the currently-open
/// chooser's window — see the module doc comment for why that's the whole
/// access-control mechanism here.
pub async fn candidates_for(chooser: &ChooserRegistry, caller_window_label: &str) -> Option<(Vec<UsbDeviceFilter>, Vec<UsbDeviceFilter>)> {
    let active = chooser.current().await?;
    if active.window_label != caller_window_label {
        return None;
    }
    Some((active.filters.clone(), active.exclusion_filters.clone()))
}

pub async fn submit_selection(chooser: &ChooserRegistry, caller_window_label: &str, vendor_id: u16, product_id: u16) -> bool {
    let Some(active) = chooser.current().await else { return false };
    if active.window_label != caller_window_label {
        return false;
    }
    if let Some(tx) = active.outcome_tx.lock().await.take() {
        let _ = tx.send(ChooserOutcome::Selected { vendor_id, product_id });
        true
    } else {
        false
    }
}

pub async fn submit_cancel(chooser: &ChooserRegistry, caller_window_label: &str) -> bool {
    let Some(active) = chooser.current().await else { return false };
    if active.window_label != caller_window_label {
        return false;
    }
    if let Some(tx) = active.outcome_tx.lock().await.take() {
        let _ = tx.send(ChooserOutcome::Cancelled);
        true
    } else {
        false
    }
}

/// Also exposes which `origin` a chooser-only command's caller is acting
/// for, so `commands.rs` doesn't need a second lookup — the window label
/// alone already proves the caller *is* the legitimate chooser window, and
/// the origin stored alongside it at creation time is what the picked
/// device's grant should actually be recorded against.
pub async fn origin_for(chooser: &ChooserRegistry, caller_window_label: &str) -> Option<String> {
    let active = chooser.current().await?;
    (active.window_label == caller_window_label).then(|| active.origin.clone())
}

fn short_hash(s: &str) -> String {
    // FNV-1a — good enough for "make a window label that won't collide with
    // an app's own window labels", not a security boundary itself (the
    // security boundary is the label *match* check above, not the hash
    // being hard to predict).
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in s.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_hash_is_deterministic() {
        assert_eq!(short_hash("https://example.com"), short_hash("https://example.com"));
    }

    #[test]
    fn short_hash_differs_for_different_origins() {
        assert_ne!(short_hash("https://a.example.com"), short_hash("https://b.example.com"));
    }

    #[test]
    fn short_hash_is_hex_of_fixed_length() {
        let h = short_hash("https://example.com");
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn short_hash_empty_string_does_not_panic() {
        let h = short_hash("");
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn short_hash_single_bit_flip_changes_output() {
        assert_ne!(short_hash("https://example.com"), short_hash("https://Example.com"));
    }
}
