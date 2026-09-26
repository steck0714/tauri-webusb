//! hotplug.rs
//! ==========
//! Fires `USBConnectionEvent`s (`navigator.usb.onconnect` /
//! `.ondisconnect`) when a device that some origin already holds a grant for
//! is plugged in or unplugged — spec behavior, and something both
//! predecessors also implement (`pyside6-webusb`'s `HotplugManager`,
//! `fox-webusb`'s equivalent background thread).
//!
//! ## Polling, not `nusb::watch_devices()`
//!
//! `nusb` has a native hotplug stream (`nusb::watch_devices()`). This module
//! uses periodic polling instead, for the same reason flagged in
//! `bridge.rs`'s module doc comment: the exact stream item shape wasn't
//! something this crate's author could confirm with enough confidence to
//! commit to without being able to compile against it in this sandboxed
//! environment. Polling is simple enough to get right from first
//! principles (diff two device lists) and to unit-test the diffing logic
//! for directly, with no `nusb` type in the function signature at all —
//! see `diff_snapshots` below. A future version switching to
//! `watch_devices()` for lower latency should be a localized change to this
//! file's `run` function; nothing about the fan-out logic or its tests would
//! need to change.
//!
//! ## Fan-out: who actually receives the event
//!
//! A connect/disconnect event for device `(vendorId, productId)` only ever
//! reaches a webview when *both*:
//! 1. that webview's own current origin (`origin::origin_of(&webview.url())`)
//!    holds a grant for that exact device
//!    (`SettingsData::granted_origins_for_device`), and
//! 2. that webview still exists / is still enumerable via
//!    `app.webview_windows()` at the moment the event fires.
//!
//! This is deliberately re-checked from scratch on every hotplug tick
//! (rather than, say, a registry of "origins that have ever asked for
//! hotplug events") for the same reason `origin.rs`'s doc comment gives for
//! not needing a frame-registration handshake at all: Tauri's own
//! `webview.url()` is always the live, current answer, so there is nothing
//! to keep in sync — a webview that has since navigated away from a granted
//! origin simply won't match anymore, automatically.

use crate::bridge;
use crate::hardening;
use crate::models::{DeviceDescriptor, UsbDeviceFilter};
use crate::origin::origin_of;
use crate::settings_store::SettingsStore;
use std::collections::HashMap;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, Runtime};

const POLL_INTERVAL: Duration = Duration::from_millis(1500);

/// Identity key for one physical, currently-connected device across
/// consecutive polls. `(vendorId, productId)` alone isn't enough (two
/// identical devices could be plugged in at once); `nusb::DeviceInfo`'s own
/// bus/address pair is what actually distinguishes them — see `bridge.rs`'s
/// module doc comment on why the exact accessor names for these are one of
/// the less-certain spots. If `busId`/`deviceAddress`-equivalent fields turn
/// out to have different names in the `nusb` version actually resolved,
/// this type (and only the snapshot-taking code in `run`, not
/// `diff_snapshots`) is what needs adjusting.
type PhysicalDeviceId = (u32, u32);

struct TrackedDevice {
    vendor_id: u16,
    product_id: u16,
    /// Full descriptor captured while the device was still connected — a
    /// `disconnect` event still needs a fully-shaped `USBDevice` payload
    /// (per spec) despite the device no longer being reachable to read
    /// descriptors from at the moment the event fires.
    last_known_descriptor: DeviceDescriptor,
}

/// Pure diff: given the previous poll's identities and the current poll's
/// `(identity, vendorId, productId)` triples, returns
/// `(newly_connected_identities, newly_disconnected_identities)`. No `nusb`
/// type appears in this signature at all, which is what makes it directly
/// unit-testable — see the `tests` module.
fn diff_snapshots(
    previous: &[PhysicalDeviceId],
    current: &[(PhysicalDeviceId, u16, u16)],
) -> (Vec<(PhysicalDeviceId, u16, u16)>, Vec<PhysicalDeviceId>) {
    let current_ids: Vec<PhysicalDeviceId> = current.iter().map(|(id, ..)| *id).collect();
    let added = current.iter().filter(|(id, ..)| !previous.contains(id)).cloned().collect();
    let removed = previous.iter().filter(|id| !current_ids.contains(id)).copied().collect();
    (added, removed)
}

/// Spawned once from `lib.rs`'s `setup` hook and left running for the life
/// of the app (`tauri::async_runtime::spawn`, not awaited).
pub async fn run<R: Runtime>(app: AppHandle<R>, settings: std::sync::Arc<SettingsStore>) {
    let mut tracked: HashMap<PhysicalDeviceId, TrackedDevice> = HashMap::new();

    loop {
        tokio::time::sleep(POLL_INTERVAL).await;

        let current = match snapshot().await {
            Ok(s) => s,
            Err(_) => continue, // transient enumeration failure: just try again next tick
        };
        let previous_ids: Vec<PhysicalDeviceId> = tracked.keys().copied().collect();
        let current_triples: Vec<(PhysicalDeviceId, u16, u16)> =
            current.iter().map(|(id, vid, pid, _)| (*id, *vid, *pid)).collect();
        let (added, removed) = diff_snapshots(&previous_ids, &current_triples);

        for (id, vendor_id, product_id) in added {
            let Some((_, _, _, descriptor)) = current.iter().find(|(i, ..)| *i == id) else { continue };
            if hardening::device_is_fully_blocked(descriptor) {
                continue; // never announce a blocklisted device's arrival, even to an origin with a stale grant for it
            }
            tracked.insert(id, TrackedDevice { vendor_id, product_id, last_known_descriptor: descriptor.clone() });
            notify(&app, &settings, vendor_id, product_id, descriptor.clone(), "tauri-webusb://connect").await;
        }

        for id in removed {
            if let Some(dev) = tracked.remove(&id) {
                notify(&app, &settings, dev.vendor_id, dev.product_id, dev.last_known_descriptor, "tauri-webusb://disconnect").await;
            }
        }
    }
}

async fn snapshot() -> Result<Vec<(PhysicalDeviceId, u16, u16, DeviceDescriptor)>, ()> {
    // Deliberately reuses `bridge::candidates_for_chooser` with a
    // match-everything filter rather than a bespoke enumeration path: a
    // hotplug event's payload must be exactly the same shape `getDevices()`
    // would return for that device (`hardening::device_matches_any_usb_filter`
    // and the descriptor-building logic are the same code either way), and
    // reusing it means there is exactly one place in the crate that decides
    // what a `DeviceDescriptor` looks like once a device is a serious
    // candidate — see `bridge.rs`'s module doc comment on that split.
    let match_everything = [UsbDeviceFilter::default()];
    let descriptors = bridge::candidates_for_chooser(&match_everything, &[]).await.map_err(|_| ())?;
    // 🔍 Physical identity: see this module's doc comment on
    // `PhysicalDeviceId` — `bridge::candidates_for_chooser` doesn't currently
    // plumb bus/address through (it only needs vendor/product for filter
    // matching), so for now this uses `(vendorId, productId)` as a stand-in
    // identity. This is a real, documented simplification versus true
    // per-physical-device identity: two simultaneously-connected identical
    // devices will be indistinguishable to the hotplug diff (unplugging one
    // of the two will not reliably fire exactly one disconnect event tied
    // to the *specific* one removed). Both predecessors document the
    // analogous limitation for their own permission-grant model (grants are
    // also keyed by vendorId/productId, not a specific unit, absent a
    // serial number) — see `settings_logic.rs`'s doc comment. Extending
    // `bridge.rs` to plumb through a real bus/address (or serial-number-based)
    // identity is a natural, localized follow-up.
    Ok(descriptors.into_iter().map(|d| ((d.vendor_id as u32) << 16 | d.product_id as u32, d.vendor_id, d.product_id, d)).collect())
}

async fn notify<R: Runtime>(
    app: &AppHandle<R>,
    settings: &SettingsStore,
    vendor_id: u16,
    product_id: u16,
    descriptor: DeviceDescriptor,
    event_name: &str,
) {
    let origins = settings.read(|d| d.granted_origins_for_device(vendor_id, product_id)).await;
    if origins.is_empty() {
        return;
    }
    for webview in app.webview_windows().values() {
        let Ok(url) = webview.url() else { continue };
        let Some(webview_origin) = origin_of(&url) else { continue };
        if origins.contains(&webview_origin) {
            let _ = webview.emit(event_name, &descriptor);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_change_produces_no_added_or_removed() {
        let ids = vec![(1, 2)];
        let current = vec![((1, 2), 0x1234, 0x5678)];
        let (added, removed) = diff_snapshots(&ids, &current);
        assert!(added.is_empty());
        assert!(removed.is_empty());
    }

    #[test]
    fn new_device_is_reported_as_added() {
        let previous: Vec<PhysicalDeviceId> = vec![];
        let current = vec![((1, 2), 0x1234, 0x5678)];
        let (added, removed) = diff_snapshots(&previous, &current);
        assert_eq!(added, vec![((1, 2), 0x1234, 0x5678)]);
        assert!(removed.is_empty());
    }

    #[test]
    fn unplugged_device_is_reported_as_removed() {
        let previous = vec![(1, 2)];
        let current: Vec<((u32, u32), u16, u16)> = vec![];
        let (added, removed) = diff_snapshots(&previous, &current);
        assert!(added.is_empty());
        assert_eq!(removed, vec![(1, 2)]);
    }

    #[test]
    fn one_added_and_one_removed_in_the_same_tick() {
        let previous = vec![(1, 2)];
        let current = vec![((3, 4), 0xaaaa, 0xbbbb)];
        let (added, removed) = diff_snapshots(&previous, &current);
        assert_eq!(added, vec![((3, 4), 0xaaaa, 0xbbbb)]);
        assert_eq!(removed, vec![(1, 2)]);
    }

    #[test]
    fn unrelated_still_connected_devices_are_untouched() {
        let previous = vec![(1, 2), (5, 6)];
        let current = vec![((1, 2), 0x1111, 0x2222), ((5, 6), 0x3333, 0x4444), ((7, 8), 0x5555, 0x6666)];
        let (added, removed) = diff_snapshots(&previous, &current);
        assert_eq!(added, vec![((7, 8), 0x5555, 0x6666)]);
        assert!(removed.is_empty());
    }

    #[test]
    fn empty_to_empty_is_a_no_op() {
        let (added, removed) = diff_snapshots(&[], &[]);
        assert!(added.is_empty());
        assert!(removed.is_empty());
    }

    #[test]
    fn everything_disconnecting_at_once_reports_all_of_them() {
        let previous = vec![(1, 1), (2, 2), (3, 3)];
        let (added, removed) = diff_snapshots(&previous, &[]);
        assert!(added.is_empty());
        assert_eq!(removed.len(), 3);
    }
}
