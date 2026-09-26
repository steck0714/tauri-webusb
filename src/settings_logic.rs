//! settings_logic.rs
//! ==================
//! The pure bookkeeping logic behind persistent per-origin device grants and
//! the "known devices" history, factored out from actual file I/O so it can
//! be unit tested without a filesystem or a Tauri `AppHandle`. The real
//! plugin's `settings_store.rs` wraps `SettingsData` from this module in a
//! `tokio::sync::Mutex`, loads/saves it as JSON at
//! `app.path().app_config_dir()?.join("settings.json")`, and persists after
//! every mutating call — exactly the role `settings_store.py`'s
//! `SettingsStore` class played on top of a hand-rolled JSON file (both
//! predecessors: `pyside6-webusb` used `QSettings`; `fox-webusb` switched to
//! a plain JSON file directly, since `QSettings` is a Qt facility with no
//! equivalent to lean on outside Qt — the OS-appropriate directory is instead
//! whatever `app.path()` resolves to. tauri-webusb follows `fox-webusb`'s
//! plain-JSON-file choice for the same reason).
//!
//! `SettingsData` is deliberately the *same* shape returned to a trusted
//! management UI by the `list_granted_origins`/`list_known_devices` commands
//! (see `commands.rs`) — there is no separate "wire" representation, the
//! persisted file and the command response are the same struct.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GrantedDevice {
    pub vendor_id: u16,
    pub product_id: u16,
    /// RFC 3339 / ISO 8601 UTC timestamp string (e.g.
    /// `"2026-09-04T01:22:00Z"`), matching `serde_json`'s natural rendering
    /// of `time::OffsetDateTime`/`chrono::DateTime<Utc>` and staying
    /// trivially human-readable for anyone inspecting the settings file by
    /// hand. The real plugin (`settings_store.rs`) is responsible for
    /// producing this value at call time; everything in *this* module takes
    /// it as a plain, already-formatted `String` so none of the logic below
    /// needs a clock or a timezone dependency to be testable.
    pub granted_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KnownDevice {
    pub vendor_id: u16,
    pub product_id: u16,
    pub product_name: Option<String>,
    pub manufacturer_name: Option<String>,
    pub connect_count: u64,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SettingsData {
    #[serde(default)]
    pub granted_origins: HashMap<String, Vec<GrantedDevice>>,
    #[serde(default)]
    pub known_devices: Vec<KnownDevice>,
}

impl SettingsData {
    pub fn new() -> Self {
        Self::default()
    }

    // ---- granted origins ----

    pub fn is_origin_granted(&self, origin: &str, vendor_id: u16, product_id: u16) -> bool {
        self.granted_origins
            .get(origin)
            .is_some_and(|grants| grants.iter().any(|g| g.vendor_id == vendor_id && g.product_id == product_id))
    }

    /// `(vendorId, productId)` pairs this `origin` currently holds a grant
    /// for. Used by `bridge.rs` to filter `getDevices()`'s result down to
    /// only devices the origin was previously granted (`getDevices()` never
    /// itself grants anything new — only `requestDevice()`'s chooser does).
    pub fn granted_pairs_for_origin(&self, origin: &str) -> Vec<(u16, u16)> {
        self.granted_origins
            .get(origin)
            .map(|grants| grants.iter().map(|g| (g.vendor_id, g.product_id)).collect())
            .unwrap_or_default()
    }

    /// Idempotent: granting a pair the origin already holds is a no-op (does
    /// not duplicate the entry or reset `grantedAt`).
    pub fn grant_origin(&mut self, origin: &str, vendor_id: u16, product_id: u16, now: &str) {
        let grants = self.granted_origins.entry(origin.to_string()).or_default();
        if !grants.iter().any(|g| g.vendor_id == vendor_id && g.product_id == product_id) {
            grants.push(GrantedDevice { vendor_id, product_id, granted_at: now.to_string() });
        }
    }

    /// Returns whether a grant was actually removed (so callers/commands can
    /// tell "revoked" from "there was nothing to revoke" without a second
    /// lookup).
    pub fn revoke_origin_grant(&mut self, origin: &str, vendor_id: u16, product_id: u16) -> bool {
        let Some(grants) = self.granted_origins.get_mut(origin) else { return false };
        let before = grants.len();
        grants.retain(|g| !(g.vendor_id == vendor_id && g.product_id == product_id));
        let removed = grants.len() != before;
        if grants.is_empty() {
            self.granted_origins.remove(origin);
        }
        removed
    }

    /// Removes every grant for `origin`. Returns how many were removed.
    /// Mirrors `revokeAllForOrigin`, used both by the trusted management UI
    /// and, per both predecessors' design, automatically whenever an
    /// origin's last tab/window actually closes (`originClosed` /
    /// `on_frame_removed` — see `README.md`'s "Known limitations" for why
    /// tauri-webusb does *not* replicate that auto-revoke-on-close behavior
    /// in v0.0.0).
    pub fn revoke_all_for_origin(&mut self, origin: &str) -> usize {
        match self.granted_origins.remove(origin) {
            Some(grants) => grants.len(),
            None => 0,
        }
    }

    /// The inverse of `granted_pairs_for_origin`: every origin currently
    /// holding a grant for this specific `(vendorId, productId)` pair. Used
    /// by the hotplug watcher (`hotplug.rs`) to decide which webviews to
    /// notify when a matching device connects or disconnects — a
    /// `USBConnectionEvent` must never reach an origin that was never
    /// granted this device, even though the event itself carries no
    /// sensitive data beyond what `getDevices()` would already reveal to
    /// that same origin.
    pub fn granted_origins_for_device(&self, vendor_id: u16, product_id: u16) -> Vec<String> {
        self.granted_origins
            .iter()
            .filter(|(_, grants)| grants.iter().any(|g| g.vendor_id == vendor_id && g.product_id == product_id))
            .map(|(origin, _)| origin.clone())
            .collect()
    }

    // ---- known devices (history, purely informational — never itself a permission grant) ----

    /// Upserts by `(vendorId, productId)`: increments `connectCount` and
    /// refreshes `lastSeenAt`/name fields if already known, otherwise
    /// inserts a fresh entry with `connectCount: 1`. Called once per
    /// successful `open()`, from every origin — this list intentionally
    /// carries no origin information at all (a device's connection history
    /// is not itself sensitive the way "which origins can access it" is),
    /// matching both predecessors.
    pub fn record_device_usage(
        &mut self,
        vendor_id: u16,
        product_id: u16,
        product_name: Option<String>,
        manufacturer_name: Option<String>,
        now: &str,
    ) {
        if let Some(existing) = self
            .known_devices
            .iter_mut()
            .find(|d| d.vendor_id == vendor_id && d.product_id == product_id)
        {
            existing.connect_count += 1;
            existing.last_seen_at = now.to_string();
            // A device can legitimately change its reported string
            // descriptors between plugs (a firmware update, or simply a
            // device that reports differently pre-/post-configuration) —
            // refresh rather than keep whatever we first saw, but only when
            // the new read actually produced something (don't clobber a
            // known name with `None` just because this particular read
            // failed).
            if product_name.is_some() {
                existing.product_name = product_name;
            }
            if manufacturer_name.is_some() {
                existing.manufacturer_name = manufacturer_name;
            }
        } else {
            self.known_devices.push(KnownDevice {
                vendor_id, product_id, product_name, manufacturer_name,
                connect_count: 1,
                last_seen_at: now.to_string(),
            });
        }
    }

    pub fn forget_known_device(&mut self, vendor_id: u16, product_id: u16) -> bool {
        let before = self.known_devices.len();
        self.known_devices.retain(|d| !(d.vendor_id == vendor_id && d.product_id == product_id));
        self.known_devices.len() != before
    }

    pub fn forget_all_known_devices(&mut self) -> usize {
        let n = self.known_devices.len();
        self.known_devices.clear();
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-09-04T00:00:00Z";
    const LATER: &str = "2026-09-04T01:00:00Z";

    #[test]
    fn fresh_settings_grant_nothing_and_know_no_devices() {
        let s = SettingsData::new();
        assert!(!s.is_origin_granted("https://example.com", 1, 2));
        assert!(s.granted_pairs_for_origin("https://example.com").is_empty());
        assert!(s.known_devices.is_empty());
    }

    #[test]
    fn grant_then_is_granted() {
        let mut s = SettingsData::new();
        s.grant_origin("https://example.com", 0x1234, 0x5678, NOW);
        assert!(s.is_origin_granted("https://example.com", 0x1234, 0x5678));
    }

    #[test]
    fn grant_is_scoped_to_the_exact_origin() {
        let mut s = SettingsData::new();
        s.grant_origin("https://a.example.com", 1, 2, NOW);
        assert!(!s.is_origin_granted("https://b.example.com", 1, 2));
        assert!(!s.is_origin_granted("http://a.example.com", 1, 2)); // different scheme = different origin
    }

    #[test]
    fn grant_is_scoped_to_the_exact_device_pair() {
        let mut s = SettingsData::new();
        s.grant_origin("https://example.com", 1, 2, NOW);
        assert!(!s.is_origin_granted("https://example.com", 1, 999));
        assert!(!s.is_origin_granted("https://example.com", 999, 2));
    }

    #[test]
    fn granting_the_same_pair_twice_does_not_duplicate() {
        let mut s = SettingsData::new();
        s.grant_origin("https://example.com", 1, 2, NOW);
        s.grant_origin("https://example.com", 1, 2, LATER);
        assert_eq!(s.granted_pairs_for_origin("https://example.com").len(), 1);
        // and keeps the original grantedAt, doesn't refresh it:
        assert_eq!(s.granted_origins["https://example.com"][0].granted_at, NOW);
    }

    #[test]
    fn granted_pairs_for_origin_reflects_multiple_grants() {
        let mut s = SettingsData::new();
        s.grant_origin("https://example.com", 1, 2, NOW);
        s.grant_origin("https://example.com", 3, 4, NOW);
        let mut pairs = s.granted_pairs_for_origin("https://example.com");
        pairs.sort();
        assert_eq!(pairs, vec![(1, 2), (3, 4)]);
    }

    #[test]
    fn revoke_single_grant_returns_true_and_removes_only_that_pair() {
        let mut s = SettingsData::new();
        s.grant_origin("https://example.com", 1, 2, NOW);
        s.grant_origin("https://example.com", 3, 4, NOW);
        assert!(s.revoke_origin_grant("https://example.com", 1, 2));
        assert!(!s.is_origin_granted("https://example.com", 1, 2));
        assert!(s.is_origin_granted("https://example.com", 3, 4));
    }

    #[test]
    fn revoke_nonexistent_grant_returns_false() {
        let mut s = SettingsData::new();
        assert!(!s.revoke_origin_grant("https://example.com", 1, 2));
        s.grant_origin("https://example.com", 1, 2, NOW);
        assert!(!s.revoke_origin_grant("https://example.com", 9, 9));
    }

    #[test]
    fn revoking_last_grant_for_an_origin_removes_the_origin_entry_entirely() {
        let mut s = SettingsData::new();
        s.grant_origin("https://example.com", 1, 2, NOW);
        s.revoke_origin_grant("https://example.com", 1, 2);
        assert!(!s.granted_origins.contains_key("https://example.com"));
    }

    #[test]
    fn revoke_all_for_origin_clears_everything_for_that_origin_only() {
        let mut s = SettingsData::new();
        s.grant_origin("https://a.example.com", 1, 2, NOW);
        s.grant_origin("https://a.example.com", 3, 4, NOW);
        s.grant_origin("https://b.example.com", 5, 6, NOW);
        assert_eq!(s.revoke_all_for_origin("https://a.example.com"), 2);
        assert!(s.granted_pairs_for_origin("https://a.example.com").is_empty());
        assert!(s.is_origin_granted("https://b.example.com", 5, 6));
    }

    #[test]
    fn revoke_all_for_unknown_origin_returns_zero() {
        let mut s = SettingsData::new();
        assert_eq!(s.revoke_all_for_origin("https://nope.example.com"), 0);
    }

    #[test]
    fn record_device_usage_inserts_new_device_with_count_one() {
        let mut s = SettingsData::new();
        s.record_device_usage(1, 2, Some("Widget".into()), Some("Acme".into()), NOW);
        assert_eq!(s.known_devices.len(), 1);
        assert_eq!(s.known_devices[0].connect_count, 1);
        assert_eq!(s.known_devices[0].last_seen_at, NOW);
    }

    #[test]
    fn record_device_usage_increments_existing_and_refreshes_timestamp() {
        let mut s = SettingsData::new();
        s.record_device_usage(1, 2, Some("Widget".into()), None, NOW);
        s.record_device_usage(1, 2, Some("Widget".into()), None, LATER);
        assert_eq!(s.known_devices.len(), 1);
        assert_eq!(s.known_devices[0].connect_count, 2);
        assert_eq!(s.known_devices[0].last_seen_at, LATER);
    }

    #[test]
    fn record_device_usage_does_not_clobber_known_name_with_a_failed_read() {
        let mut s = SettingsData::new();
        s.record_device_usage(1, 2, Some("Widget".into()), Some("Acme".into()), NOW);
        s.record_device_usage(1, 2, None, None, LATER); // second read failed to get strings
        assert_eq!(s.known_devices[0].product_name.as_deref(), Some("Widget"));
        assert_eq!(s.known_devices[0].manufacturer_name.as_deref(), Some("Acme"));
        assert_eq!(s.known_devices[0].connect_count, 2); // still counted, though
    }

    #[test]
    fn granted_origins_for_device_finds_every_origin_holding_that_pair() {
        let mut s = SettingsData::new();
        s.grant_origin("https://a.example.com", 1, 2, NOW);
        s.grant_origin("https://b.example.com", 1, 2, NOW);
        s.grant_origin("https://c.example.com", 9, 9, NOW); // different device
        let mut origins = s.granted_origins_for_device(1, 2);
        origins.sort();
        assert_eq!(origins, vec!["https://a.example.com", "https://b.example.com"]);
    }

    #[test]
    fn granted_origins_for_device_empty_when_nobody_holds_it() {
        let s = SettingsData::new();
        assert!(s.granted_origins_for_device(1, 2).is_empty());
    }

    #[test]
    fn forget_known_device_removes_only_that_pair() {
        let mut s = SettingsData::new();
        s.record_device_usage(1, 2, None, None, NOW);
        s.record_device_usage(3, 4, None, None, NOW);
        assert!(s.forget_known_device(1, 2));
        assert_eq!(s.known_devices.len(), 1);
        assert_eq!(s.known_devices[0].vendor_id, 3);
    }

    #[test]
    fn forget_unknown_device_returns_false() {
        let mut s = SettingsData::new();
        assert!(!s.forget_known_device(1, 2));
    }

    #[test]
    fn forget_all_known_devices_clears_everything_and_returns_count() {
        let mut s = SettingsData::new();
        s.record_device_usage(1, 2, None, None, NOW);
        s.record_device_usage(3, 4, None, None, NOW);
        assert_eq!(s.forget_all_known_devices(), 2);
        assert!(s.known_devices.is_empty());
    }

    #[test]
    fn forgetting_a_known_device_does_not_touch_granted_origins() {
        // Known-devices history and origin grants are deliberately
        // independent axes — forgetting the history entry is not the same
        // action as revoking access, and must not silently do both.
        let mut s = SettingsData::new();
        s.grant_origin("https://example.com", 1, 2, NOW);
        s.record_device_usage(1, 2, None, None, NOW);
        s.forget_known_device(1, 2);
        assert!(s.is_origin_granted("https://example.com", 1, 2));
    }

    #[test]
    fn settings_data_round_trips_through_json() {
        let mut s = SettingsData::new();
        s.grant_origin("https://example.com", 1, 2, NOW);
        s.record_device_usage(1, 2, Some("Widget".into()), None, NOW);
        let json = serde_json::to_string(&s).unwrap();
        let back: SettingsData = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn empty_json_object_deserializes_to_fresh_settings() {
        // First-run case: settings.json doesn't exist yet / is `{}`.
        let s: SettingsData = serde_json::from_str("{}").unwrap();
        assert_eq!(s, SettingsData::new());
    }

    #[test]
    fn wire_shape_uses_camel_case() {
        let mut s = SettingsData::new();
        s.grant_origin("https://example.com", 0x1234, 0x5678, NOW);
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(
            json["grantedOrigins"]["https://example.com"][0]["vendorId"],
            0x1234
        );
        assert_eq!(
            json["grantedOrigins"]["https://example.com"][0]["grantedAt"],
            NOW
        );
    }
}
