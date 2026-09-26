//! settings_store.rs
//! ==================
//! Persistent storage for per-origin device grants and the "known devices"
//! history. The bookkeeping rules themselves (`SettingsData` and its
//! methods) are pure and unit-tested with zero I/O — see the doc comment on
//! that struct below. This file adds the two things that make it durable
//! across app restarts: a location to put the file, and a way to write it
//! that can't leave a half-written file behind after a crash or power loss.
//!
//! ## Where the file lives
//!
//! `pyside6-webusb` used Qt's `QSettings` (which itself picks an
//! OS-appropriate location — the registry on Windows, a plist on macOS, an
//! INI-style file on Linux). `fox-webusb`, with no Qt available, switched to
//! a single JSON file directly under the OS's own "user config directory"
//! convention. tauri-webusb follows `fox-webusb`'s choice for the same
//! reason (no Qt), using Tauri's own equivalent resolver:
//! `app.path().app_config_dir()`, which already encodes the right
//! platform-specific base path (e.g. `~/.config/<bundle-id>` on Linux,
//! `~/Library/Application Support/<bundle-id>` on macOS,
//! `%APPDATA%\<bundle-id>` on Windows) using the *consuming app's* bundle
//! identifier — so two different Tauri apps that both depend on
//! tauri-webusb naturally get separate settings files, never sharing grants
//! with each other. The file itself is `tauri-webusb-settings.json` inside
//! that directory.
//!
//! ## Atomic writes
//!
//! Every mutating call rewrites the whole file (it's small — origin grants
//! and a device history, not device data itself) via write-to-temp-file +
//! rename, exactly like both predecessors' `settings_store.py`: `rename()`
//! within the same directory is atomic on every platform this targets, so a
//! process that dies mid-write (crash, forced quit, power loss) leaves
//! either the old complete file or the new complete file, never a truncated
//! one that would fail to parse on the next launch.

use crate::settings_logic::SettingsData;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager, Runtime};
use tokio::sync::Mutex;

const SETTINGS_FILE_NAME: &str = "tauri-webusb-settings.json";

pub struct SettingsStore {
    path: PathBuf,
    data: Mutex<SettingsData>,
}

impl SettingsStore {
    /// Resolves the settings file path via the app's config directory and
    /// loads whatever is there (or starts fresh — see `load_or_default`).
    /// Called once, from `lib.rs`'s `setup` hook, and stored in Tauri's
    /// managed state (`app.manage(...)`) for every command to share.
    pub fn init<R: Runtime>(app: &AppHandle<R>) -> Result<Self, String> {
        let dir = app
            .path()
            .app_config_dir()
            .map_err(|e| format!("could not resolve app config directory: {e}"))?;
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("could not create app config directory {}: {e}", dir.display()))?;
        let path = dir.join(SETTINGS_FILE_NAME);
        let data = load_or_default(&path)?;
        Ok(Self { path, data: Mutex::new(data) })
    }

    /// Runs `f` against the current settings and persists the result if `f`
    /// reports it made a change. `f` returns `(R, changed)`; when
    /// `changed` is `false` (e.g. `revoke_origin_grant` on a pair that was
    /// never granted) this skips the disk write entirely — every mutating
    /// command already computes whether it actually changed anything as
    /// part of doing its job, so this avoids a redundant write-and-fsync on
    /// what both predecessors called a "no-op grant/revoke" (repeatedly
    /// granting the same already-granted pair, for instance).
    pub async fn mutate<T>(&self, f: impl FnOnce(&mut SettingsData) -> (T, bool)) -> Result<T, String> {
        let mut guard = self.data.lock().await;
        let (result, changed) = f(&mut guard);
        if changed {
            persist(&self.path, &guard)?;
        }
        Ok(result)
    }

    /// Read-only access, for the commands that only ever look (e.g.
    /// `is_origin_granted` inside `getDevices()`/transfer-permission checks,
    /// `list_granted_origins`/`list_known_devices` for the trusted
    /// management UI).
    pub async fn read<T>(&self, f: impl FnOnce(&SettingsData) -> T) -> T {
        let guard = self.data.lock().await;
        f(&guard)
    }
}

fn load_or_default(path: &Path) -> Result<SettingsData, String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(serde_json::from_str(&contents).unwrap_or_else(|e| {
            // 🛡️ A corrupt/hand-edited settings file should not brick the
            // plugin on every launch — but silently discarding it would
            // also silently discard every granted origin, which is a
            // security-relevant, surprising thing to do quietly. Loudly
            // logging and falling back to fresh (empty) settings mirrors
            // `settings_store.py`'s own choice here: fail open to "nothing
            // is granted" (safe default) rather than fail closed to
            // "plugin doesn't start at all" (denial of service against the
            // whole app over one bad file).
            //
            // (This is `unwrap_or_else`, not `map_err` — an earlier draft
            // of this function used `map_err` here, which type-checks to
            // nonsense once you look closely: it would turn a
            // `Result<SettingsData, serde_json::Error>` into
            // `Result<SettingsData, SettingsData>`, an error value that can
            // never actually be constructed as an *error* by the `Err(e)`
            // arm two lines below, since that arm's `e` is a
            // `std::io::Error`, not a `SettingsData`. Caught by actually
            // compiling this exact function — see
            // `verify/src/settings_store_persistence_check.rs`, extracted
            // specifically because this file's `tauri` dependency otherwise
            // blocked compiling it at all in this project's sandbox; see
            // README.md's "Development environment".)
            eprintln!(
                "[tauri-webusb] {} could not be parsed as JSON ({e}); starting with empty \
                 settings (no origins granted, no device history) rather than failing to start. \
                 The unreadable file has been left in place at that path for inspection.",
                path.display()
            );
            SettingsData::new()
        })),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SettingsData::new()),
        Err(e) => Err(format!("could not read {}: {e}", path.display())),
    }
}

fn persist(path: &Path, data: &SettingsData) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| format!("could not serialize settings: {e}"))?;
    let dir = path.parent().ok_or_else(|| "settings path has no parent directory".to_string())?;
    // Temp file in the *same* directory as the real target, not
    // `std::env::temp_dir()` — `rename()` is only atomic within a single
    // filesystem/volume, and a system temp directory is not guaranteed to
    // be on the same one as the app config directory.
    let tmp_path = dir.join(format!("{SETTINGS_FILE_NAME}.tmp-{}", std::process::id()));
    std::fs::write(&tmp_path, json.as_bytes())
        .map_err(|e| format!("could not write temp settings file {}: {e}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        format!("could not atomically replace settings file {}: {e}", path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings_logic::SettingsData;

    // `SettingsStore::init` itself needs a live `AppHandle`, which requires
    // a running Tauri app and so isn't exercised here (see the crate's
    // `README.md` "What's tested where" section) — but the file-level
    // load/persist helpers only need a `Path`, so those get real,
    // filesystem-backed tests.

    #[test]
    fn load_or_default_returns_fresh_settings_for_a_missing_file() {
        let dir = std::env::temp_dir().join(format!("tauri-webusb-test-{}", std::process::id()));
        let path = dir.join("does-not-exist.json");
        assert_eq!(load_or_default(&path).unwrap(), SettingsData::new());
    }

    #[test]
    fn persist_then_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("tauri-webusb-test-roundtrip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(SETTINGS_FILE_NAME);

        let mut data = SettingsData::new();
        data.grant_origin("https://example.com", 0x1234, 0x5678, "2026-09-04T00:00:00Z");
        persist(&path, &data).unwrap();

        let loaded = load_or_default(&path).unwrap();
        assert_eq!(loaded, data);

        // no leftover temp file:
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "temp file was not cleaned up: {leftovers:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_default_falls_back_to_fresh_settings_on_corrupt_json() {
        let dir = std::env::temp_dir().join(format!("tauri-webusb-test-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(SETTINGS_FILE_NAME);
        std::fs::write(&path, b"{ not valid json").unwrap();

        let loaded = load_or_default(&path).unwrap();
        assert_eq!(loaded, SettingsData::new());
        assert!(path.exists(), "the unreadable file itself should be left in place, not deleted");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_overwrites_a_previous_version_cleanly() {
        let dir = std::env::temp_dir().join(format!("tauri-webusb-test-overwrite-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(SETTINGS_FILE_NAME);

        let mut first = SettingsData::new();
        first.grant_origin("https://a.example.com", 1, 2, "2026-01-01T00:00:00Z");
        persist(&path, &first).unwrap();

        let mut second = SettingsData::new();
        second.grant_origin("https://b.example.com", 3, 4, "2026-01-02T00:00:00Z");
        persist(&path, &second).unwrap();

        let loaded = load_or_default(&path).unwrap();
        assert_eq!(loaded, second);
        assert!(!loaded.is_origin_granted("https://a.example.com", 1, 2), "stale data from the first write leaked through");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_rejects_a_path_with_no_parent_directory() {
        let data = SettingsData::new();
        let result = persist(Path::new("/"), &data);
        assert!(result.is_err() || Path::new("/").parent().is_none());
    }
}
