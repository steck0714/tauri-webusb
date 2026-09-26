//! state.rs
//! ========
//! The single struct this plugin hands to `app.manage(...)` in `lib.rs`.
//! Every command (`commands.rs`) reaches the rest of the plugin only through
//! `tauri::State<WebUsbState>` — nothing here is itself global/`static`
//! mutable state, which is what lets an app embed tauri-webusb without it
//! reaching outside the one `AppHandle` it was set up with.

use crate::bridge::SessionRegistry;
use crate::settings_store::SettingsStore;
use crate::chooser::ChooserRegistry;
use std::sync::Arc;

pub struct WebUsbState {
    /// `Arc`, not an owned `SettingsStore`: the long-lived hotplug task
    /// spawned in `lib.rs`'s `setup` hook needs its own handle to the exact
    /// same store (to check grants when deciding whether to fire a
    /// connect/disconnect event), independent of whatever `tauri::State`
    /// borrow lifetime any particular command invocation has. Every method
    /// on `SettingsStore` takes `&self`, so call sites reading through
    /// `state.settings.foo()` work identically whether `settings` is a
    /// plain value or (as here) an `Arc` — deref coercion handles it.
    pub settings: Arc<SettingsStore>,
    pub sessions: SessionRegistry,
    pub chooser: ChooserRegistry,
}

impl WebUsbState {
    pub fn new(settings: Arc<SettingsStore>) -> Self {
        Self { settings, sessions: SessionRegistry::new(), chooser: ChooserRegistry::new() }
    }
}
