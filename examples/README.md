# Examples

These are plain HTML/JS pages, not a full runnable Tauri project — drop one
in as the `frontendDist` of a minimal Tauri v2 app with this plugin
installed and capability-granted (see the main `README.md`'s "Installation"
section) to try it.

Minimal `src-tauri/src/main.rs` to run either of these against:

```rust
fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_webusb::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

- **`quickstart.html`** — the smallest end-to-end example: request a device,
  open it, claim an interface, read from an IN endpoint. Start here.
- **`device-info.html`** — enumerates every device the page currently holds
  a grant for (`getDevices()`, no chooser) and renders its full descriptor
  tree (configurations → interfaces → alternates → endpoints), including
  which interfaces are protected. Useful for sanity-checking that a real
  device's descriptors are coming through the plugin correctly, and for
  seeing `onconnect`/`ondisconnect` fire live.

Both pages assume they're the app's own bundled frontend (loaded from
tauri://localhost or https://tauri.localhost — see `origin.rs`'s module doc
comment on why that matters for `window.isSecureContext`), so
`navigator.usb` is expected to already exist with no explicit install step.
