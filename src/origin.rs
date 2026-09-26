//! origin.rs
//! =========
//! Turns a webview's *current URL* into the `scheme://host[:port]` origin
//! string that every per-origin permission grant in `settings_store.rs` is
//! keyed by. This is the single most important architectural difference from
//! both predecessors, so it's worth spelling out in full here.
//!
//! ## How each predecessor established a trustworthy origin
//!
//! - `pyside6-webusb`: QtWebEngine gives no built-in "which frame/origin is
//!   this JS call coming from" for a `QWebChannel` `@Slot` call, so it built
//!   its own: `frame_origin.py`'s `FrameOriginTracker`, injecting a random,
//!   unguessable per-frame token via `QWebEngineScript` at
//!   `DocumentCreation` time (before any page JS runs) and requiring every
//!   bridge call to present it. The origin itself came from a
//!   `QWebEngineUrlRequestInterceptor` recording each frame's real navigated
//!   URL, keyed by that same token.
//! - `fox-webusb`: Firefox's WebExtensions API hands `background.js` a
//!   `sender.url` on every `runtime.onMessage`/port message — a value the
//!   browser itself verified from the actual sending frame, not something
//!   page JS can spoof by lying in the message payload. No token scheme
//!   needed.
//!
//! ## tauri-webusb
//!
//! Tauri has a direct equivalent to `sender.url`, and it comes from Tauri's
//! own core, not from anything this plugin builds: a command handler can
//! take `webview: tauri::Webview<R>` as a parameter (Tauri's dependency
//! injection recognizes the type and supplies it automatically — see
//! `commands.rs`), and `webview.url()` returns that specific webview's
//! actual, currently-loaded URL as tracked by the webview engine itself.
//! Page JS has no way to influence what this returns short of an actual
//! navigation (which would mean the origin genuinely did change). It is, in
//! other words, exactly `sender.url` — so, like `fox-webusb`, tauri-webusb
//! needs no frame-token scheme at all: `origin_of(&webview.url()?)` at the
//! top of a command handler is the whole mechanism.
//!
//! This also happens to be the *same* value Tauri's own permission/capability
//! system (the `remote.urls` scoping in `capabilities/*.json`) checks
//! against to decide whether a webview may call a command at all, before
//! this plugin's command handler even runs — see `README.md`'s "Trust
//! model" section for how the two layers (Tauri's ACL, and this module's
//! per-origin device grants) compose.

use url::Url;

/// `scheme://host[:port]`, with the port omitted when it's the scheme's
/// default (80 for `http`, 443 for `https`) — matching how browsers define
/// "origin" and how both predecessors computed it
/// (`frame_origin.py::url_to_origin`, `background.js`'s `originFromSender`).
///
/// Returns `None` for URLs with no meaningful origin to grant permissions
/// against: no host (e.g. `about:blank`), or a `data:`/`blob:` URL (opaque
/// origin — spec-correct to treat as unable to be granted persistent
/// permissions, since a fresh `data:` navigation is indistinguishable from
/// any other for grant purposes). Callers should treat `None` as "refuse to
/// proceed with `SecurityError`", not as an empty-string fallback — see
/// `bridge.rs`.
pub fn origin_of(url: &Url) -> Option<String> {
    let scheme = url.scheme();
    if scheme == "data" || scheme == "blob" || scheme == "about" {
        return None;
    }
    let host = url.host_str()?;
    let default_port = match scheme {
        "http" => Some(80u16),
        "https" => Some(443u16),
        _ => None,
    };
    match url.port() {
        Some(p) if Some(p) != default_port => Some(format!("{scheme}://{host}:{p}")),
        _ => Some(format!("{scheme}://{host}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(s: &str) -> Option<String> {
        origin_of(&Url::parse(s).unwrap())
    }

    #[test]
    fn https_default_port_omitted() {
        assert_eq!(origin("https://example.com/path?x=1"), Some("https://example.com".into()));
    }

    #[test]
    fn http_default_port_omitted() {
        assert_eq!(origin("http://example.com/"), Some("http://example.com".into()));
    }

    #[test]
    fn https_explicit_default_port_still_omitted() {
        assert_eq!(origin("https://example.com:443/"), Some("https://example.com".into()));
    }

    #[test]
    fn non_default_port_is_kept() {
        assert_eq!(origin("https://example.com:8443/"), Some("https://example.com:8443".into()));
    }

    #[test]
    fn http_on_nonstandard_port_is_kept() {
        assert_eq!(origin("http://localhost:1420/"), Some("http://localhost:1420".into()));
    }

    #[test]
    fn path_query_and_fragment_are_irrelevant_to_origin() {
        assert_eq!(
            origin("https://example.com/a/b?c=d#frag"),
            origin("https://example.com/x")
        );
    }

    #[test]
    fn tauri_windows_localhost_scheme_is_treated_as_https() {
        // Tauri serves the app's own bundled frontend as
        // `https://tauri.localhost/...` on Windows.
        assert_eq!(origin("https://tauri.localhost/index.html"), Some("https://tauri.localhost".into()));
    }

    #[test]
    fn custom_tauri_scheme_on_macos_linux_keeps_its_own_scheme() {
        // ...and as a custom `tauri://` scheme on macOS/Linux.
        assert_eq!(origin("tauri://localhost/index.html"), Some("tauri://localhost".into()));
    }

    #[test]
    fn data_url_has_no_grantable_origin() {
        assert_eq!(origin("data:text/html,<h1>hi</h1>"), None);
    }

    #[test]
    fn different_hosts_are_different_origins() {
        assert_ne!(origin("https://a.example.com/"), origin("https://b.example.com/"));
    }

    #[test]
    fn different_schemes_are_different_origins_even_with_same_host() {
        assert_ne!(origin("http://example.com/"), origin("https://example.com/"));
    }
}
