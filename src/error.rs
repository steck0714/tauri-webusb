//! error.rs
//! ========
//! Single place that defines the `"XxxError: message"` string convention this
//! plugin uses to tell the guest-js polyfill which `DOMException` name to
//! throw. Mirrors `errors.py` in both `fox-webusb` and `pyside6-webusb`.
//!
//! ## Provenance of the exact prefix set
//!
//! `fox-webusb` v0.0.0/v0.0.0a0 recognizes five prefixes: `SecurityError`,
//! `InvalidStateError`, `NotFoundError`, `InvalidAccessError`, `IndexSizeError`.
//! `pyside6-webusb` v0.0.4b2 recognizes six: the same five plus `DataError`,
//! added specifically because real Chrome (Blink's `usb_device.cc`) uses
//! `DataError` — not `IndexSizeError` — for "transfer size exceeds the
//! implementation's limit" and "isochronous data length does not match the
//! packetLengths total". `fox-webusb` was ported from the *older*
//! pyside6-webusb v0.0.4b0, predating that distinction, so it still maps both
//! of those cases to `IndexSizeError`.
//!
//! Cross-referencing both projects turned up one more thing neither had
//! fully consistently: pyside6-webusb v0.0.4b2's own `bridge.py` returns a
//! hand-written `"NotSupportedError: ..."` string for the
//! isochronous-transfers-unavailable case (see its `_iso_backend_or_error`),
//! but its `errors.py` has no `not_supported_error()` helper for it, and —
//! more importantly — `polyfill.py`'s `KNOWN_ERROR_PREFIXES` list does *not*
//! include `"NotSupportedError:"` even after the v0.0.4b2 pass that
//! deliberately audited and expanded that exact list against everything
//! `errors.py` can produce. The result: that specific rejection actually
//! surfaces to the page as `DOMException` with `.name === "NetworkError"`
//! (the dispatcher's default) even though the message text says
//! "NotSupportedError". `NotSupportedError` is itself a standard DOMException
//! name (used across the web platform for "this operation/feature is not
//! supported in this configuration"), and it is exactly what this plugin
//! needs for its own isochronous-transfers-not-implemented case (see
//! `bridge.rs`), so tauri-webusb adds it as a first-class, properly-recognized
//! member of the taxonomy rather than reproducing the gap.
//!
//! tauri-webusb's taxonomy is therefore the union of both predecessors' fixes:
//! `SecurityError`, `InvalidStateError`, `NotFoundError`, `InvalidAccessError`,
//! `IndexSizeError`, `DataError`, `NotSupportedError` — seven prefixes, all of
//! which the guest-js side recognizes (see `guest-js/src/polyfill.ts`,
//! `KNOWN_ERROR_PREFIXES`).

use std::fmt;

/// The DOMException name a failure should surface as on the page side.
///
/// Every command handler in this plugin returns `Result<T, WebUsbError>`.
/// `WebUsbError`'s `Display` impl produces the exact `"Name: message"` string
/// the guest-js `throwFromResult()`-equivalent parses — the wire format is a
/// plain string (inside a JSON error field), not a structured object, so that
/// it round-trips identically however the command's `Result::Err` ends up
/// serialized by Tauri's IPC layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Protected-interface-class / blocklisted-device / non-`requestDevice()`-mediated
    /// state-changing control transfer rejections, and anything else the real
    /// WebUSB security model rejects outright.
    Security,
    /// "This operation can't be performed right now" — no configuration
    /// selected yet, interface not claimed, a chooser already open, a handle
    /// currently busy with another operation, etc.
    InvalidState,
    /// The referenced interface/endpoint/device/handle doesn't exist, or the
    /// user dismissed the chooser without selecting anything.
    NotFound,
    /// The target exists but is the wrong kind of thing for this operation
    /// (e.g. an isochronous transfer aimed at a bulk endpoint).
    InvalidAccess,
    /// A numeric argument is out of the range this call accepts (endpoint
    /// numbers, control-transfer `length`).
    IndexSize,
    /// The data itself — its size or shape — is the problem: exceeds this
    /// implementation's hard transfer-size ceiling, or an
    /// `isochronousTransferOut` payload whose length doesn't match the sum of
    /// `packetLengths`. Matches real Blink's choice of `DataError` for both
    /// (confirmed against `usb_device.cc` by pyside6-webusb v0.0.4b2; see the
    /// module doc comment above).
    DataError,
    /// The operation is recognized and its arguments are valid, but this
    /// implementation does not (yet) support it in the current environment —
    /// currently used only for isochronous transfers, since the underlying
    /// `nusb` backend has no isochronous support to call into (see
    /// `bridge.rs`).
    NotSupported,
}

impl ErrorKind {
    pub fn prefix(self) -> &'static str {
        match self {
            ErrorKind::Security => "SecurityError",
            ErrorKind::InvalidState => "InvalidStateError",
            ErrorKind::NotFound => "NotFoundError",
            ErrorKind::InvalidAccess => "InvalidAccessError",
            ErrorKind::IndexSize => "IndexSizeError",
            ErrorKind::DataError => "DataError",
            ErrorKind::NotSupported => "NotSupportedError",
        }
    }

    /// The full list this crate can produce. `guest-js/src/polyfill.ts`'s
    /// `KNOWN_ERROR_PREFIXES` must stay in sync with this — `tests` in this
    /// module and the guest-js test suite each independently assert their own
    /// side's list has exactly these seven, so a future addition here that
    /// forgets the TS side (the exact class of bug pyside6-webusb v0.0.4b2
    /// found and fixed) fails a test on the Rust side even before anyone
    /// gets to the JS side.
    pub const ALL: [ErrorKind; 7] = [
        ErrorKind::Security,
        ErrorKind::InvalidState,
        ErrorKind::NotFound,
        ErrorKind::InvalidAccess,
        ErrorKind::IndexSize,
        ErrorKind::DataError,
        ErrorKind::NotSupported,
    ];
}

/// A `WebUsbError` is always rendered to the wire as `"{kind}: {message}"`.
/// It intentionally does not implement `std::error::Error` + carry a `source`
/// chain across the IPC boundary — once this crosses into JSON there is no
/// receiving end that could use it, and flattening early keeps every command
/// handler's error path uniform (see `commands.rs`).
#[derive(Debug, Clone)]
pub struct WebUsbError {
    pub kind: ErrorKind,
    pub message: String,
}

impl WebUsbError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: sanitize_message(&message.into()) }
    }

    pub fn security(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Security, message)
    }
    pub fn invalid_state(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidState, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, message)
    }
    pub fn invalid_access(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidAccess, message)
    }
    pub fn index_size(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::IndexSize, message)
    }
    pub fn data_error(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::DataError, message)
    }
    pub fn not_supported(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotSupported, message)
    }
}

impl fmt::Display for WebUsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.prefix(), self.message)
    }
}

impl std::error::Error for WebUsbError {}

// serde: commands return `Result<T, WebUsbError>`; Tauri serializes the `Err`
// side with this `Serialize` impl. We deliberately serialize straight to the
// `"Kind: message"` string (not `{kind, message}`) so it is the *same* wire
// shape whether it travels back as a command rejection or gets embedded in a
// `{success: false, error: "..."}`-shaped payload (bulk/control transfer
// results use the latter, since STALL is a *resolved* value, not a rejected
// promise — see `bridge.rs`).
impl serde::Serialize for WebUsbError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Maximum length (in `char`s, matching the Python predecessors' behavior of
/// slicing rather than counting UTF-8 bytes) kept from an underlying error
/// before truncating. Mirrors `hardening.py`'s `safe_error_str`.
const MAX_MESSAGE_LEN: usize = 500;

/// Normalizes an arbitrary error message (which may ultimately originate from
/// `nusb`, the OS, or a malformed device's string descriptors) into something
/// safe to fold into a `"Kind: message"` line and hand to `console`/log
/// output downstream: no embedded newlines/tabs/carriage returns, and a
/// bounded length. Mirrors `hardening.py::safe_error_str`. Does *not* touch
/// the `"Kind: "` prefix itself, since that's always a `&'static str` literal
/// this crate writes, never attacker- or device-controlled text.
pub fn sanitize_message(msg: &str) -> String {
    let cleaned: String = msg
        .chars()
        .map(|c| if c == '\n' || c == '\r' || c == '\t' { ' ' } else { c })
        .collect();
    if cleaned.chars().count() > MAX_MESSAGE_LEN {
        let mut truncated: String = cleaned.chars().take(MAX_MESSAGE_LEN).collect();
        truncated.push('…');
        truncated
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_matches_kind() {
        assert_eq!(WebUsbError::security("x").to_string(), "SecurityError: x");
        assert_eq!(WebUsbError::invalid_state("x").to_string(), "InvalidStateError: x");
        assert_eq!(WebUsbError::not_found("x").to_string(), "NotFoundError: x");
        assert_eq!(WebUsbError::invalid_access("x").to_string(), "InvalidAccessError: x");
        assert_eq!(WebUsbError::index_size("x").to_string(), "IndexSizeError: x");
        assert_eq!(WebUsbError::data_error("x").to_string(), "DataError: x");
        assert_eq!(WebUsbError::not_supported("x").to_string(), "NotSupportedError: x");
    }

    #[test]
    fn all_seven_prefixes_are_distinct_and_stable() {
        let prefixes: Vec<&str> = ErrorKind::ALL.iter().map(|k| k.prefix()).collect();
        let mut sorted = prefixes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 7, "expected exactly 7 distinct prefixes, got {prefixes:?}");
        assert_eq!(
            prefixes,
            vec![
                "SecurityError", "InvalidStateError", "NotFoundError",
                "InvalidAccessError", "IndexSizeError", "DataError", "NotSupportedError",
            ]
        );
    }

    #[test]
    fn sanitize_strips_control_characters() {
        assert_eq!(sanitize_message("a\nb\tc\rd"), "a b c d");
    }

    #[test]
    fn sanitize_truncates_long_messages_with_ellipsis() {
        let long = "x".repeat(600);
        let got = sanitize_message(&long);
        assert_eq!(got.chars().count(), MAX_MESSAGE_LEN + 1); // +1 for the '…'
        assert!(got.ends_with('…'));
    }

    #[test]
    fn sanitize_leaves_short_clean_messages_untouched() {
        assert_eq!(sanitize_message("all good"), "all good");
    }

    #[test]
    fn error_serializes_to_plain_prefixed_string() {
        let e = WebUsbError::not_found("no device");
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(json, "\"NotFoundError: no device\"");
    }

    #[test]
    fn constructors_sanitize_their_message() {
        let e = WebUsbError::security("line1\nline2");
        assert_eq!(e.message, "line1 line2");
    }
}
