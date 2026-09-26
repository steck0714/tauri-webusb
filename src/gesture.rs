//! gesture.rs
//! ==========
//! Short-lived, single-use tokens proving `requestDevice()` was actually
//! called from a real user gesture — the server-side half of
//! `security_report/VULNERABILITY_REPORT.md` finding No.2 in the reference
//! `pyside6-webusb` project this crate is ported from (the other half,
//! server-side filter-shape validation, has been enforced by
//! `commands.rs`/`hardening::is_valid_usb_device_filter` from the start).
//! Ported from `bridge.py`'s `mintGestureToken()`/`_consume_gesture_token()`.
//!
//! ## Why a client-side check alone isn't enough
//!
//! `guest-js/src/polyfill.ts`'s `requestDevice()` checks
//! `navigator.userActivation.isActive` before doing anything else — but
//! that check runs in the page's own JS context. Tauri's IPC bridge
//! (`invoke("plugin:webusb|request_device", ...)`) is reachable from *any*
//! script running in a webview that holds the `webusb:default` capability,
//! not only from code that imports this package and goes through
//! `polyfill.ts`'s wrapper — exactly the same "direct channel, bypassing
//! the polyfill" threat model `bridge.py`'s own docstring for this fix
//! describes for `QWebChannel`. Without a check here, that direct call
//! could pop the native device-chooser window at any time, with zero
//! actual user interaction.
//!
//! ## What this does and does not guarantee
//!
//! `mint()` is itself just another command any script with IPC access can
//! call — the token it returns is not cryptographic proof that a *human*
//! clicked anything, only that *some* script successfully completed one
//! authenticated round trip to this specific command before presenting the
//! result to `request_device`. This raises the bar substantially (a script
//! that wants to bypass the check now has to call two commands in the
//! right order within a five-second window, rather than one) without being
//! a perfect guarantee against a sufficiently determined scripted attacker
//! that also mints its own token — matching `bridge.py`'s own documented
//! caveat for the identical limitation (PySide6/QtWebEngine, like Tauri's
//! webview backends, has no public API letting the host process directly
//! observe a page's real DOM `UserActivation` state).
//!
//! ## Why this needs `tokio::sync::Mutex` but still has no `nusb`/`tauri`
//! dependency
//!
//! `tokio` alone (no `nusb`, no `tauri`) compiles under a substantially
//! older `rustc` than either of those — see `README.md`'s "Development
//! environment". That means, unlike `bridge.rs`/`chooser.rs`/`commands.rs`,
//! this module's tests *did* run for real in the sandbox this was written
//! in (`#[tokio::test]`, no fake/mock backend required) — see the `tests`
//! module below.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::hardening::{GESTURE_TOKEN_CACHE_CAP, GESTURE_TOKEN_TTL_SECS};

/// 128 bits from the OS CSPRNG, hex-encoded — plenty to make guessing a
/// live token infeasible within its five-second lifetime, matching the
/// order of magnitude of `bridge.py`'s own `secrets.token_urlsafe(24)`
/// (24 random bytes = 192 bits; 128 is still far beyond what a five-second
/// guessing window could threaten).
fn random_token() -> String {
    let mut bytes = [0u8; 16];
    // `getrandom` reads from the OS's own CSPRNG (`getrandom(2)` on Linux,
    // `BCryptGenRandom` on Windows, `getentropy(2)` on macOS) and is the
    // same source every other crate in this ecosystem that needs secure
    // randomness (`rand`, `uuid`, ...) ultimately calls into — used
    // directly here rather than pulling in all of `rand` for one call
    // site. A failure here means the OS itself couldn't supply entropy,
    // which is already a fairly extraordinary environment problem; falling
    // back to a *less* random token in that situation would be actively
    // wrong for a security token, so this deliberately panics rather than
    // silently minting something weaker.
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct MintedToken {
    minted_at: Instant,
}

/// The token cache itself. One instance lives in `WebUsbState`
/// (`state.rs`), shared between every `mint`/`consume` call the same way
/// `SessionRegistry`/`SettingsStore` already are.
pub struct GestureTokens {
    tokens: Mutex<HashMap<String, MintedToken>>,
}

impl GestureTokens {
    pub fn new() -> Self {
        Self { tokens: Mutex::new(HashMap::new()) }
    }

    /// Mints a fresh token, valid for `GESTURE_TOKEN_TTL_SECS` and usable
    /// exactly once (see `consume`). Also opportunistically evicts every
    /// already-expired token, then — if still at or over
    /// `GESTURE_TOKEN_CACHE_CAP` — evicts whichever remaining token is
    /// closest to expiring, oldest first, until there's room. A page
    /// calling this in a tight loop without ever calling `requestDevice()`
    /// can therefore never grow this map without bound; it can only ever
    /// force its own earlier, still-unused tokens to expire early.
    pub async fn mint(&self) -> String {
        let mut guard = self.tokens.lock().await;
        let ttl = Duration::from_secs(GESTURE_TOKEN_TTL_SECS);
        let now = Instant::now();
        guard.retain(|_, t| now.duration_since(t.minted_at) <= ttl);
        while guard.len() >= GESTURE_TOKEN_CACHE_CAP {
            let Some(oldest_key) = guard.iter().min_by_key(|(_, t)| t.minted_at).map(|(k, _)| k.clone()) else {
                break;
            };
            guard.remove(&oldest_key);
        }
        let token = random_token();
        guard.insert(token.clone(), MintedToken { minted_at: now });
        token
    }

    /// Verifies and *consumes* (single-use — removed whether or not it was
    /// valid) `token`. `true` only when the token was actually minted by
    /// this same cache and is still within its TTL; `false` for a token
    /// that never existed, was already consumed, or expired.
    pub async fn consume(&self, token: &str) -> bool {
        let mut guard = self.tokens.lock().await;
        match guard.remove(token) {
            Some(t) => Instant::now().duration_since(t.minted_at) <= Duration::from_secs(GESTURE_TOKEN_TTL_SECS),
            None => false,
        }
    }
}

impl Default for GestureTokens {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_freshly_minted_token_is_valid() {
        let tokens = GestureTokens::new();
        let t = tokens.mint().await;
        assert!(tokens.consume(&t).await);
    }

    #[tokio::test]
    async fn a_token_can_only_be_consumed_once() {
        let tokens = GestureTokens::new();
        let t = tokens.mint().await;
        assert!(tokens.consume(&t).await);
        assert!(!tokens.consume(&t).await, "the same token must not verify a second time");
    }

    #[tokio::test]
    async fn an_unknown_token_is_rejected() {
        let tokens = GestureTokens::new();
        assert!(!tokens.consume("not-a-real-token").await);
    }

    #[tokio::test]
    async fn two_distinct_mints_produce_two_distinct_tokens() {
        let tokens = GestureTokens::new();
        let a = tokens.mint().await;
        let b = tokens.mint().await;
        assert_ne!(a, b);
        assert!(tokens.consume(&a).await);
        assert!(tokens.consume(&b).await);
    }

    #[tokio::test]
    async fn consuming_one_token_does_not_invalidate_a_different_one() {
        let tokens = GestureTokens::new();
        let a = tokens.mint().await;
        let b = tokens.mint().await;
        assert!(tokens.consume(&a).await);
        assert!(tokens.consume(&b).await, "consuming `a` must not have removed `b` too");
    }

    #[tokio::test]
    async fn mint_evicts_the_oldest_entries_once_the_cache_cap_is_reached() {
        let tokens = GestureTokens::new();
        let mut minted = Vec::new();
        // One past the cap: mint() itself must make room rather than
        // growing past GESTURE_TOKEN_CACHE_CAP, so the very first token
        // minted is the one that gets evicted to make room for the last.
        for _ in 0..=GESTURE_TOKEN_CACHE_CAP {
            minted.push(tokens.mint().await);
        }
        assert_eq!(tokens.tokens.lock().await.len(), GESTURE_TOKEN_CACHE_CAP);
        assert!(!tokens.consume(&minted[0]).await, "the oldest token should have been evicted to make room");
        assert!(tokens.consume(minted.last().unwrap()).await, "the newest token should still be valid");
    }

    #[tokio::test]
    async fn an_expired_token_is_rejected_even_though_it_was_never_explicitly_removed() {
        let tokens = GestureTokens::new();
        let t = tokens.mint().await;
        // Reach into the cache and backdate it rather than actually
        // sleeping GESTURE_TOKEN_TTL_SECS in a test.
        {
            let mut guard = tokens.tokens.lock().await;
            let entry = guard.get_mut(&t).unwrap();
            entry.minted_at = Instant::now() - Duration::from_secs(GESTURE_TOKEN_TTL_SECS + 1);
        }
        assert!(!tokens.consume(&t).await);
    }

    #[tokio::test]
    async fn minting_opportunistically_sweeps_out_already_expired_tokens() {
        let tokens = GestureTokens::new();
        let stale = tokens.mint().await;
        {
            let mut guard = tokens.tokens.lock().await;
            let entry = guard.get_mut(&stale).unwrap();
            entry.minted_at = Instant::now() - Duration::from_secs(GESTURE_TOKEN_TTL_SECS + 1);
        }
        let _fresh = tokens.mint().await;
        assert_eq!(tokens.tokens.lock().await.len(), 1, "the expired entry should have been swept during mint()");
    }

    #[test]
    fn random_token_calls_do_not_collide_in_a_reasonably_large_sample() {
        // Not a statistical randomness test (out of scope for a unit test)
        // -- just a sanity check that this isn't accidentally returning a
        // constant or a narrow/predictable value.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(random_token()), "random_token() produced a duplicate within 1000 calls");
        }
    }
}
