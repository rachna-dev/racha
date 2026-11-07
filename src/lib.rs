//! Rachna — a declarative, isolated development environment manager.
//!
//! One crate, modules inside it. The seams that matter are enforced by module
//! boundaries and visibility rather than by separate crates; see `AGENTS.md`
//! and `design-docs/01-ARCHITECTURE.md` §1 for why an earlier twelve-crate
//! workspace was deleted.
//!
//! Build order is `design-docs/01-ARCHITECTURE.md` §7. Nothing here is
//! implemented yet beyond the harness.

// `unwrap_used`, `expect_used` and `panic` are warnings for product code: this
// is a security boundary and a panic in the broker is a denial of service. In
// tests they are fine and clearer than ceremony (AGENTS.md, "Rust style"), so
// they are allowed there.
//
// Verified rather than assumed: without this, a single `unwrap()` in a test
// fails the gate.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

/// The full version string, exactly as it is displayed.
///
/// `Major.Minor.Patch+<NixOS release>` — e.g. `0.4.1+26.11`. The guest system
/// version is carried *in* the version so the pairing is visible wherever a
/// version appears. Shown in full, including the patch component: a patch bump
/// is the promise "bug fix only, same guest, snapshots still restore".
///
/// See `design-docs/08-POLICY-AND-STORE.md` §4.1.1 for the release contract
/// each component commits to.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The NixOS release this build's guest is pinned to, if one is pinned yet.
///
/// `None` only before the first release that ships a guest; from then on the
/// build metadata is always present, because a `rachna` with no guest cannot
/// start a VM.
#[must_use]
pub fn guest_release() -> Option<&'static str> {
    version().split_once('+').map(|(_, guest)| guest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwrap_in_tests_does_not_trip_the_gate() {
        // AGENTS.md permits unwrap in tests. This asserts the lint
        // configuration actually agrees, so the rule and the tooling cannot
        // drift apart.
        //
        // Parsed rather than a literal `Some`: clippy's `unwrap_on_some`
        // fires on an obviously-Some value regardless of `unwrap_used`, and
        // the point here is the realistic case.
        let parsed: u32 = "41".parse().unwrap();
        assert_eq!(parsed + 1, 42);
    }

    // The version string is a promise (`08` §4.1.1), so its shape is checked
    // rather than its value: asserting the literal would only have to be
    // edited at every release, which tests the editor and not the scheme.

    /// The `Major.Minor.Patch` part: everything before the first `+` or `-`.
    ///
    /// Both separators are stripped so each test below fails for its own
    /// reason — a pre-release hyphen would otherwise also break the component
    /// count, and the count's failure message would blame the wrong thing.
    fn version_core() -> &'static str {
        let v = version();
        &v[..v.find(['+', '-']).unwrap_or(v.len())]
    }

    #[test]
    fn version_has_three_numeric_components() {
        let core = version_core();
        let parts: Vec<&str> = core.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "version core must be Major.Minor.Patch, got {core:?}"
        );
        for part in parts {
            assert!(
                !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()),
                "component {part:?} of {core:?} is not a plain number"
            );
        }
    }

    #[test]
    fn version_separates_the_guest_with_plus_not_hyphen() {
        // A hyphen would make the guest release a SemVer PRE-RELEASE: it would
        // sort before the same version without it and `cargo add` would skip
        // it. `+` is build metadata, ignored for precedence. This is the one
        // character that inverts the meaning, so it is pinned.
        //
        // Verified by probe: Cargo itself rejects `0.4+26.11`, `0.4+26.11x`
        // and `1.0+26.11+extra` at manifest-parse time, so those shapes can
        // never reach this test. `0.4.0-26.11` parses fine and is exactly what
        // is left for us to catch.
        assert!(
            !version().contains('-'),
            "{:?} uses `-`, which SemVer reads as a pre-release",
            version()
        );
    }

    #[test]
    fn guest_release_is_absent_only_while_no_guest_is_pinned() {
        // Build order step 1 has no guest to pin to, so `0.0.0` carries no
        // metadata. Once it does, the accessor must return it rather than the
        // whole string.
        match guest_release() {
            None => assert_eq!(version(), "0.0.0", "only 0.0.0 may omit a guest"),
            Some(guest) => {
                assert!(!guest.is_empty());
                assert!(!guest.contains('+'), "one `+` separator, not several");
            }
        }
    }
}
