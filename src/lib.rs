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

/// The NixOS release carried in a version string, if it has build metadata.
///
/// `None` for a version with no guest pinned — which is every version before
/// the first release that ships one.
///
/// # Why this takes the version rather than reading it
///
/// There was a `guest_release()` that read `CARGO_PKG_VERSION` directly. It is
/// deleted: nothing called it but its own tests, and because the only
/// observable input was `0.0.0`, a mutant returning a constant `None` was
/// behaviourally identical and survived every test that could be written.
/// Suppressing that mutant would have left untested, uncalled code in a
/// security tool. Taking the version as an argument makes the logic testable
/// against any input, which is the actual fix.
///
/// A caller wanting this build's guest release passes [`version()`].
#[must_use]
pub fn guest_release_of(version: &str) -> Option<&str> {
    version.split_once('+').map(|(_, guest)| guest)
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
    fn the_guest_release_is_the_metadata_after_the_first_plus() {
        assert_eq!(guest_release_of("0.4.1+26.11"), Some("26.11"));
        // Build metadata may itself contain dots and dashes; only the FIRST
        // `+` separates, so the whole remainder is the guest identity.
        assert_eq!(
            guest_release_of("1.0.0+26.11-3181085"),
            Some("26.11-3181085")
        );
        assert_eq!(guest_release_of("2.0.0+a+b"), Some("a+b"));
    }

    #[test]
    fn a_version_with_no_metadata_has_no_guest() {
        assert_eq!(guest_release_of("0.0.0"), None);
        assert_eq!(guest_release_of("1.2.3"), None);
    }

    #[test]
    fn an_empty_metadata_section_is_present_but_empty() {
        // Documents a boundary rather than claiming it is good: `1.0.0+`
        // parses to `Some("")`. Cargo rejects a trailing `+`, so this cannot
        // reach us from a manifest — recorded so it is deliberate rather than
        // discovered later.
        assert_eq!(guest_release_of("1.0.0+"), Some(""));
    }

    #[test]
    fn this_builds_guest_release_agrees_with_its_version_string() {
        // Asserts the RELATIONSHIP, not today's value. A first draft asserted
        // `== None`, which is true at 0.0.0 and becomes false at the first
        // release that ships a guest — the same brittleness as pinning the
        // literal version, caught by running the suite at 0.4.1+26.11.
        match guest_release_of(version()) {
            None => assert!(
                !version().contains('+'),
                "no guest reported, but {:?} carries metadata",
                version()
            ),
            Some(guest) => assert!(
                version().ends_with(guest) && version().contains('+'),
                "reported guest {guest:?} is not the metadata of {:?}",
                version()
            ),
        }
    }
}

pub mod credential;
pub mod decide;
pub mod decision;
pub mod denial;
pub mod enforcement;
pub mod exclusion;
pub mod grant;
pub mod layout;
pub mod lifecycle;
pub mod policy;
pub mod summary;
pub mod supervise;
pub mod synthesize;
pub mod tap;
pub mod transport;
pub mod untrusted;

#[cfg(test)]
mod json_limits {
    /// A hostile `rachna.nix` can make `nix eval --json` emit arbitrarily
    /// nested output, so the parser must refuse rather than overflow the
    /// stack. `17` §2 claims serde_json's default recursion limit does this;
    /// verified here rather than trusted, because a stack overflow in the
    /// host-side evaluator is a crash at full privilege.
    #[test]
    fn deeply_nested_json_is_refused_rather_than_crashing() {
        let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        let parsed = serde_json::from_str::<serde_json::Value>(&deep);
        assert!(parsed.is_err(), "100k-deep input must be rejected");
    }

    /// And the limit does not reject anything a real config produces.
    #[test]
    fn realistically_nested_json_still_parses() {
        let nested = format!("{}1{}", "[".repeat(100), "]".repeat(100));
        assert!(serde_json::from_str::<serde_json::Value>(&nested).is_ok());
    }
}
pub mod backend;
pub mod cli;
pub mod config;
pub mod eval;
pub mod protocol;
pub mod reload;
pub mod render;
pub mod resources;
pub mod snapshot;
pub mod store;
