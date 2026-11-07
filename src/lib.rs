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

/// Placeholder so the crate compiles and the gate has something to check.
///
/// Step 2 replaces this with the core types.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
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

    #[test]
    fn version_is_reported() {
        assert_eq!(version(), "0.0.0");
    }
}
