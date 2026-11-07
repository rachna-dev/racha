//! Rachna — a declarative, isolated development environment manager.
//!
//! One crate, modules inside it. The seams that matter are enforced by module
//! boundaries and visibility rather than by separate crates; see
//! `AGENTS.md` and `design-docs/01-ARCHITECTURE.md` §1 for why an earlier
//! twelve-crate workspace was deleted.
//!
//! Build order is `design-docs/01-ARCHITECTURE.md` §7. Nothing here is
//! implemented yet beyond the harness.

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
    fn version_is_reported() {
        assert_eq!(version(), "0.0.0");
    }
}
