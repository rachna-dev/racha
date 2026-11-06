//! Host↔guest path translation. One library, no exceptions.
//!
//! The guest sees `/workspace/src/main.rs`; the editor sees
//! `/Users/you/Projects/app/src/main.rs`. Every LSP message carries URIs and
//! every compiler error carries a path, so both directions need rewriting in:
//!
//! - **LSP JSON-RPC** — `textDocument.uri`, `rootUri`, `rootPath`,
//!   `workspaceFolders`, every `Location`/`LocationLink` in responses, and URIs
//!   embedded in `window/showMessage` text.
//! - **DAP** — `source.path`, breakpoint paths, `cwd`.
//! - **Compiler stderr** — so `cargo build` errors stay clickable in the
//!   editor.
//! - **Generic JSON** — anything carrying a `file://`.
//!
//! This crate exists as its own crate for one reason: it is a *structural
//! guarantee* that no shim invents its own rewriting. Per-shim path munging is
//! an unfixable bug farm, and this is the single most important piece of code
//! in the IDE story (design-docs/00-PRODUCT.md §6.3).
//!
//! # Edge cases that belong in the test suite
//!
//! Translation must be a lossless round-trip, property-tested. The cases that
//! will bite (design-docs/01-ARCHITECTURE.md §4):
//!
//! - symlinks in the host path
//! - case-insensitive host filesystem vs case-sensitive guest
//! - URL-encoded spaces and non-ASCII
//! - paths *outside* the workspace — must pass through untouched or be
//!   rejected, **never half-rewritten**
//! - `..` traversal

use camino::{Utf8Path, Utf8PathBuf};

/// A host↔guest mapping for one workspace.
#[derive(Clone, Debug)]
pub struct Mapping {
    host_root: Utf8PathBuf,
    guest_root: Utf8PathBuf,
}

impl Mapping {
    #[must_use]
    pub fn new(host_root: impl Into<Utf8PathBuf>, guest_root: impl Into<Utf8PathBuf>) -> Self {
        Self {
            host_root: host_root.into(),
            guest_root: guest_root.into(),
        }
    }

    /// Translate a host path into the guest.
    ///
    /// Returns `None` for paths outside the workspace, so callers must decide
    /// explicitly whether to pass through or reject. Returning a half-rewritten
    /// path would be worse than either.
    #[must_use]
    pub fn to_guest(&self, host: &Utf8Path) -> Option<Utf8PathBuf> {
        host.strip_prefix(&self.host_root)
            .ok()
            .map(|rest| self.guest_root.join(rest))
    }

    /// Translate a guest path back to the host.
    #[must_use]
    pub fn to_host(&self, guest: &Utf8Path) -> Option<Utf8PathBuf> {
        guest
            .strip_prefix(&self.guest_root)
            .ok()
            .map(|rest| self.host_root.join(rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping() -> Mapping {
        Mapping::new("/Users/you/Projects/app", "/workspace")
    }

    #[test]
    fn translates_both_directions() {
        let m = mapping();
        let guest = m.to_guest(Utf8Path::new("/Users/you/Projects/app/src/main.rs"));
        assert_eq!(
            guest.as_deref(),
            Some(Utf8Path::new("/workspace/src/main.rs"))
        );

        let host = m.to_host(Utf8Path::new("/workspace/src/main.rs"));
        assert_eq!(
            host.as_deref(),
            Some(Utf8Path::new("/Users/you/Projects/app/src/main.rs"))
        );
    }

    #[test]
    fn round_trip_is_lossless() {
        let m = mapping();
        let original = Utf8Path::new("/Users/you/Projects/app/deep/nested/file.rs");
        let there = m.to_guest(original).expect("inside workspace");
        let back = m.to_host(&there).expect("inside workspace");
        assert_eq!(back, original);
    }

    #[test]
    fn roots_themselves_translate() {
        let m = mapping();
        assert_eq!(
            m.to_guest(Utf8Path::new("/Users/you/Projects/app"))
                .as_deref(),
            Some(Utf8Path::new("/workspace"))
        );
    }

    #[test]
    fn outside_the_workspace_is_none_not_mangled() {
        // The important negative case: a path we cannot translate must not come
        // back partially rewritten.
        let m = mapping();
        assert!(m
            .to_guest(Utf8Path::new("/Users/you/.ssh/id_ed25519"))
            .is_none());
        assert!(m.to_host(Utf8Path::new("/etc/passwd")).is_none());
    }

    #[test]
    fn sibling_prefix_is_not_treated_as_inside() {
        // `/Users/you/Projects/app-other` shares a textual prefix with the
        // workspace root but is a different directory. A naive string
        // starts_with would translate it; strip_prefix is path-aware.
        let m = mapping();
        assert!(m
            .to_guest(Utf8Path::new("/Users/you/Projects/app-other/src/lib.rs"))
            .is_none());
    }
}
