//! `rachna.nix` in, two specs out — plus surgical edits back.
//!
//! Three responsibilities, and the third is easy to overlook:
//!
//! 1. **Evaluate** into an [`rachna_core::ExecSpec`] and an
//!    [`rachna_core::PolicySpec`]. Nothing downstream reads Nix again.
//! 2. **Edit** via an `rnix` CST so comments and formatting survive. When the
//!    file uses a construct that cannot be safely modified — a `let`, an
//!    `import`, a function call building the allow list — **refuse and let the
//!    CLI print a snippet to paste.** Never silently rewrite or reformat
//!    (design-docs/00-PRODUCT.md §5.3). Because of this, the editor is a
//!    convenience, not load-bearing.
//! 3. **Report the file dependency set.** The watcher needs to know which
//!    files to watch, including everything `import`ed. This is a real
//!    requirement on the Nix layer, not an afterthought
//!    (design-docs/00-PRODUCT.md §3.5).
//!
//! Evaluation shells out to `nix eval --json` rather than linking libnixexpr.
//! That choice, and how to get the dependency set out of it, is
//! design-docs/01-ARCHITECTURE.md §11.1 — still open.

use camino::Utf8PathBuf;

/// The result of evaluating a config, including what it depends on.
#[derive(Debug)]
pub struct Evaluated {
    pub exec: rachna_core::ExecSpec,
    pub policy: rachna_core::PolicySpec,
    /// Every file that participated in evaluation. The watcher watches all of
    /// these, not just `rachna.nix`.
    pub depends_on: Vec<Utf8PathBuf>,
    pub revision: rachna_core::ConfigRevision,
}

/// Evaluate a project's `rachna.nix`.
///
/// # Errors
///
/// Returns [`rachna_core::Error::Config`] when evaluation fails. A failure here
/// must never disturb a running environment: the broker keeps the last-good
/// spec and keeps watching.
///
/// # Panics
///
/// Unimplemented: see design-docs/01-ARCHITECTURE.md §8 step 2.
pub fn evaluate(_path: &camino::Utf8Path) -> rachna_core::Result<Evaluated> {
    todo!("step 2: nix eval --json → both specs, plus the import set")
}
