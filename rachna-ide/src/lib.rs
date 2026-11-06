//! Pointing an editor at the guest.
//!
//! Two attach modes, one environment. The guest is the real environment; how an
//! editor reaches it is pluggable (design-docs/00-PRODUCT.md §6.2):
//!
//! - **VS Code Server in the guest**, devcontainer-style. One RPC channel,
//!   declared once, and extensions never touch the host — so there is no path
//!   translation at all. Cleanest, but VS Code only.
//! - **Declared tool shims**, for every other editor. N protocol endpoints,
//!   each declared and scoped, editor-agnostic.
//!
//! Shims come first: they are the general mechanism, they prove the plumbing
//! VS Code Server also needs, and they serve git hooks and CI too.
//!
//! No editor plugin is required, because every editor can override a server
//! path or a format command — `rust-analyzer.server.path` in VS Code,
//! `lsp.*.binary.path` in Zed, `cmd = {...}` in Neovim, toolchain paths in
//! JetBrains. This crate writes those files and reports drift.
//!
//! The honest limitation: extensions that shell out to hardcoded binary paths
//! will break and cannot be fixed from here. The fallback is the terminal
//! profile — the editor's integrated terminal defaults to a guest shell, so
//! anything typed manually is already inside.

/// Editors Rachna can configure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Editor {
    VsCode,
    Zed,
    Neovim,
    JetBrains,
}

/// Write the editor's configuration to point at `.rachna/bin`.
///
/// # Panics
///
/// Unimplemented: see design-docs/01-ARCHITECTURE.md §8 step 10.
pub fn configure(_editor: Editor, _root: &camino::Utf8Path) -> rachna_core::Result<()> {
    todo!("step 10: per-editor config generation")
}
