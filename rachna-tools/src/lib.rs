//! Tool exposure as a declared permission.
//!
//! A shim directory that forwards anything to the guest would be a privileged
//! backdoor around the policy model. So exposure *is* policy: `.rachna/bin`
//! contains **exactly** the declared set, it is generated output rather than a
//! scratch directory, and creating a symlink by hand changes nothing because
//! the host-side agent checks policy before forwarding
//! (design-docs/00-PRODUCT.md §6.4).
//!
//! That buys three things at once: tool denials join the same run report as
//! blocked network calls, unused exposures show up in `rachna audit` like any
//! other unused grant, and adding a tool hot-reloads like any other policy
//! change.
//!
//! # A tool is a scoped role
//!
//! Language servers execute project code — build scripts, proc macros,
//! `eslint.config.js` — which makes them among the most privileged things in a
//! normal dev setup, and nobody treats them that way. `rust-analyzer` needs to
//! read the workspace and run `cargo check`; it does not need network. So each
//! exposed tool carries its own access scope, enforced guest-side as defense in
//! depth and host-side for anything crossing the boundary.
//!
//! # What was deliberately cut
//!
//! Surfacing guest *libraries* to host-side editor extensions
//! (`.rachna/lib/typescript`) would mean the host reads and executes JS
//! originating in the guest — exactly the host-integration-bug class
//! idea.md §19 lists as a top risk. A declared tool is always a protocol
//! endpoint, never a file the host runs (design-docs/00-PRODUCT.md §6.5).

/// Generate `.rachna/bin` from the declared tool set.
///
/// Every entry is a symlink back to the `rachna` binary, which dispatches on
/// `argv[0]` — busybox-style.
///
/// # Panics
///
/// Unimplemented: see design-docs/01-ARCHITECTURE.md §8 step 10.
pub fn generate(
    _policy: &rachna_core::PolicySpec,
    _bin_dir: &camino::Utf8Path,
) -> rachna_core::Result<()> {
    todo!("step 10: declared set → symlinks")
}
