//! Classifying what a config change actually requires.
//!
//! This is the whole hot-reload decision, and it falls out of the
//! `ExecSpec`/`PolicySpec` split: policy deltas are usually live, exec deltas
//! usually need a new Nix closure (design-docs/00-PRODUCT.md §3.5).

/// What a config change demands of the running environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delta {
    /// Nothing changed that matters.
    None,
    /// Recompile policy and swap it in place. Sub-100ms: network allowlist,
    /// port forwards, mount add/remove, resource limits, env for new
    /// processes.
    Live,
    /// Restart one service unit in the guest, e.g. a changed Postgres port.
    RestartService { name: &'static str },
    /// Changes the Nix closure — packages, guest version, kernel params. Needs
    /// a rebuild and a VM restart, so it is *announced and waits* rather than
    /// applied.
    Rebuild,
}

/// Watch a config and its imports, classifying each change.
///
/// # Panics
///
/// Unimplemented: see design-docs/01-ARCHITECTURE.md §8 step 7.
///
/// Two mechanics that must be right: editors write atomically (temp file plus
/// rename), so watch the *directory* for renames rather than the inode; and
/// debounce around 200ms so a save mid-keystroke does not thrash.
pub fn watch(_root: &camino::Utf8Path) -> rachna_core::Result<()> {
    todo!("step 7: watch → evaluate → diff → classify, over the mock backend")
}
