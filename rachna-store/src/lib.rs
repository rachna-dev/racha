//! Observed data: `.rachna/rachna.db`.
//!
//! Everything Rachna *observes* lives here — runs, decisions, grants, usage.
//! Everything Rachna is *told* lives in `rachna.nix`. That line matters:
//!
//! - **This is a cache, not truth.** Deleting the database loses audit history
//!   and nothing else. Permissions are in `rachna.nix`; VM state is in disks
//!   and snapshots. Which means migrations need not be bulletproof early
//!   (design-docs/00-PRODUCT.md §8).
//! - **Host-side and guest-unreachable.** If the guest could write here,
//!   malware would forge usage to keep its exfil channel alive, or forge
//!   silence to get your grants revoked (idea.md §8.1).
//! - **It is itself sensitive.** A log of every path read and host contacted is
//!   a map of your work: local-only, never phoned home, 90-day rolling
//!   retention by default.
//!
//! Write path: WAL, single writer (the broker), **batched per run**. One row
//! per decision rather than per unique target — a denial report needs `× 47`
//! and the time distribution both — but a chatty `npm install` would be
//! thousands of inserts, so the broker accumulates in memory and flushes once.
//!
//! Tables: `runs`, `decisions`, `grants`, `usage`, `config_revisions`
//! (design-docs/01-ARCHITECTURE.md §1).

/// # Panics
///
/// Unimplemented: see design-docs/01-ARCHITECTURE.md §8 step 4.
pub fn open(_path: &camino::Utf8Path) -> rachna_core::Result<()> {
    todo!("step 4: schema, batched writes, audit queries")
}
