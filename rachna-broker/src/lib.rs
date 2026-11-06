//! The trusted host-side supervisor.
//!
//! Two concurrent concerns:
//!
//! **The reload loop** — watch `rachna.nix` and its import set, evaluate, diff
//! the two specs against what is live, classify the delta, and apply the
//! cheapest action that satisfies it.
//!
//! **The enforcement path** — every attempted operation becomes a
//! [`rachna_core::Decision`], recorded and accumulated into the run's report.
//!
//! Invariants that must hold (design-docs/01-ARCHITECTURE.md §5):
//!
//! - **Never auto-restart a VM holding live processes.** Live deltas apply
//!   silently; disruptive changes are announced and wait for `rachna rebuild`.
//! - **A failed evaluation never disturbs a running environment.** You will be
//!   mid-edit constantly; a syntax error cannot take down your Postgres.
//! - **The guest agent is a coordinator, never an authority.** Every decision
//!   is made host-side (idea.md §15.3).
//! - Decisions accumulate in memory per run and flush to the store in a batch.

pub mod reload;

pub use reload::Delta;
