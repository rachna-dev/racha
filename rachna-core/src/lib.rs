//! Shared vocabulary for Rachna.
//!
//! This crate holds the types every other crate agrees on and deliberately
//! knows nothing concrete: no Nix, no SQL, no sockets, no hypervisor. If
//! something here needs to do I/O, it belongs in another crate.
//!
//! The two most load-bearing shapes are:
//!
//! - [`ExecSpec`] and [`PolicySpec`] — the *only* two artifacts `rachna.nix`
//!   evaluates into. Nothing downstream re-reads the Nix file, and hot-reload
//!   classification is a diff over these two structs
//!   (design-docs/01-ARCHITECTURE.md §2).
//! - [`Decision`] — a permission answer is an *event*, never a `bool`. It
//!   carries what matched, what was touched, why it was denied, and the
//!   narrowest grant that would have allowed it
//!   (design-docs/00-PRODUCT.md §9.1).

pub mod decision;
pub mod error;
pub mod ids;
pub mod request;
pub mod spec;

pub use decision::{Decision, DenyReason, Scope, Verdict};
pub use error::{Error, Result};
pub use ids::{ConfigRevision, GrantId, RunId, SnapshotId};
pub use request::{ProcessChain, ProcessInfo, Request, RequestKind};
pub use spec::{Access, ExecSpec, Grant, PolicySpec, Profile, ToolKind};
