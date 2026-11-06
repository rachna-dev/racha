//! The backend seam.
//!
//! No hypervisor is chosen yet — that is the point. [`MockBackend`] implements
//! the full trait in-process, which lets the policy, audit, reload, and IDE
//! stories all be built and tested on macOS with no virtualization at all. It
//! is also the basis of the conformance suite every real backend must pass, so
//! capability gaps surface as explicit skips rather than silent divergence
//! (design-docs/01-ARCHITECTURE.md §6).
//!
//! **The rule that must not be softened:** if a backend cannot enforce a
//! requested policy, reject the config or make the user explicitly choose a
//! weaker one. Never silently downgrade security (idea.md §16.2).

pub mod backend;
pub mod capabilities;
pub mod mock;
pub mod state;

pub use backend::{VmBackend, VmHandle};
pub use capabilities::{Capabilities, FsSharing};
pub use mock::MockBackend;
pub use state::VmState;
