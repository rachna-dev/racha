//! The lifecycle state machine.
//!
//! The states a developer can be in, and which transitions are legal. Worth
//! being a real type rather than a bool pair, because the error cases matter:
//! a failed save, an incompatible snapshot, or a host shutdown mid-write all
//! have to leave the environment recoverable (idea.md §14.3).

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmState {
    Stopped,
    Running,
    /// Execution frozen, RAM still allocated on the host. Fast, but reclaims
    /// nothing.
    Paused,
    /// State written to durable storage and host RAM released. The steady state
    /// between work sessions.
    Suspended,
    /// A save or restore is in flight. Distinct because an interrupted save
    /// must not destroy the only valid disk state (idea.md §15.2).
    Transitioning,
}

impl VmState {
    /// A short label for error messages, e.g. "cannot resume while running".
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Suspended => "suspended",
            Self::Transitioning => "transitioning",
        }
    }
}
