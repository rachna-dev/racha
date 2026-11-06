//! The error taxonomy shared across crates.
//!
//! Library crates return typed errors; `rachna-cli` adds human context. The
//! split exists so the CLI can decide how to *present* a failure — a config
//! error wants a file and line, a backend capability gap wants an explanation
//! of what to change — without libraries guessing at presentation.

use std::fmt;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /// `rachna.nix` could not be evaluated. Never fatal to a running
    /// environment: the broker keeps the last-good spec and keeps watching
    /// (design-docs/00-PRODUCT.md §3.5).
    #[error("config: {message}")]
    Config {
        message: String,
        /// Where the problem is, when the evaluator can say.
        location: Option<SourceLocation>,
    },

    /// The CST editor declined to modify the file rather than risk mangling
    /// it. The CLI responds by printing the snippet to paste, which is why
    /// this is a normal outcome and not a bug
    /// (design-docs/00-PRODUCT.md §5.3).
    #[error("cannot safely edit rachna.nix: {reason}")]
    EditRefused { reason: String },

    /// The policy asks for something the selected backend cannot enforce.
    /// Rachna rejects rather than silently weakening the policy
    /// (idea.md §16.2).
    #[error("backend {backend} cannot enforce {capability}")]
    UnsupportedCapability { backend: String, capability: String },

    /// An operation was requested that the VM's current state does not allow,
    /// e.g. resuming something already running.
    #[error("cannot {operation} while {state}")]
    InvalidTransition {
        operation: &'static str,
        state: &'static str,
    },

    /// A run id prefix matched more than one run.
    #[error("run id \"{prefix}\" is ambiguous ({matches} matches)")]
    AmbiguousRunId { prefix: String, matches: usize },

    #[error("no such run: {prefix}")]
    NoSuchRun { prefix: String },

    /// Data arrived from the guest agent that failed validation. The agent is
    /// a coordinator, never an authority (idea.md §15.3), so this is an
    /// expected failure mode rather than an internal error.
    #[error("rejected data from guest agent: {reason}")]
    UntrustedInput { reason: String },

    #[error("store: {0}")]
    Store(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    #[must_use]
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
            location: None,
        }
    }

    #[must_use]
    pub fn config_at(message: impl Into<String>, location: SourceLocation) -> Self {
        Self::Config {
            message: message.into(),
            location: Some(location),
        }
    }
}

/// A position in a Nix source file, for pointing at the offending line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_refusal_explains_itself() {
        let err = Error::EditRefused {
            reason: "the allow list is built by a function call".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "cannot safely edit rachna.nix: the allow list is built by a function call"
        );
    }

    #[test]
    fn capability_gap_names_both_sides() {
        let err = Error::UnsupportedCapability {
            backend: "mock".to_owned(),
            capability: "memory_snapshot".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "backend mock cannot enforce memory_snapshot"
        );
    }

    #[test]
    fn source_location_renders_clickably() {
        let loc = SourceLocation {
            file: "rachna.nix".to_owned(),
            line: 42,
            column: 7,
        };
        assert_eq!(loc.to_string(), "rachna.nix:42:7");
    }
}
