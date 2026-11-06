//! The host↔guest wire.
//!
//! Carries three things: command execution with full stdio, tool invocations
//! from the shims, and lifecycle coordination (quiesce, service restart).
//!
//! The important property is in the type system, not the wire format. Anything
//! arriving *from* the guest is [`Untrusted`] and must be validated before use,
//! so "the agent is not the security authority" is enforced by the compiler
//! rather than by discipline (design-docs/01-ARCHITECTURE.md §11.5).

use std::fmt;

/// A value that came from the guest and has not been validated.
///
/// There is deliberately no `Deref`, no `into_inner`, and no `Debug` passthrough
/// on the payload: the only way to get at the value is [`Untrusted::validate`],
/// which forces a caller to say what "valid" means.
pub struct Untrusted<T>(T);

impl<T> Untrusted<T> {
    /// Wrap a value received from the guest.
    #[must_use]
    pub fn received(value: T) -> Self {
        Self(value)
    }

    /// Validate and unwrap.
    ///
    /// # Errors
    ///
    /// Returns [`rachna_core::Error::UntrustedInput`] when the check fails. A
    /// compromised guest lying to the host is an expected failure mode, not an
    /// internal error.
    pub fn validate<F>(self, reason: &str, check: F) -> rachna_core::Result<T>
    where
        F: FnOnce(&T) -> bool,
    {
        if check(&self.0) {
            Ok(self.0)
        } else {
            Err(rachna_core::Error::UntrustedInput {
                reason: reason.to_owned(),
            })
        }
    }
}

impl<T> fmt::Debug for Untrusted<T> {
    /// Deliberately opaque, so untrusted guest data cannot leak into logs
    /// looking like it had been checked.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Untrusted(<unvalidated>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_is_mandatory_to_unwrap() {
        let ok = Untrusted::received(42u32).validate("must be small", |n| *n < 100);
        assert_eq!(ok.ok(), Some(42));

        let bad = Untrusted::received(9000u32).validate("must be small", |n| *n < 100);
        assert!(bad.is_err());
    }

    #[test]
    fn debug_does_not_leak_guest_data() {
        let value = Untrusted::received("../../etc/shadow");
        assert_eq!(format!("{value:?}"), "Untrusted(<unvalidated>)");
    }
}
