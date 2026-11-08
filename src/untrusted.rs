//! `Untrusted<T>` — anything the guest said.
//!
//! `01-ARCHITECTURE.md` §2.5: *a compromised guest can lie, so anything
//! arriving from the agent should be a distinct type that must be validated
//! before use — making "the agent is not the security authority" a compiler
//! guarantee rather than a matter of discipline.*
//!
//! # What makes this a guarantee rather than a convention
//!
//! There is **no** `Deref`, no `AsRef`, no `From<Untrusted<T>> for T`, and the
//! inner value is private. The only way to a `T` is
//! [`Untrusted::validate`], which takes a function that can refuse. So
//! "forgot to validate" is a compile error, not a code-review finding.
//!
//! That is the whole design, and the temptation to add a convenience
//! accessor is exactly what it exists to resist: one `Deref` and every
//! downstream use of guest data silently becomes trusted again.

use core::fmt;

/// A value that came from the guest and has not been validated.
///
/// Deliberately **not** `Deref`, `AsRef`, `Copy`, or convertible into `T`.
/// See the module docs for why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Untrusted<T> {
    value: T,
}

impl<T> Untrusted<T> {
    /// Marks `value` as having come from the guest.
    ///
    /// Called at exactly one place per transport: where bytes are decoded.
    /// Anywhere else is a sign something trusted is being re-wrapped, which
    /// is harmless but points at a confused boundary.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self { value }
    }

    /// Validates, producing a trusted value or a reason it was rejected.
    ///
    /// The **only** way out. `check` receives the untrusted value by
    /// reference and returns the trusted form it vouches for, so a validator
    /// cannot accidentally pass the input through unexamined — it has to
    /// construct the result.
    ///
    /// # Errors
    ///
    /// Whatever `check` returns. A rejection is the expected case, not an
    /// exceptional one: a compromised guest sending a malformed message is
    /// precisely what this is for.
    pub fn validate<U, E>(&self, check: impl FnOnce(&T) -> Result<U, E>) -> Result<U, E> {
        check(&self.value)
    }

    /// The raw value, for logging and nothing else.
    ///
    /// Named to be uncomfortable at a call site. Reaching for this in the
    /// decision path is the bug the type exists to prevent — but refusing to
    /// expose it at all would mean a denial could not say *what* was
    /// rejected, which makes a diagnostic useless (`00` §3.3).
    #[must_use]
    pub const fn for_diagnostics_only(&self) -> &T {
        &self.value
    }

    /// Applies an infallible transformation, staying untrusted.
    ///
    /// For decoding steps that cannot fail and do not validate — a byte slice
    /// into a struct of fields that are each still suspect. The result is
    /// still `Untrusted`, which is the point: parsing is not validating.
    #[must_use]
    pub fn map<U>(self, transform: impl FnOnce(T) -> U) -> Untrusted<U> {
        Untrusted {
            value: transform(self.value),
        }
    }
}

impl<T: fmt::Display> fmt::Display for Untrusted<T> {
    /// Renders the value with a marker, so an untrusted value cannot appear
    /// in output looking like a fact.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<untrusted: {}>", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_is_the_only_way_to_a_trusted_value() {
        // Structural. There is no Deref, no AsRef, no From, and the field is
        // private — so this test documents the shape rather than exercising a
        // branch. If a convenience accessor is ever added, the module docs
        // explain why that is a security regression and not an ergonomic win.
        let untrusted = Untrusted::new(41_u32);
        let trusted: u32 = untrusted
            .validate(|value| {
                if *value < 100 {
                    Ok(*value + 1)
                } else {
                    Err("too large")
                }
            })
            .expect("41 is in range");
        assert_eq!(trusted, 42);
    }

    #[test]
    fn a_validator_can_refuse() {
        // A rejection is the expected case: a compromised guest sending a
        // malformed message is what this type is for.
        let untrusted = Untrusted::new(9999_u32);
        let result = untrusted.validate(|value| {
            if *value < 100 {
                Ok(*value)
            } else {
                Err("too large")
            }
        });
        assert_eq!(result, Err("too large"));
    }

    #[test]
    fn validation_does_not_consume_the_value() {
        // So a denial can report what was rejected after refusing it. Taking
        // `self` would force a clone at every call site that wants to
        // diagnose, and the diagnostic is the product (`00` §3.3).
        let untrusted = Untrusted::new("../../etc/passwd".to_owned());
        let rejected = untrusted.validate(|path| {
            if path.contains("..") {
                Err("path traversal")
            } else {
                Ok(path.clone())
            }
        });
        assert_eq!(rejected, Err("path traversal"));
        assert_eq!(untrusted.for_diagnostics_only(), "../../etc/passwd");
    }

    #[test]
    fn mapping_stays_untrusted() {
        // Parsing is not validating. Decoding bytes into a struct makes the
        // shape known and the CONTENTS no more trustworthy, so the result
        // must still require validation.
        let bytes = Untrusted::new(vec![b'4', b'2']);
        let text: Untrusted<String> = bytes.map(|raw| String::from_utf8_lossy(&raw).into_owned());
        // Still untrusted: the only way on is `validate`.
        assert_eq!(text.for_diagnostics_only(), "42");
        let number: u32 = text
            .validate(|s| s.parse::<u32>().map_err(|_| "not a number"))
            .expect("parses");
        assert_eq!(number, 42);
    }

    #[test]
    fn display_marks_the_value_as_untrusted() {
        // So guest-supplied text cannot appear in output looking like a fact.
        // A log line reading `path: /etc/shadow` implies Rachna believes it;
        // `<untrusted: /etc/shadow>` does not.
        let untrusted = Untrusted::new("/etc/shadow");
        assert_eq!(untrusted.to_string(), "<untrusted: /etc/shadow>");
    }

    #[test]
    fn two_untrusted_values_compare_by_content() {
        // Needed so a transport test can assert what it decoded.
        assert_eq!(Untrusted::new(1), Untrusted::new(1));
        assert_ne!(Untrusted::new(1), Untrusted::new(2));
    }
}
