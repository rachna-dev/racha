//! Credential placeholders (`00` §3.6).
//!
//! The guest receives a *placeholder* token. The host proxy substitutes the
//! real value on the way out:
//!
//! ```text
//! guest                     host proxy                   api.github.com
//!   │  GET /user                 │                              │
//!   │  Authorization: <ph>  ────▶│  swaps in the real token ───▶│
//! ```
//!
//! `15` §7 item 5 ranks this above snapshot encryption in one specific way:
//! `10` §4 planted three secret classes in a guest and recovered all three
//! from a snapshot, and **placeholders eliminate the first class entirely** —
//! a token that never enters the guest cannot be in its memory. Encryption
//! protects all three but only at rest, and only once the key management in
//! `25` §5 exists.
//!
//! # The property that makes this better than a secret broker
//!
//! `00` §3.6's third bullet, which is the good one: **bypassing the proxy is
//! self-defeating rather than merely detected.** A request that goes around
//! the proxy carries only the placeholder, so the remote host *refuses it*.
//! Compare the alternative — noticing a bypass after the credential has
//! already left.
//!
//! # What this module is responsible for, and what it must never do
//!
//! It owns the placeholder↔secret mapping and the decision to substitute. It
//! deliberately **cannot hold a secret value in any type that is logged,
//! stored, or sent to the guest**, and that is enforced by the types rather
//! than by review:
//!
//! - [`Placeholder`] is what the guest gets. It is safe to log and safe to
//!   store, because it *is* public — that is the whole point.
//! - [`Secret`] holds the real value, and its `Debug` and `Display` are
//!   **redacted**. `17` §3 establishes that audit records must never go
//!   through `tracing` because `RUST_LOG` could drop them; this is the
//!   mirror-image rule — a secret must never *reach* `tracing` at all.
//! - [`Grant::Secret`](crate::grant::Grant::Secret) already holds a name and
//!   never a value, so the policy layer cannot carry one either.

use crate::decision::{Category, Decision, DenyReason};
use core::fmt;

/// The public token a guest holds in place of a real credential.
///
/// Safe to log, store, and hand to the guest — it is designed to be useless
/// anywhere but at our proxy. That is not a convenience: `00` §3.6's
/// self-defeating-bypass property depends on the guest holding something a
/// remote host will *reject*.
///
/// # Why the shape is fixed rather than random-looking
///
/// A placeholder has to be recognisable *by us*, in a byte stream, with no
/// context — the proxy sees `Authorization: Bearer <something>` and must
/// decide whether that something is ours. A fixed, improbable prefix makes
/// that a cheap exact test instead of a guess. `exclusion.rs` is the
/// precedent: a name-based guess about identity was measured wrong twice
/// (`13` §2, `15` §3.4), so anything identity-shaped gets an exact test.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Placeholder {
    name: String,
}

/// The prefix every placeholder carries.
///
/// Deliberately not a plausible token: a real credential that happened to
/// collide with this would be substituted, which is worse than failing to
/// recognise one of ours.
const PLACEHOLDER_PREFIX: &str = "rachna-placeholder-";

impl Placeholder {
    /// The placeholder for a declared secret name.
    ///
    /// Derived from the name rather than random, because the guest's
    /// environment must be **stable across restarts**: a process that cached
    /// `$GITHUB_TOKEN` before a resume would otherwise hold a value the proxy
    /// no longer recognises, and the failure would look like an expired
    /// token rather than a Rachna bug.
    ///
    /// # Errors
    ///
    /// [`CredentialError::EmptyName`] for an empty name, which would produce
    /// a bare prefix that every placeholder shares.
    pub fn for_name(name: impl Into<String>) -> Result<Self, CredentialError> {
        let name = name.into();
        if name.is_empty() {
            return Err(CredentialError::EmptyName);
        }
        Ok(Self { name })
    }

    /// The secret name this stands for.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The token text, as the guest sees it.
    #[must_use]
    pub fn token(&self) -> String {
        format!("{PLACEHOLDER_PREFIX}{}", self.name)
    }

    /// The secret name inside a token, if this is one of ours.
    ///
    /// The proxy's recognition test. Returns `None` for anything else —
    /// including a token that merely *contains* the prefix, because a
    /// substring match would let a guest smuggle a real-looking credential
    /// past us by embedding our prefix in it.
    #[must_use]
    pub fn name_in_token(token: &str) -> Option<&str> {
        let name = token.strip_prefix(PLACEHOLDER_PREFIX)?;
        if name.is_empty() {
            return None;
        }
        Some(name)
    }
}

impl fmt::Display for Placeholder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.token())
    }
}

/// A real credential value.
///
/// # Why this type exists rather than a `String`
///
/// `Debug` and `Display` are **redacted**, so a secret cannot reach a log,
/// an error message, or a panic payload by accident. A `String` would have
/// printed itself at the first `{:?}` someone added while debugging — and
/// that is not a hypothetical: `09` §4's whole finding is that secrets end
/// up in places nobody put them deliberately.
///
/// It deliberately does **not** implement `Clone`, `PartialEq` or
/// `Serialize`:
///
/// - no `Clone`, so there is one copy to reason about;
/// - no `PartialEq`, because a naive `==` is a timing oracle, and
///   [`Self::matches`] exists for the comparison that is actually needed;
/// - no `Serialize`, so it cannot be written to the audit store — `08` §3.4
///   makes that store host-side and guest-unreachable, which is necessary
///   and would be pointless if we wrote credentials into it.
pub struct Secret {
    value: String,
}

impl Secret {
    /// Takes ownership of a real credential value.
    ///
    /// # Errors
    ///
    /// [`CredentialError::EmptySecret`] for an empty value. Refused because
    /// an empty secret substituted into a request produces an
    /// indistinguishable-from-unauthenticated call to a real API, and the
    /// 401 that comes back would be read as "my token is wrong" rather than
    /// "Rachna had nothing to substitute".
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialError> {
        let value = value.into();
        if value.is_empty() {
            return Err(CredentialError::EmptySecret);
        }
        Ok(Self { value })
    }

    /// The real value, for substitution at the boundary.
    ///
    /// Named to be conspicuous at a call site. There should be exactly one
    /// caller — the proxy's substitution step — and a second one is a design
    /// question rather than a convenience.
    #[must_use]
    pub fn expose_for_substitution(&self) -> &str {
        &self.value
    }

    /// Whether this secret equals `candidate`, in constant time.
    ///
    /// Not `PartialEq`: a short-circuiting `==` leaks the length of the
    /// common prefix through timing. This is hand-rolled rather than pulled
    /// from a crate because `17`'s rule is to evaluate a dependency before
    /// adding one, and the whole operation is six lines.
    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        let left = self.value.as_bytes();
        let right = candidate.as_bytes();
        // Length is not secret — it is observable from the ciphertext of
        // almost any protocol — so an early return on length is fine and the
        // loop below needs equal lengths to be meaningful.
        if left.len() != right.len() {
            return false;
        }
        let mut difference = 0_u8;
        for (a, b) in left.iter().zip(right.iter()) {
            difference |= a ^ b;
        }
        difference == 0
    }
}

/// Redacted, deliberately.
///
/// This is the line that stops a credential reaching a log. A test asserts
/// the real value is absent from the output, because the failure mode is
/// silent: nothing breaks when a secret prints itself.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Why a credential operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// A secret name was empty.
    EmptyName,
    /// A secret value was empty.
    EmptySecret,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => f.write_str(
                "a secret must have a name: it is the name the guest sees and \
                 the name `rachna audit` reports",
            ),
            Self::EmptySecret => f.write_str(
                "a secret's value is empty. Substituting it would send an \
                 unauthenticated request to a real API, and the 401 would \
                 look like a bad token rather than a missing one",
            ),
        }
    }
}

impl core::error::Error for CredentialError {}

/// What the proxy decided to do with a token it saw.
///
/// A sum type rather than `Option<&Secret>` because the three outcomes need
/// different handling and two of them are *findings*, not absences:
/// `00` §3.3 requires a denial to explain itself, and "the guest used a
/// placeholder nobody declared" is a different story from "this is not one of
/// our tokens at all".
#[derive(Debug)]
pub enum Substitution<'a> {
    /// Not one of ours. Passed through untouched.
    ///
    /// The common case, and it must stay cheap: every header of every request
    /// goes through this test.
    NotOurs,
    /// Ours, declared, and allowed. The real value follows.
    Substituted {
        /// The secret name, for the audit record.
        name: &'a str,
        /// The value to put on the wire.
        secret: &'a Secret,
    },
    /// Ours, but the policy does not permit it.
    ///
    /// Carries the `Decision` so it lands in the audit trail like any other
    /// denial (`01` §2.7: the proxy's decisions are `Decision`s).
    Refused {
        /// The secret name the guest asked for.
        name: String,
        /// The denial, ready for the store and the report.
        decision: Decision,
    },
}

/// The host's credential store: placeholder names to real values.
///
/// Host-side only. `08` §3.4 makes the audit store guest-unreachable; this is
/// the same rule applied to something more sensitive, and the type cannot be
/// serialised at all because [`Secret`] cannot.
#[derive(Debug, Default)]
pub struct Broker {
    entries: Vec<(String, Secret)>,
}

impl Broker {
    /// An empty broker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Declares a secret, replacing any previous value for that name.
    ///
    /// Replacing rather than refusing a duplicate, because a rotated token
    /// arriving at `rachna start` is the normal case and refusing it would
    /// make rotation an error.
    pub fn declare(&mut self, name: impl Into<String>, secret: Secret) {
        let name = name.into();
        self.entries.retain(|(existing, _)| *existing != name);
        self.entries.push((name, secret));
    }

    /// Every declared name, sorted.
    ///
    /// Names only. There is no accessor that yields every *value*, so a
    /// caller cannot iterate the store and print it.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.entries.iter().map(|(name, _)| name.as_str()).collect();
        names.sort_unstable();
        names
    }

    /// Decides what to do with one token the proxy saw.
    ///
    /// `permitted` is the policy answer for this secret name — supplied by
    /// the caller rather than computed here, because `decide.rs` owns that
    /// question and duplicating it would create a second policy engine that
    /// could disagree with the first (`AGENTS.md`, "extend the owner").
    #[must_use]
    pub fn substitute(&self, token: &str, permitted: bool) -> Substitution<'_> {
        let Some(name) = Placeholder::name_in_token(token) else {
            return Substitution::NotOurs;
        };

        if !permitted {
            // The policy refused this secret. `NoMatchingGrant` rather than
            // a new variant: `decide.rs` already owns this taxonomy, and
            // "the policy does not cover it" is exactly what happened.
            return Substitution::Refused {
                name: name.to_owned(),
                decision: Decision::Deny {
                    reason: DenyReason::NoMatchingGrant {
                        category: Category::Secret,
                    },
                },
            };
        }

        match self.entries.iter().find(|(known, _)| known == name) {
            Some((known, secret)) => Substitution::Substituted {
                name: known,
                secret,
            },
            // A placeholder the guest holds for a secret the host does not
            // have. Distinct from `NotOurs`: the guest got this token from
            // us, so an undeclared name means our own state is inconsistent
            // — worth a denial record rather than a silent pass-through,
            // which would send the placeholder to the remote host.
            //
            // `BackendCannotEnforce` is the honest reason, and the existing
            // doc comment on it says why: "a rule the backend cannot enforce
            // must never behave like a rule that is simply missing, or the
            // config file lies". A declared secret we hold no value for is
            // that case exactly — the grant exists and we cannot honour it.
            None => Substitution::Refused {
                name: name.to_owned(),
                decision: Decision::Deny {
                    reason: DenyReason::BackendCannotEnforce {
                        category: Category::Secret,
                    },
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = "ghp_realtokenvalue1234567890abcdef";

    fn broker_with(name: &str) -> Broker {
        let mut broker = Broker::new();
        broker.declare(name, Secret::new(REAL).expect("non-empty"));
        broker
    }

    // ---- the property the whole module exists for -------------------------

    #[test]
    fn a_secret_never_prints_itself() {
        // THE test. `09` §4's finding is that secrets end up in places nobody
        // put them deliberately, and a `String` would have printed itself at
        // the first `{:?}` added while debugging. The failure mode is silent:
        // nothing breaks when a credential leaks into a log.
        let secret = Secret::new(REAL).expect("non-empty");

        // First assert the thing under attack exists: the real value IS
        // retrievable through the one conspicuous accessor. Without this, a
        // `Secret` that stored nothing would pass every assertion below.
        assert_eq!(secret.expose_for_substitution(), REAL);

        for rendered in [format!("{secret:?}"), format!("{secret}")] {
            assert!(
                !rendered.contains(REAL),
                "a secret printed its value: {rendered}"
            );
            assert!(
                !rendered.contains("realtokenvalue"),
                "a secret printed part of its value: {rendered}"
            );
            assert!(rendered.contains("redacted"), "{rendered}");
        }

        // And inside a container, which is how it will usually be printed —
        // `{:?}` on a struct holding one must not reach through it.
        let wrapped = Some(&secret);
        assert!(!format!("{wrapped:?}").contains(REAL));
        let broker = broker_with("GITHUB_TOKEN");
        assert!(
            !format!("{broker:?}").contains(REAL),
            "the broker printed a secret: {broker:?}"
        );
    }

    #[test]
    fn the_broker_exposes_names_but_never_values() {
        // `08` §3.4 keeps the audit store guest-unreachable; this is the same
        // rule one level up. `names()` is the only enumeration, so a caller
        // cannot iterate the store and print it.
        let mut broker = Broker::new();
        broker.declare("B_TOKEN", Secret::new("b-value").expect("ok"));
        broker.declare("A_TOKEN", Secret::new("a-value").expect("ok"));
        assert_eq!(broker.names(), vec!["A_TOKEN", "B_TOKEN"]);
        // Sorted, so `rachna status` output is stable between runs.
        let rendered = format!("{:?}", broker.names());
        assert!(!rendered.contains("a-value") && !rendered.contains("b-value"));
    }

    // ---- recognition: the proxy's test -----------------------------------

    #[test]
    fn a_placeholder_round_trips_through_its_token() {
        let placeholder = Placeholder::for_name("GITHUB_TOKEN").expect("named");
        let token = placeholder.token();
        assert_eq!(Placeholder::name_in_token(&token), Some("GITHUB_TOKEN"));
        // Display is the token, because that is what gets written into an
        // environment variable.
        assert_eq!(placeholder.to_string(), token);
    }

    #[test]
    fn the_token_is_stable_across_restarts() {
        // Derived from the name rather than random, because a process that
        // cached `$GITHUB_TOKEN` before a resume would otherwise hold a value
        // the proxy no longer recognises — and the failure would look like an
        // expired token rather than a Rachna bug.
        let first = Placeholder::for_name("GITHUB_TOKEN")
            .expect("named")
            .token();
        let second = Placeholder::for_name("GITHUB_TOKEN")
            .expect("named")
            .token();
        assert_eq!(first, second);
        // And two names never collide.
        assert_ne!(
            first,
            Placeholder::for_name("NPM_TOKEN").expect("x").token()
        );
    }

    #[test]
    fn only_an_exact_prefix_is_recognised() {
        // A substring match would let a guest smuggle a real-looking
        // credential past us by embedding our prefix in it. `exclusion.rs` is
        // the precedent: a name-based guess about identity was measured wrong
        // twice (`13` §2, `15` §3.4).
        //
        // First the positive case, so the negatives below are not vacuous.
        assert_eq!(
            Placeholder::name_in_token("rachna-placeholder-X"),
            Some("X")
        );

        for rejected in [
            "",
            "rachna-placeholder-",         // bare prefix, no name
            "ghp_realtoken",               // an actual token
            "Bearer rachna-placeholder-X", // prefix not at the start
            "xrachna-placeholder-X",       // one byte before it
            "RACHNA-PLACEHOLDER-X",        // case differs
            "rachna-placeholder",          // truncated prefix
            "rachna_placeholder-X",        // separator differs
        ] {
            assert_eq!(
                Placeholder::name_in_token(rejected),
                None,
                "`{rejected}` was recognised as a placeholder"
            );
        }
    }

    // ---- substitution and refusal ----------------------------------------

    #[test]
    fn a_declared_and_permitted_placeholder_is_substituted() {
        let broker = broker_with("GITHUB_TOKEN");
        let token = Placeholder::for_name("GITHUB_TOKEN")
            .expect("named")
            .token();
        match broker.substitute(&token, true) {
            Substitution::Substituted { name, secret } => {
                assert_eq!(name, "GITHUB_TOKEN");
                assert_eq!(secret.expose_for_substitution(), REAL);
            }
            other => panic!("expected a substitution, got {other:?}"),
        }
    }

    #[test]
    fn a_token_that_is_not_ours_passes_through_untouched() {
        // The common case, and it must not become a denial: a guest talking
        // to a service with its own non-Rachna credential is normal.
        let broker = broker_with("GITHUB_TOKEN");
        for foreign in ["ghp_somethingelse", "Bearer abc", ""] {
            assert!(
                matches!(broker.substitute(foreign, true), Substitution::NotOurs),
                "`{foreign}` was not passed through"
            );
        }
    }

    #[test]
    fn a_placeholder_the_policy_refuses_produces_a_denial_not_a_passthrough() {
        // `01` §2.7: the proxy's decisions are `Decision`s and land in the
        // audit trail. Passing the placeholder through instead would send it
        // to the remote host, which is `00` §3.6's self-defeating-bypass
        // property working by accident rather than by design — and would
        // leave no record of the attempt.
        let broker = broker_with("GITHUB_TOKEN");
        let token = Placeholder::for_name("GITHUB_TOKEN")
            .expect("named")
            .token();
        match broker.substitute(&token, false) {
            Substitution::Refused { name, decision } => {
                assert_eq!(name, "GITHUB_TOKEN");
                let Decision::Deny { reason } = decision else {
                    panic!("a refusal must be a Deny")
                };
                // The existing taxonomy, not a new variant: `decide.rs` owns
                // this and a second list would be one that could disagree.
                assert_eq!(
                    reason,
                    DenyReason::NoMatchingGrant {
                        category: Category::Secret
                    }
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_placeholder_for_an_undeclared_secret_is_refused_not_passed_on() {
        // Distinct from `NotOurs`: the guest got this token from US, so an
        // undeclared name means our own state is inconsistent. Passing it
        // through would put the placeholder on the wire.
        let broker = broker_with("GITHUB_TOKEN");
        let token = Placeholder::for_name("NPM_TOKEN").expect("named").token();
        match broker.substitute(&token, true) {
            Substitution::Refused { name, decision } => {
                assert_eq!(name, "NPM_TOKEN");
                // A DIFFERENT reason from a policy refusal, and the
                // distinction is load-bearing. `DenyReason`'s own doc on
                // this variant says why: "a rule the backend cannot enforce
                // must never behave like a rule that is simply missing, or
                // the config file lies". A secret declared in rachna.nix
                // whose value the host does not hold is that case — the
                // grant exists and we cannot honour it, which the user must
                // be able to tell from "the policy says no".
                let Decision::Deny { reason } = decision else {
                    panic!("a refusal must be a Deny")
                };
                assert_eq!(
                    reason,
                    DenyReason::BackendCannotEnforce {
                        category: Category::Secret
                    }
                );
            }
            other => panic!("an undeclared placeholder must be refused, got {other:?}"),
        }
    }

    #[test]
    fn the_two_refusal_reasons_are_distinguishable() {
        // Both paths refuse, so a test that only checked `is Refused` would
        // pass with one reason used for both — and a user could not tell
        // "your policy forbids this" from "rachna has no value for it", which
        // have completely different fixes.
        let broker = broker_with("GITHUB_TOKEN");
        let declared = Placeholder::for_name("GITHUB_TOKEN").expect("x").token();
        let undeclared = Placeholder::for_name("NPM_TOKEN").expect("x").token();

        let reason_of = |outcome: Substitution<'_>| -> DenyReason {
            match outcome {
                Substitution::Refused { decision, .. } => match decision {
                    Decision::Deny { reason } => reason,
                    Decision::Allow { .. } => panic!("a refusal that allows"),
                },
                other => panic!("expected a refusal, got {other:?}"),
            }
        };

        let policy_refused = reason_of(broker.substitute(&declared, false));
        let no_value = reason_of(broker.substitute(&undeclared, true));
        assert_ne!(
            policy_refused, no_value,
            "a forbidden secret and a missing one gave the same reason"
        );
    }

    #[test]
    fn the_real_value_never_appears_in_a_refusal() {
        // A denial is written to the audit store and rendered to the user, so
        // it is the most likely place for a secret to leak. Checked against
        // BOTH refusal paths, because they are built separately.
        let broker = broker_with("GITHUB_TOKEN");
        let declared = Placeholder::for_name("GITHUB_TOKEN").expect("x").token();
        let undeclared = Placeholder::for_name("OTHER").expect("x").token();
        for outcome in [
            broker.substitute(&declared, false),
            broker.substitute(&undeclared, true),
        ] {
            let rendered = format!("{outcome:?}");
            assert!(
                !rendered.contains(REAL),
                "a refusal carried the real value: {rendered}"
            );
        }
    }

    // ---- rotation and comparison -----------------------------------------

    #[test]
    fn declaring_a_name_twice_replaces_the_value() {
        // A rotated token arriving at `rachna start` is the normal case;
        // refusing the duplicate would make rotation an error.
        let mut broker = broker_with("GITHUB_TOKEN");
        broker.declare("GITHUB_TOKEN", Secret::new("ghp_rotated").expect("ok"));
        assert_eq!(broker.names(), vec!["GITHUB_TOKEN"], "rotation duplicated");
        let token = Placeholder::for_name("GITHUB_TOKEN").expect("x").token();
        match broker.substitute(&token, true) {
            Substitution::Substituted { secret, .. } => {
                assert_eq!(secret.expose_for_substitution(), "ghp_rotated");
            }
            other => panic!("expected a substitution, got {other:?}"),
        }
    }

    #[test]
    fn comparison_is_length_safe_and_correct() {
        // `matches` exists because a short-circuiting `==` leaks the length
        // of the common prefix through timing. Correctness is what a test can
        // assert; the timing property is a code-shape claim, so the loop is
        // written to have no early exit and that is visible at the call site.
        let secret = Secret::new(REAL).expect("non-empty");
        assert!(secret.matches(REAL));
        assert!(!secret.matches(""));
        assert!(!secret.matches("ghp_realtokenvalue1234567890abcde")); // one short
        assert!(!secret.matches("ghp_realtokenvalue1234567890abcdef0")); // one long
                                                                         // A shared prefix must not match — the case a prefix comparison
                                                                         // would get wrong.
        assert!(!secret.matches("ghp_realtokenvalue1234567890abcdeX"));
    }

    // ---- the errors explain themselves -----------------------------------

    #[test]
    fn an_empty_name_or_value_is_refused_with_a_reason() {
        assert_eq!(
            Placeholder::for_name("").err(),
            Some(CredentialError::EmptyName)
        );
        assert_eq!(Secret::new("").err(), Some(CredentialError::EmptySecret));

        // An empty secret is the subtle one: substituting it would send an
        // unauthenticated request to a real API, and the 401 would read as a
        // bad token rather than a missing one. The message has to say that.
        let message = CredentialError::EmptySecret.to_string();
        assert!(message.contains("401"), "{message}");
        assert!(message.contains("unauthenticated"), "{message}");
        assert!(
            CredentialError::EmptyName.to_string().len() > 40,
            "too terse to act on"
        );
    }
}
