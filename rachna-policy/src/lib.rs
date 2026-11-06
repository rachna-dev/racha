//! The policy engine.
//!
//! This crate is deliberately **pure**: no files, no sockets, no clock. It
//! takes specs and requests and returns answers. That is the key design choice
//! in the workspace — the hardest-to-get-right component becomes exhaustively
//! testable without a VM, which is exactly what the "backend-agnostic core
//! first" decision is meant to buy (design-docs/01-ARCHITECTURE.md §1).
//!
//! It answers two different kinds of question, and the second one is unusual:
//!
//! - [`decide`] — "is this allowed?" The enforcement path.
//! - [`synthesize`] — "what is the narrowest rule set covering these
//!   observations?" The engine is also a *synthesizer*, which is what powers
//!   audit's narrowing suggestions. This is a counterfactual query, not a
//!   lookup (design-docs/00-PRODUCT.md §9.4).

#![allow(clippy::needless_pass_by_value)] // API shape is settled before bodies are.

use rachna_core::{Decision, PolicySpec, Request};

/// Answer one request against the policy.
///
/// Returns a [`Decision`] — never a bool. See `rachna_core::decision` for why.
///
/// # Panics
///
/// Unimplemented: see design-docs/01-ARCHITECTURE.md §8 step 3.
pub fn decide(_policy: &PolicySpec, _request: Request) -> Decision {
    todo!("step 3: exhaustive table-driven decide() over the full taxonomy")
}

/// Given what was actually observed, propose the narrowest rules that cover it.
///
/// The highest-value case is wildcard collapse: a `*.googleapis.com` grant used
/// only for two concrete hosts becomes a suggestion to allow exactly those two.
/// Path scopes narrow the same way.
///
/// # Panics
///
/// Unimplemented: see design-docs/01-ARCHITECTURE.md §8 step 5.
pub fn synthesize(_observations: &[rachna_core::Decision]) -> Vec<rachna_core::Grant> {
    todo!("step 5: observations → minimal rule set")
}
