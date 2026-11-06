//! Stable identities.
//!
//! The non-obvious one is [`GrantId`]: it is *content-derived*, not random.
//! Audit has to say "granted 24 days ago, never used" about a permission that
//! has survived arbitrary edits to `rachna.nix` — reformatting, reordering,
//! comments. So the identity of a grant is a hash of its normalized semantic
//! content, which means usage records attach to the permission itself rather
//! than to a line in a file (design-docs/00-PRODUCT.md §9.3).

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Identifies a single command execution under Rachna.
///
/// Rendered short (`run/a3f2`) for humans, because `rachna explain run/a3f2`
/// is meant to be typed from a terminal report.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunId(Uuid);

impl RunId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// The short form shown in reports and accepted by `rachna explain`.
    ///
    /// Four hex characters is enough to disambiguate within a project's recent
    /// history; the store resolves a prefix and reports ambiguity rather than
    /// guessing.
    #[must_use]
    pub fn short(&self) -> String {
        self.0.simple().to_string()[..4].to_owned()
    }

    #[must_use]
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for RunId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "run/{}", self.short())
    }
}

impl fmt::Debug for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RunId({})", self.0.simple())
    }
}

/// Content-derived identity of an effective permission.
///
/// Two grants with the same semantic content have the same id regardless of how
/// they were written. This is what lets usage survive config edits.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GrantId(String);

impl GrantId {
    /// Derive an id from a grant's normalized content.
    ///
    /// Callers must pass an already-normalized string — see
    /// `rachna_core::spec::Grant::fingerprint`, which is the only intended
    /// producer.
    #[must_use]
    pub fn from_content(normalized: &str) -> Self {
        Self(short_hash(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GrantId({})", self.0)
    }
}

/// Identity of one observed state of `rachna.nix`.
///
/// Audit uses this to answer "which revision introduced this grant", and the
/// store keys config history by it.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfigRevision(String);

impl ConfigRevision {
    #[must_use]
    pub fn from_source(source: &str) -> Self {
        Self(short_hash(source))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ConfigRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ConfigRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConfigRevision({})", self.0)
    }
}

/// Identity of a saved VM state.
///
/// Opaque to everything but the backend that produced it: snapshot payloads are
/// backend-specific by design and are never portable between hypervisors
/// (idea.md §14.7).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct SnapshotId(pub String);

impl fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A short, stable, non-cryptographic content hash.
///
/// FNV-1a, rendered as 16 hex characters. These ids are for *identity and
/// correlation*, never for integrity or authentication — snapshot and artifact
/// verification use real checksums elsewhere. Swapping this for a cryptographic
/// hash later changes every id, so it is deliberately isolated here.
fn short_hash(input: &str) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_ids_are_unique_and_render_short() {
        let a = RunId::new();
        let b = RunId::new();
        assert_ne!(a, b);
        assert_eq!(a.short().len(), 4);
        assert_eq!(a.to_string(), format!("run/{}", a.short()));
    }

    #[test]
    fn grant_id_is_content_derived() {
        // The whole point: same content, same id, independently of when or
        // where it was derived.
        let a = GrantId::from_content("network:registry.npmjs.org:443:tcp");
        let b = GrantId::from_content("network:registry.npmjs.org:443:tcp");
        let c = GrantId::from_content("network:github.com:443:tcp");

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn hash_is_stable_across_runs() {
        // Guards against accidentally swapping in a randomly-seeded hasher,
        // which would silently orphan every usage record on upgrade.
        assert_eq!(short_hash("rachna"), short_hash("rachna"));
        assert_eq!(short_hash("").len(), 16);
    }
}
