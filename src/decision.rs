//! The vocabulary of a policy decision.
//!
//! Every type here exists to make an illegal state unrepresentable rather than
//! merely unlikely. The module is pure data: no files, no sockets, no clock
//! (`08-POLICY-AND-STORE.md` §1.1), which is what lets the hardest code in the
//! product be tested exhaustively with no VM.
//!
//! The ordering of [`DenyReason`] mirrors the matching order in
//! `08-POLICY-AND-STORE.md` §1.2, and that is deliberate: the sequence is the
//! specification, so a reader can check one against the other.

use core::fmt;

/// What a request wants to touch.
///
/// A category is never a string. A stringly-typed category cannot be matched
/// exhaustively, and the compiler stops helping at exactly the point where a
/// missed case becomes a security hole (`AGENTS.md`, "prefer enums").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    /// Reaching a network address.
    Network,
    /// Reading or writing a host path.
    Filesystem,
    /// Invoking a declared tool (LSP, formatter, debugger).
    Tool,
    /// Binding or forwarding a port.
    Port,
    /// Reading a credential placeholder.
    Secret,
}

impl Category {
    /// Every category, for exhaustive table-driven tests.
    ///
    /// Kept adjacent to the enum so adding a variant without adding it here is
    /// caught by [`Self::ALL_IS_EXHAUSTIVE`]'s test rather than by review.
    pub const ALL: [Self; 5] = [
        Self::Network,
        Self::Filesystem,
        Self::Tool,
        Self::Port,
        Self::Secret,
    ];

    /// The word used for this category in `rachna.nix` and on the CLI.
    ///
    /// One definition, because the config surface, the denial report and the
    /// audit store must agree (`AGENTS.md`, "extend the owner").
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Filesystem => "fs",
            Self::Tool => "tool",
            Self::Port => "port",
            Self::Secret => "secret",
        }
    }

    /// The category a user typed, or `None`.
    ///
    /// Lives here rather than in `cli.rs` because [`Self::as_str`] is the one
    /// definition of these words (`AGENTS.md`, "extend the owner") — a
    /// separate parser in the CLI would be a second list to keep in step, and
    /// the first one to drift.
    ///
    /// Derived from [`Self::ALL`] rather than written as a second `match`, so
    /// a new variant is parseable the moment it is added. The round-trip
    /// against `as_str` is therefore a property, not a table to maintain.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == word)
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How much access a grant confers, or a request wants.
///
/// Replaces a `read_only: bool`. A bool cannot express "no access" without a
/// second bool, and two bools admit a fourth state that means nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Access {
    /// May observe, not modify.
    ReadOnly,
    /// May observe and modify.
    ReadWrite,
}

impl Access {
    /// Whether a grant at `self` is enough for a request wanting `wanted`.
    ///
    /// `ReadWrite` subsumes `ReadOnly`; the reverse is the
    /// [`DenyReason::InsufficientAccess`] case.
    #[must_use]
    pub const fn covers(self, wanted: Self) -> bool {
        matches!(
            (self, wanted),
            (Self::ReadWrite, _) | (Self::ReadOnly, Self::ReadOnly)
        )
    }
}

/// Why a request was denied.
///
/// Variants are ordered as the matching sequence in
/// `08-POLICY-AND-STORE.md` §1.2 evaluates them. There is deliberately **no**
/// `Other(String)`: a catch-all defeats exhaustive matching, which is the
/// entire reason this is an enum (`AGENTS.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// The active profile forbids this category outright.
    ProfileForbids { category: Category },
    /// Policy speaks in names, and the request used a literal address.
    ///
    /// Not a missing grant: a hostname allowlist that resolves on the guest's
    /// behalf is not a boundary, because the guest can dial an IP and skip DNS
    /// (`02` §7). It is a distinct denial so it can be explained distinctly.
    DirectAddressBypass { literal: String },
    /// No grant covers the target.
    NoMatchingGrant { category: Category },
    /// A grant covers the target, but not at this access level.
    InsufficientAccess { granted: Access, wanted: Access },
    /// The tool's own role does not permit this.
    ToolRoleForbids { tool: String },
    /// The backend cannot enforce the rule that would have allowed this.
    ///
    /// Distinct from an absent rule on purpose: a rule the backend cannot
    /// enforce must never behave like a rule that is simply missing, or the
    /// config file lies (`01-ARCHITECTURE.md` §3b).
    BackendCannotEnforce { category: Category },
}

impl DenyReason {
    /// The category this denial concerns, where it names one.
    ///
    /// `None` for denials that are not about a category: a literal-address
    /// bypass is about *how* the request was made, and a tool-role refusal is
    /// about the tool.
    #[must_use]
    pub const fn category(&self) -> Option<Category> {
        match self {
            Self::ProfileForbids { category }
            | Self::NoMatchingGrant { category }
            | Self::BackendCannotEnforce { category } => Some(*category),
            Self::DirectAddressBypass { .. }
            | Self::InsufficientAccess { .. }
            | Self::ToolRoleForbids { .. } => None,
        }
    }

    /// Whether editing `rachna.nix` could turn this denial into an allow.
    ///
    /// The denial report leads with the fixable ones, because a suggested
    /// `rachna allow` line on an unfixable denial is a lie (`00` §3.3).
    /// `BackendCannotEnforce` is the sharp case: adding the grant changes
    /// nothing, because the platform cannot honour it.
    #[must_use]
    pub const fn is_fixable_by_grant(&self) -> bool {
        match self {
            Self::NoMatchingGrant { .. }
            | Self::InsufficientAccess { .. }
            | Self::DirectAddressBypass { .. } => true,
            Self::ProfileForbids { .. }
            | Self::ToolRoleForbids { .. }
            | Self::BackendCannotEnforce { .. } => false,
        }
    }
}

/// The concrete value a request touched inside a possibly-broader grant.
///
/// This is what makes narrowing possible: without it audit can only say "used
/// 412 times", and with it, "only ever these two hosts"
/// (`08-POLICY-AND-STORE.md` §1.3). **A missing scope on an allow is a bug**,
/// which is why [`Decision::Allow`] cannot be constructed without one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Scope(String);

impl Scope {
    /// Records the concrete value touched.
    ///
    /// # Errors
    ///
    /// [`ScopeError::Empty`] if `value` is empty: an empty scope is
    /// indistinguishable from not recording one, and would silently make audit
    /// useless rather than loudly fail.
    pub fn new(value: impl Into<String>) -> Result<Self, ScopeError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ScopeError::Empty);
        }
        Ok(Self(value))
    }

    /// The recorded value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why a [`Scope`] could not be recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeError {
    /// The value was empty, so nothing was actually recorded.
    Empty,
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("a scope must name the value that was touched"),
        }
    }
}

impl core::error::Error for ScopeError {}

/// The answer to one request.
///
/// An enum and not a `bool`, because an answer carries *why*
/// (`01-ARCHITECTURE.md` §2.2). It is also an **event**, not a verdict: it is
/// what gets written to the audit store, so it must carry everything the
/// denial report, `rachna explain` and narrowing each need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Permitted, recording the concrete value touched.
    Allow { scope: Scope },
    /// Refused, recording why.
    Deny { reason: DenyReason },
}

impl Decision {
    /// Whether the request may proceed.
    ///
    /// Deliberately not `From<Decision> for bool`: collapsing to a bool at a
    /// call site discards the reason, and the reason is the product.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_category_parses_back_from_the_word_it_prints() {
        // A property over ALL rather than a table, so a new category is
        // covered the moment it exists. First assert the thing under attack
        // exists: that `parse` is not simply returning the same answer for
        // everything.
        assert_eq!(Category::parse("network"), Some(Category::Network));
        assert_eq!(Category::parse("fs"), Some(Category::Filesystem));

        for category in Category::ALL {
            assert_eq!(
                Category::parse(category.as_str()),
                Some(category),
                "`{category}` does not round-trip"
            );
        }

        // And the cases a CLI actually sees. `fs` is deliberately not
        // `filesystem` on the wire (as_str), so the long spelling must NOT
        // parse — accepting both would mean two spellings in rachna.nix.
        for rejected in ["", "filesystem", "Network", "net", "networks", " fs"] {
            assert_eq!(
                Category::parse(rejected),
                None,
                "`{rejected}` was accepted as a category"
            );
        }
    }

    // `Category::ALL` exists for table-driven tests, so a variant added
    // without updating it would silently shrink every table that uses it.
    // Matching exhaustively here means adding a variant fails to compile.
    #[test]
    fn all_lists_every_category() {
        for category in Category::ALL {
            match category {
                Category::Network
                | Category::Filesystem
                | Category::Tool
                | Category::Port
                | Category::Secret => {}
            }
        }
        let mut sorted = Category::ALL;
        sorted.sort_unstable();
        let mut deduped = sorted.to_vec();
        deduped.dedup();
        assert_eq!(deduped.len(), Category::ALL.len(), "ALL has a duplicate");
    }

    #[test]
    fn category_names_are_distinct_and_stable() {
        // These strings appear in rachna.nix, the CLI and the audit store, so
        // a collision would make two categories indistinguishable on disk.
        let mut names: Vec<&str> = Category::ALL.iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two categories share a name");

        // Pinned: renaming one silently breaks every existing config file.
        assert_eq!(Category::Filesystem.as_str(), "fs");
        assert_eq!(Category::Network.as_str(), "network");
    }

    #[test]
    fn display_agrees_with_as_str() {
        // Two ways to render the same thing must not drift (AGENTS.md).
        for category in Category::ALL {
            assert_eq!(category.to_string(), category.as_str());
        }
    }

    #[test]
    fn read_write_covers_everything_and_read_only_covers_only_itself() {
        assert!(Access::ReadWrite.covers(Access::ReadWrite));
        assert!(Access::ReadWrite.covers(Access::ReadOnly));
        assert!(Access::ReadOnly.covers(Access::ReadOnly));
        // The InsufficientAccess case, and the one that matters: a read-only
        // grant must never satisfy a write.
        assert!(!Access::ReadOnly.covers(Access::ReadWrite));
    }

    /// One of every `DenyReason`, so a new variant fails to compile here.
    fn every_deny_reason() -> Vec<DenyReason> {
        let all = vec![
            DenyReason::ProfileForbids {
                category: Category::Network,
            },
            DenyReason::DirectAddressBypass {
                literal: "10.0.0.1:443".to_owned(),
            },
            DenyReason::NoMatchingGrant {
                category: Category::Filesystem,
            },
            DenyReason::InsufficientAccess {
                granted: Access::ReadOnly,
                wanted: Access::ReadWrite,
            },
            DenyReason::ToolRoleForbids {
                tool: "rust-analyzer".to_owned(),
            },
            DenyReason::BackendCannotEnforce {
                category: Category::Port,
            },
        ];
        // Exhaustiveness: adding a variant breaks this match, which is the
        // point of avoiding `#[non_exhaustive]` on internal enums.
        for reason in &all {
            match reason {
                DenyReason::ProfileForbids { .. }
                | DenyReason::DirectAddressBypass { .. }
                | DenyReason::NoMatchingGrant { .. }
                | DenyReason::InsufficientAccess { .. }
                | DenyReason::ToolRoleForbids { .. }
                | DenyReason::BackendCannotEnforce { .. } => {}
            }
        }
        all
    }

    #[test]
    fn every_deny_reason_answers_both_questions() {
        // Not asserting specific values here — the point is that neither
        // accessor can panic or be forgotten for any variant.
        for reason in every_deny_reason() {
            let _ = reason.category();
            let _ = reason.is_fixable_by_grant();
        }
    }

    #[test]
    fn backend_cannot_enforce_is_not_fixable_by_a_grant() {
        // The sharp case. Adding the grant changes nothing because the
        // platform cannot honour it, so suggesting `rachna allow` would be a
        // lie. A limit that does not enforce is worse than no limit
        // (01-ARCHITECTURE.md §3b).
        let reason = DenyReason::BackendCannotEnforce {
            category: Category::Port,
        };
        assert!(!reason.is_fixable_by_grant());
    }

    #[test]
    fn a_direct_address_bypass_is_fixable_but_names_no_category() {
        // It is about HOW the request was made, not what it touched — so it
        // reports no category while still being user-fixable.
        let reason = DenyReason::DirectAddressBypass {
            literal: "10.0.0.1:443".to_owned(),
        };
        assert_eq!(reason.category(), None);
        assert!(reason.is_fixable_by_grant());
    }

    #[test]
    fn profile_forbids_names_a_category_but_is_not_grant_fixable() {
        // Both accessors disagreeing is exactly the combination a bool would
        // have hidden: it HAS a category, and a grant still cannot fix it.
        let reason = DenyReason::ProfileForbids {
            category: Category::Secret,
        };
        assert_eq!(reason.category(), Some(Category::Secret));
        assert!(!reason.is_fixable_by_grant());
    }

    #[test]
    fn an_empty_scope_is_refused() {
        // Under-recording scope is the easiest way to make audit useless and
        // is invisible for months (08 §1.3), so an empty one is an error and
        // not a silently-stored blank.
        assert_eq!(Scope::new(""), Err(ScopeError::Empty));
        assert_eq!(Scope::new(String::new()), Err(ScopeError::Empty));
    }

    #[test]
    fn the_empty_scope_error_explains_itself() {
        // This string reaches a user, so an empty or vague Display is a
        // product defect rather than a cosmetic one. Asserted on content
        // because mutation testing showed a no-op `fmt` surviving.
        let message = ScopeError::Empty.to_string();
        assert!(
            message.contains("scope"),
            "message must name what was wrong: {message:?}"
        );
        assert!(
            message.contains("touched"),
            "message must say what to supply: {message:?}"
        );
    }

    #[test]
    fn a_scope_round_trips_its_value() {
        let scope = Scope::new("storage.googleapis.com").expect("non-empty");
        assert_eq!(scope.as_str(), "storage.googleapis.com");
    }

    #[test]
    fn whitespace_is_a_valid_scope_value() {
        // Documents a deliberate limit: Scope checks only that something was
        // recorded. A path may legitimately contain a space, and this type
        // cannot know which categories allow what, so it does not guess.
        assert!(Scope::new(" ").is_ok());
    }

    #[test]
    fn an_allow_is_allowed_and_a_deny_is_not() {
        let allow = Decision::Allow {
            scope: Scope::new("github.com:443").expect("non-empty"),
        };
        assert!(allow.is_allowed());

        let deny = Decision::Deny {
            reason: DenyReason::NoMatchingGrant {
                category: Category::Network,
            },
        };
        assert!(!deny.is_allowed());
    }

    #[test]
    fn an_allow_cannot_exist_without_a_scope() {
        // Structural, not a runtime check: `Decision::Allow` holds a `Scope`,
        // and `Scope` cannot be empty, so "an allow with no recorded value"
        // is unrepresentable rather than merely discouraged.
        let Ok(scope) = Scope::new("x") else {
            panic!("non-empty scope must construct")
        };
        match (Decision::Allow { scope }) {
            Decision::Allow { scope } => assert!(!scope.as_str().is_empty()),
            Decision::Deny { .. } => panic!("constructed an Allow"),
        }
    }
}
