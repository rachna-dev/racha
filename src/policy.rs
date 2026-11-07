//! The two independent axes a `rachna.nix` declares, and what they govern.
//!
//! `00-PRODUCT.md` §3.9 is the specification, and the split it describes is
//! load-bearing rather than cosmetic: the original design had three profiles
//! covering everything, so changing the network posture meant also accepting a
//! change to filesystem, device and credential access. Separating them is
//! adopted from `devvm`.
//!
//! The axes differ in a way the types should carry:
//!
//! - [`Tier`] is **ordered**. `open` ⊃ `internet` ⊃ `allowlist` ⊃ `none`, so
//!   "is this at least as permissive as that" is a meaningful question and
//!   `Ord` answers it.
//! - [`Profile`] is **not ordered**. It selects a posture across several
//!   unrelated concerns, so no single comparison is meaningful and deriving
//!   `Ord` would invite a wrong one.

use crate::decision::Category;
use core::fmt;

/// How much network the project may reach. **An ordered axis.**
///
/// Variants are declared most- to least-permissive so the derived [`Ord`]
/// matches the permissiveness ordering, making `>=` a correct permissiveness
/// test rather than an accident of declaration order. Pinned by test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Tier {
    /// Everything, including the local network and link-local addresses.
    Open,
    /// The public internet, but not the host's private networks.
    Internet,
    /// Only the hosts named by a grant.
    Allowlist,
    /// No network at all.
    None,
}

impl Tier {
    /// Every tier, most-permissive first.
    pub const ALL: [Self; 4] = [Self::Open, Self::Internet, Self::Allowlist, Self::None];

    /// The word used in `rachna.nix` and on the CLI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Internet => "internet",
            Self::Allowlist => "allowlist",
            Self::None => "none",
        }
    }

    /// Whether this tier is at least as permissive as `other`.
    ///
    /// Used to explain near-misses — *"`internet` would allow this; you are on
    /// `allowlist`"* (`00-PRODUCT.md` §3.3) — so it must agree with the
    /// declaration order rather than merely look like it does.
    #[must_use]
    pub fn is_at_least_as_permissive_as(self, other: Self) -> bool {
        self <= other
    }

    /// Whether any network request can be permitted at this tier.
    ///
    /// [`Self::None`] denies before any grant is consulted, which is why it is
    /// a tier rather than an empty allowlist: an empty allowlist is a config a
    /// grant could change, and `none` is a decision.
    #[must_use]
    pub const fn permits_any_network(self) -> bool {
        !matches!(self, Self::None)
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The posture for everything that is not network. **Not an ordered axis.**
///
/// Deliberately no [`Ord`]: it governs filesystem, devices, credentials and
/// IPC at once, and those do not vary together along one line. A derived
/// ordering would let `profile_a > profile_b` compile and mean nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// Nothing beyond the workspace. No devices, no credentials, no IPC.
    Sealed,
    /// The default: the workspace plus what development normally needs.
    Development,
    /// Development, plus the credential and IPC access online work implies.
    Online,
}

impl Profile {
    /// Every profile.
    pub const ALL: [Self; 3] = [Self::Sealed, Self::Development, Self::Online];

    /// The word used in `rachna.nix` and on the CLI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Development => "development",
            Self::Online => "online",
        }
    }

    /// Whether this profile forbids `category` outright.
    ///
    /// This is step 1 of the matching order (`08-POLICY-AND-STORE.md` §1.2):
    /// a profile refusal precedes every grant lookup, so a grant cannot
    /// re-open what the profile closed.
    ///
    /// [`Category::Network`] is never forbidden here — that axis is [`Tier`]'s
    /// (`00-PRODUCT.md` §3.9), and answering for it would reintroduce exactly
    /// the conflation the split removed.
    #[must_use]
    pub const fn forbids(self, category: Category) -> bool {
        match (self, category) {
            (_, Category::Network) => false,
            // Sealed means the workspace and nothing else.
            (Self::Sealed, Category::Secret | Category::Port) => true,
            (Self::Sealed, Category::Filesystem | Category::Tool) => false,
            // Development withholds credentials; online is what grants them.
            (Self::Development, Category::Secret) => true,
            (Self::Development, Category::Filesystem | Category::Tool | Category::Port) => false,
            (Self::Online, _) => false,
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Default for Profile {
    /// [`Profile::Development`], per `00-PRODUCT.md` §3.9.
    fn default() -> Self {
        Self::Development
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_declaration_order_is_the_permissiveness_order() {
        // The derived Ord is only correct because of declaration order, which
        // a refactor could silently change. This pins the claim rather than
        // trusting the comment above the enum.
        assert!(Tier::Open < Tier::Internet);
        assert!(Tier::Internet < Tier::Allowlist);
        assert!(Tier::Allowlist < Tier::None);

        // And ALL is in that same order.
        let mut sorted = Tier::ALL;
        sorted.sort_unstable();
        assert_eq!(sorted, Tier::ALL, "ALL must be most-permissive first");
    }

    #[test]
    fn permissiveness_is_reflexive_and_transitive_across_every_pair() {
        for a in Tier::ALL {
            assert!(a.is_at_least_as_permissive_as(a), "{a} must cover itself");
        }
        // Open covers everything; nothing but None covers None.
        for t in Tier::ALL {
            assert!(Tier::Open.is_at_least_as_permissive_as(t));
            assert!(t.is_at_least_as_permissive_as(Tier::None));
        }
        // The asymmetry that matters: allowlist does NOT cover internet.
        assert!(!Tier::Allowlist.is_at_least_as_permissive_as(Tier::Internet));
    }

    #[test]
    fn only_none_denies_network_before_any_grant() {
        for tier in Tier::ALL {
            assert_eq!(
                tier.permits_any_network(),
                tier != Tier::None,
                "{tier} disagrees with its variant"
            );
        }
    }

    #[test]
    fn profile_never_answers_for_network() {
        // Network belongs to Tier (00 §3.9). A profile answering here would
        // reintroduce the conflation the two-axis split exists to remove.
        for profile in Profile::ALL {
            assert!(
                !profile.forbids(Category::Network),
                "{profile} claimed authority over network"
            );
        }
    }

    #[test]
    fn sealed_forbids_strictly_more_than_development_which_forbids_more_than_online() {
        // Profile is deliberately not Ord, but the three shipped values DO
        // happen to nest for the categories they govern. Asserted as a
        // property over every category rather than spot-checked, so adding a
        // category cannot quietly break the nesting.
        for category in Category::ALL {
            if category == Category::Network {
                continue;
            }
            if Profile::Development.forbids(category) {
                assert!(
                    Profile::Sealed.forbids(category),
                    "sealed must forbid {category} if development does"
                );
            }
            if Profile::Online.forbids(category) {
                assert!(
                    Profile::Development.forbids(category),
                    "development must forbid {category} if online does"
                );
            }
        }
    }

    #[test]
    fn online_forbids_nothing_and_sealed_forbids_something() {
        // Guards against a `forbids` that accidentally returns a constant —
        // the two ends of the range must differ.
        assert!(
            Category::ALL.iter().all(|c| !Profile::Online.forbids(*c)),
            "online is the permissive end"
        );
        assert!(
            Category::ALL.iter().any(|c| Profile::Sealed.forbids(*c)),
            "sealed must actually forbid something"
        );
    }

    #[test]
    fn credentials_need_the_online_profile() {
        // The specific rule behind the nesting: only `online` grants secrets.
        assert!(Profile::Sealed.forbids(Category::Secret));
        assert!(Profile::Development.forbids(Category::Secret));
        assert!(!Profile::Online.forbids(Category::Secret));
    }

    #[test]
    fn the_default_profile_is_development() {
        assert_eq!(Profile::default(), Profile::Development);
    }

    #[test]
    fn axis_names_are_distinct_within_each_axis() {
        // These strings are written into rachna.nix, so a collision would make
        // two values indistinguishable on disk.
        let mut tiers: Vec<&str> = Tier::ALL.iter().map(|t| t.as_str()).collect();
        let n = tiers.len();
        tiers.sort_unstable();
        tiers.dedup();
        assert_eq!(tiers.len(), n, "two tiers share a name");

        let mut profiles: Vec<&str> = Profile::ALL.iter().map(|p| p.as_str()).collect();
        let m = profiles.len();
        profiles.sort_unstable();
        profiles.dedup();
        assert_eq!(profiles.len(), m, "two profiles share a name");
    }

    #[test]
    fn display_agrees_with_as_str_on_both_axes() {
        for tier in Tier::ALL {
            assert_eq!(tier.to_string(), tier.as_str());
        }
        for profile in Profile::ALL {
            assert_eq!(profile.to_string(), profile.as_str());
        }
    }

    #[test]
    fn names_are_pinned_against_silent_renames() {
        // A rename here invalidates every rachna.nix in existence.
        assert_eq!(Tier::Allowlist.as_str(), "allowlist");
        assert_eq!(Profile::Development.as_str(), "development");
    }
}
