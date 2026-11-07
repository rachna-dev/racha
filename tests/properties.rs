//! Property tests for the pure policy engine.
//!
//! `01-ARCHITECTURE.md` §4 lists these as a distinct instrument from mutation
//! testing, and the distinction is real: mutants prove the suite *reacts* to a
//! behaviour change, while properties explore inputs nobody thought to write
//! down. Both engine functions are pure, so there is nothing to mock.
//!
//! An integration test rather than a `#[cfg(test)]` module, so it exercises
//! only the public API — if a property needs a private detail, the API is
//! wrong.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use rachna::decide::{decide, Capabilities, Policy};
use rachna::decision::{Access, Category, Decision};
use rachna::grant::{Endpoint, Grant, Request};
use rachna::policy::{Profile, Tier};
use rachna::summary::AccessSummary;
use rachna::synthesize::{synthesize, Evidence, Observations, Threshold};
use std::path::PathBuf;

/// Hostname-ish strings, including the shapes that have caused real bugs:
/// leading dots, embedded stars, and a bare star.
fn host() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z]{1,8}(\\.[a-z]{1,8}){0,3}",
        "\\*\\.[a-z]{1,8}(\\.[a-z]{1,8}){0,2}",
        Just("*".to_owned()),
        Just(".example.com".to_owned()),
        Just("example.com.".to_owned()),
    ]
}

fn endpoint() -> impl Strategy<Value = Endpoint> {
    (host(), any::<u16>()).prop_map(|(h, p)| Endpoint::new(h, p).expect("hosts are non-empty"))
}

/// Absolute-ish paths, including traversal and a bare root.
fn path() -> impl Strategy<Value = PathBuf> {
    prop_oneof![
        "(/[a-z]{1,6}){1,4}".prop_map(PathBuf::from),
        "(/[a-z]{1,6}){1,3}/\\.\\./[a-z]{1,6}".prop_map(PathBuf::from),
        Just(PathBuf::from("/")),
    ]
}

fn access() -> impl Strategy<Value = Access> {
    prop_oneof![Just(Access::ReadOnly), Just(Access::ReadWrite)]
}

fn request() -> impl Strategy<Value = Request> {
    prop_oneof![
        (endpoint(), any::<bool>()).prop_map(|(endpoint, literal_address)| Request::Network {
            endpoint,
            literal_address
        }),
        (path(), access()).prop_map(|(path, access)| Request::Filesystem { path, access }),
        "[a-z-]{1,12}".prop_map(|name| Request::Tool { name }),
        any::<u16>().prop_map(|guest| Request::Port { guest }),
        "[a-z]{1,8}".prop_map(|name| Request::Secret { name }),
    ]
}

fn grant() -> impl Strategy<Value = Grant> {
    prop_oneof![
        endpoint().prop_map(|endpoint| Grant::Network { endpoint }),
        (path(), access()).prop_map(|(path, access)| Grant::Filesystem { path, access }),
        any::<u16>().prop_map(|guest| Grant::Port { guest, host: guest }),
        "[a-z]{1,8}".prop_map(|name| Grant::Secret { name }),
    ]
}

fn tier() -> impl Strategy<Value = Tier> {
    prop_oneof![
        Just(Tier::Open),
        Just(Tier::Internet),
        Just(Tier::Allowlist),
        Just(Tier::None)
    ]
}

fn profile() -> impl Strategy<Value = Profile> {
    prop_oneof![
        Just(Profile::Sealed),
        Just(Profile::Development),
        Just(Profile::Online)
    ]
}

const AMPLE: Evidence = Evidence {
    days: 30,
    runs: 100,
};

proptest! {
    /// An empty policy denies everything, for any request at all.
    ///
    /// Deny-by-default is the product's central claim, so it is asserted over
    /// generated input rather than a hand-written list of five.
    #[test]
    fn deny_all_denies_every_request(request in request()) {
        let decision = decide(&Policy::deny_all(), &request);
        prop_assert!(!decision.is_allowed(), "{request:?} slipped past deny_all");
    }

    /// Every allow records a non-empty scope.
    ///
    /// Under-recording scope is the easiest way to make audit useless, and it
    /// is invisible for months (`08` §1.3). No input may produce an allow
    /// without one.
    #[test]
    fn an_allow_always_carries_a_scope(
        request in request(),
        tier in tier(),
        profile in profile(),
        grants in prop::collection::vec(grant(), 0..6),
    ) {
        let policy = Policy { tier, profile, grants, capabilities: Capabilities::all() };
        if let Decision::Allow { scope } = decide(&policy, &request) {
            prop_assert!(!scope.as_str().is_empty());
        }
    }

    /// `decide` is deterministic: same inputs, same answer.
    ///
    /// The engine is specified as pure — no clock, no randomness (`08` §1.1) —
    /// and a decision that varied between calls would make the audit trail a
    /// fiction.
    #[test]
    fn decide_is_deterministic(
        request in request(),
        tier in tier(),
        profile in profile(),
        grants in prop::collection::vec(grant(), 0..4),
    ) {
        let policy = Policy { tier, profile, grants, capabilities: Capabilities::all() };
        prop_assert_eq!(decide(&policy, &request), decide(&policy, &request));
    }

    /// A category the backend cannot enforce is never allowed.
    ///
    /// A rule the backend cannot enforce must not behave like a rule that is
    /// simply absent, or the config file lies (`01` §3b).
    #[test]
    fn an_unenforceable_category_is_never_allowed(request in request(), tier in tier()) {
        let category = request.category();
        let policy = Policy {
            tier,
            profile: Profile::Online,
            // Grant generously: the capability check must still win.
            grants: vec![
                Grant::Network { endpoint: Endpoint::new("*", 0).unwrap() },
                Grant::Filesystem { path: PathBuf::from("/"), access: Access::ReadWrite },
                Grant::Port { guest: 0, host: 0 },
            ],
            capabilities: Capabilities::lacking([category]),
        };
        prop_assert!(!decide(&policy, &request).is_allowed());
    }

    /// Round trip: everything observed stays permitted by what was synthesized.
    ///
    /// A narrowing that breaks a working project is worse than no narrowing.
    /// The hand-written test checks one case; this holds it for arbitrary
    /// observation sets.
    #[test]
    fn synthesized_grants_still_permit_every_observation(
        observed in prop::collection::vec(request(), 1..12),
    ) {
        let grants = synthesize(&Observations::new(observed.clone(), AMPLE), Threshold::DEFAULT)
            .expect("ample evidence clears the threshold");
        let policy = Policy {
            // Allowlist, not open: the grants must do the work, not the tier.
            tier: Tier::Allowlist,
            profile: Profile::Online,
            grants,
            capabilities: Capabilities::all(),
        };
        for request in &observed {
            // Two observations cannot round-trip, and both exclusions are
            // behaviour the engine is SUPPOSED to have:
            //
            // 1. A literal address on an allowlist is refused by design
            //    (`02` §7) regardless of grants.
            // 2. A wildcard-shaped host is dropped by `synthesize` rather
            //    than echoed into a grant, because echoing it would widen the
            //    policy. The round-trip property must not demand the unsafe
            //    behaviour: when the two properties conflict, not widening
            //    wins. (This conflict was surfaced by the wildcard property
            //    failing first — see src/synthesize.rs::network_grants.)
            match request {
                Request::Network { literal_address: true, .. } => continue,
                Request::Network { endpoint, .. } if endpoint.is_wildcard() => continue,
                _ => {}
            }
            prop_assert!(
                decide(&policy, request).is_allowed(),
                "synthesized policy refused an observation it came from: {request:?}",
            );
        }
    }

    /// `synthesize` never emits a wildcard.
    ///
    /// Rule 1 of `08` §1.4: a wildcard is broader than any finite set of
    /// observations, so emitting one would widen the policy while claiming to
    /// narrow it — even when the observations themselves contained wildcards.
    #[test]
    fn synthesize_never_widens_to_a_wildcard(
        observed in prop::collection::vec(request(), 0..12),
    ) {
        let grants = synthesize(&Observations::new(observed, AMPLE), Threshold::DEFAULT)
            .expect("ample evidence clears the threshold");
        for grant in grants {
            if let Grant::Network { endpoint } = grant {
                prop_assert!(!endpoint.is_wildcard(), "synthesized a wildcard: {endpoint}");
            }
        }
    }

    /// Below the threshold, nothing is ever suggested.
    ///
    /// The `08` §3.4 defence: malware can forge silence, so thin evidence must
    /// never become advice.
    #[test]
    fn thin_evidence_never_yields_a_suggestion(
        observed in prop::collection::vec(request(), 0..12),
        days in 0u32..14,
        runs in 0u32..50,
    ) {
        let observations = Observations::new(observed, Evidence { days, runs });
        prop_assert!(synthesize(&observations, Threshold::DEFAULT).is_err());
    }

    /// Tier permissiveness is transitive.
    #[test]
    fn tier_permissiveness_is_transitive(a in tier(), b in tier(), c in tier()) {
        if a.is_at_least_as_permissive_as(b) && b.is_at_least_as_permissive_as(c) {
            prop_assert!(a.is_at_least_as_permissive_as(c));
        }
    }

    /// Access coverage is reflexive, and antisymmetric where it should be.
    #[test]
    fn access_coverage_is_well_behaved(a in access(), b in access()) {
        prop_assert!(a.covers(a));
        if a.covers(b) && b.covers(a) {
            prop_assert_eq!(a, b);
        }
    }

    /// The access summary names every category, for any config.
    ///
    /// A category missing from the output is a grant the user believes they do
    /// not have (`00` §3.10c). This must hold for arbitrary grant sets, not
    /// just the ones in the unit tests.
    #[test]
    fn the_summary_always_names_every_category(
        tier in tier(),
        profile in profile(),
        grants in prop::collection::vec(grant(), 0..10),
    ) {
        let rendered = AccessSummary::new(tier, profile, &grants).to_string();
        for category in Category::ALL {
            prop_assert!(
                rendered.contains(category.as_str()),
                "{category} missing from summary:\n{rendered}",
            );
        }
    }

    /// The summary fingerprint ignores grant order and duplication.
    ///
    /// Reformatting or reordering `rachna.nix` must not re-gate, or the
    /// acknowledgement becomes noise people learn to alias away.
    #[test]
    fn the_fingerprint_ignores_order_and_duplicates(
        tier in tier(),
        profile in profile(),
        grants in prop::collection::vec(grant(), 1..8),
    ) {
        let mut shuffled: Vec<_> = grants.iter().rev().cloned().collect();
        shuffled.extend(grants.iter().cloned());  // every grant twice, reversed first
        prop_assert_eq!(
            AccessSummary::new(tier, profile, &grants).fingerprint(),
            AccessSummary::new(tier, profile, &shuffled).fingerprint(),
        );
    }

    /// The summary never claims access that `decide` would refuse.
    ///
    /// The summary exists so a user can accept a config knowing what it
    /// grants (`00` §3.10c). If it lists a permission the engine then denies,
    /// the user accepted on a false basis — the more dangerous direction of
    /// the completeness property, and the bug the profile fix closed.
    #[test]
    fn the_summary_never_overstates_what_decide_permits(
        tier in tier(),
        profile in profile(),
        grants in prop::collection::vec(grant(), 0..8),
    ) {
        let rendered = AccessSummary::new(tier, profile, &grants).to_string();
        let policy = Policy {
            tier,
            profile,
            grants: grants.clone(),
            capabilities: Capabilities::all(),
        };

        // For every grant, ask the ENGINE whether the thing it names is
        // actually permitted, then require the summary not to claim it is.
        // Going through `decide` rather than re-deriving the rule is the point:
        // a reimplementation here could agree with a buggy summary.
        for grant in &grants {
            let probe = match grant {
                Grant::Secret { name } => Request::Secret { name: name.clone() },
                Grant::Port { guest, .. } => Request::Port { guest: *guest },
                // Network and filesystem grants are patterns, so a request
                // derived from one is not necessarily the same act; those are
                // covered by decide's own tests.
                Grant::Network { .. } | Grant::Filesystem { .. } | Grant::Tool { .. } => continue,
            };
            if decide(&policy, &probe).is_allowed() {
                continue;  // the summary may list it; the engine agrees
            }
            // The engine refuses it, so the summary must not present it as
            // granted. Checked on that CATEGORY's own line rather than by
            // searching the whole rendering: a first draft used a bare
            // `contains`, and a one-character secret name matched "any host"
            // and "sealed" elsewhere in the output — a false positive that
            // made a correct summary look broken.
            let line = rendered
                .lines()
                .find(|l| l.trim_start().starts_with(grant.category().as_str()))
                .unwrap_or("");
            prop_assert!(
                line.contains("none"),
                "summary presents a {} grant that decide refuses:\n{rendered}",
                grant.category(),
            );
        }
    }

    /// A profile never claims authority over the network axis.
    ///
    /// Network belongs to `Tier` (`00` §3.9); a profile answering for it would
    /// reintroduce the conflation the two-axis split exists to remove.
    #[test]
    fn no_profile_forbids_network(profile in profile()) {
        prop_assert!(!profile.forbids(Category::Network));
    }
}
