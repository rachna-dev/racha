//! Host-mediated networking, and the capability it needs (`15` §7 item 8).
//!
//! `04` §3.2 measured the asymmetry this module exists for. Cloud Hypervisor
//! accepts `--net fd=`, so a tap **we own** can carry every guest packet —
//! which is what makes `00` §3.9's allowlist enforceable rather than
//! advisory. But creating that tap needs `CAP_NET_ADMIN`, and `04` §3.2a
//! narrowed that to **exactly one syscall**:
//!
//! ```text
//! open("/dev/net/tun")        OK      — mode 666, unprivileged
//! ioctl(TUNSETIFF)            EPERM   — needs CAP_NET_ADMIN
//! passing the FD (SCM_RIGHTS) OK      — unprivileged, verified both ways
//! ```
//!
//! So `rachna-netd` holds the capability for one ioctl and hands the
//! descriptor over. Everything else stays unprivileged, which is what makes
//! `06` §7's "a few hundred auditable lines" a real claim.
//!
//! # Why this is a refusal and not a degradation
//!
//! `16` §5.3 is the sharp measurement: without the capability the VM **does
//! not start at all** —
//! `VmBoot(… OpenTap(TapOpen(ConfigureTap(PermissionDenied))))` — rather
//! than starting without network. So a project declaring any network access
//! is unbootable, and the only question is whether the user learns that from
//! us or from a hypervisor backtrace.
//!
//! `00` §3.7 and `01` §3b both forbid the alternative: running with an
//! allowlist nothing enforces. `06` §7's words — *"It refuses rather than
//! running with an unenforced allowlist… the alternative is lying about your
//! security posture."*
//!
//! # macOS needs none of this
//!
//! `02` §7 measured `VZFileHandleNetworkDeviceAttachment` over a plain
//! `socketpair(AF_UNIX, SOCK_DGRAM)` working with **no privileges**. The
//! platforms genuinely differ here, and `06` §7 decided that difference
//! should be visible rather than papered over.

use crate::decision::Category;
use crate::policy::Tier;
use core::fmt;
use std::path::{Path, PathBuf};

/// Whether this host can create the tap that enforces a network policy.
///
/// Three states rather than two, for the same reason
/// [`Outcome`](crate::enforcement::Outcome) has three: *"we checked and it is
/// missing"* and *"we could not check"* are different things to tell a user,
/// and collapsing the second into "present" would start a VM whose
/// enforcement nobody verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// The helper exists and carries `CAP_NET_ADMIN`.
    Present,
    /// The helper exists and does not carry it.
    ///
    /// The common case on a fresh install: `06` §5 puts the `setcap` in a
    /// post-install hook, and a user who built from source has not run one.
    Missing { helper: PathBuf },
    /// The helper is not installed at all.
    ///
    /// Distinct from `Missing` because the fix differs — install the package
    /// versus run one command — and `00` §3.3 requires a message that names
    /// the fix.
    HelperAbsent { looked_for: PathBuf },
    /// The check itself failed.
    Unknown { why: String },
}

impl Capability {
    /// Whether a tap can be created.
    ///
    /// An explicit match so adding a state is a compile error here rather
    /// than silently counting as usable.
    #[must_use]
    pub const fn can_create_tap(&self) -> bool {
        match *self {
            Self::Present => true,
            Self::Missing { .. } | Self::HelperAbsent { .. } | Self::Unknown { .. } => false,
        }
    }
}

/// Why a networked environment cannot start.
///
/// Carries everything the message in `06` §7 needs, so the renderer does not
/// have to re-derive it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unenforceable {
    /// What the policy asked for, in the user's own vocabulary.
    pub wanted: Wanted,
    /// Why the host cannot deliver it.
    pub capability: Capability,
}

/// The part of a policy that needs a tap.
///
/// Two separate reasons, because the message should name the one in the
/// user's config rather than a generic "networking".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wanted {
    /// An enforced network allowlist (`00` §3.9).
    NetworkAllowlist,
    /// A forwarded port.
    ForwardedPort,
}

impl Wanted {
    /// How the user's own config spells this.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NetworkAllowlist => "an enforced network allowlist",
            Self::ForwardedPort => "a forwarded port",
        }
    }

    /// The `rachna.nix` option that asked for it.
    #[must_use]
    pub const fn option(self) -> &'static str {
        match self {
            Self::NetworkAllowlist => "isolation.network.allow",
            Self::ForwardedPort => "ports",
        }
    }
}

impl fmt::Display for Unenforceable {
    /// `06` §7's format, which is the whole point of this type.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Two lines, because one is 87 characters and wraps mid-sentence on
        // an 80-column terminal. `06` §7's own example breaks it the same
        // way, which I only noticed by printing it — the same lesson as the
        // enforcement block's 115-character attempt descriptions.
        writeln!(f, "✗ rachna.nix requires {}, but", self.wanted.as_str())?;
        writeln!(f, "  this host cannot enforce it.")?;
        writeln!(f)?;
        match &self.capability {
            // Unreachable when constructed from `check`, and written out
            // rather than left to a wildcard so adding a state is a compile
            // error here instead of printing nothing.
            Capability::Present => {
                writeln!(f, "  (this host can enforce it — nothing to report)")?;
            }
            Capability::Missing { helper } => {
                writeln!(f, "  CAP_NET_ADMIN is missing from {}", helper.display())?;
                writeln!(f)?;
                writeln!(f, "      sudo setcap cap_net_admin+ep {}", helper.display())?;
            }
            Capability::HelperAbsent { looked_for } => {
                writeln!(
                    f,
                    "  rachna-netd is not installed (looked in {})",
                    looked_for.display()
                )?;
                writeln!(f)?;
                writeln!(f, "  install the rachna package, which sets the")?;
                writeln!(f, "  capability in its post-install hook")?;
            }
            Capability::Unknown { why } => {
                writeln!(f, "  the capability could not be checked: {why}")?;
                writeln!(f)?;
                writeln!(f, "      rachna doctor")?;
            }
        }
        writeln!(f)?;
        writeln!(
            f,
            "  Rachna will not start with a policy it cannot enforce. Remove"
        )?;
        writeln!(
            f,
            "  {} from rachna.nix to run without network.",
            self.wanted.option()
        )
    }
}

impl core::error::Error for Unenforceable {}

/// Whether a policy needs a tap at all.
///
/// `Tier::None` denies every host, so a guest under it has nothing to
/// enforce and needs no tap — which means **a sealed project starts fine on a
/// host with no capability**. That is not a detail: it is most of what makes
/// the refusal acceptable, because the common case (`20`'s project shapes
/// declare 1–2 hosts) is not the only case.
#[must_use]
pub fn needs_tap(tier: Tier, forwarded_ports: usize) -> Option<Wanted> {
    if forwarded_ports > 0 {
        // Checked first because `16` §5.3's measurement is about the VM not
        // booting, and a forwarded port needs the tap whatever the tier says
        // about outbound hosts.
        return Some(Wanted::ForwardedPort);
    }
    if tier.permits_any_network() {
        return Some(Wanted::NetworkAllowlist);
    }
    None
}

/// Whether `policy` can run on a host with this `capability`.
///
/// # Errors
///
/// [`Unenforceable`] when the policy needs a tap the host cannot create.
/// Deliberately an error rather than a downgraded policy: `16` §5.3 measured
/// that the VM would not boot anyway, so the only choice is whether the user
/// gets our sentence or Cloud Hypervisor's `ConfigureTap(PermissionDenied)`.
pub fn check(
    tier: Tier,
    forwarded_ports: usize,
    capability: &Capability,
) -> Result<(), Unenforceable> {
    let Some(wanted) = needs_tap(tier, forwarded_ports) else {
        // Nothing to enforce, so the capability is irrelevant.
        return Ok(());
    };
    if capability.can_create_tap() {
        return Ok(());
    }
    Err(Unenforceable {
        wanted,
        capability: capability.clone(),
    })
}

/// The category a tap failure denies, for the audit trail.
///
/// `01` §2.7 makes the proxy's decisions `Decision`s; this is the same rule
/// one layer down, so a refused start is attributable rather than only
/// printed.
#[must_use]
pub const fn denied_category() -> Category {
    Category::Network
}

/// Where the helper is looked for, in order.
///
/// A list rather than one path because `06` §5 installs it via a package
/// manager while a developer runs it from a build directory, and a check
/// that only knew the packaged location would tell every contributor their
/// install is broken.
#[must_use]
pub fn helper_search_paths(install_prefix: &Path, build_dir: &Path) -> Vec<PathBuf> {
    vec![
        install_prefix.join("bin").join(HELPER_NAME),
        build_dir.join(HELPER_NAME),
    ]
}

/// The helper's name, in one place.
pub const HELPER_NAME: &str = "rachna-netd";

#[cfg(test)]
mod tests {
    use super::*;

    fn helper() -> PathBuf {
        PathBuf::from("/usr/local/bin/rachna-netd")
    }

    // ---- when a tap is needed at all -------------------------------------

    #[test]
    fn a_sealed_project_needs_no_tap_and_starts_without_the_capability() {
        // Most of what makes the refusal acceptable. `Tier::None` denies
        // every host, so there is nothing to enforce — and a project that
        // wants no network must not be blocked by a capability it does not
        // use.
        assert_eq!(needs_tap(Tier::None, 0), None);
        assert_eq!(
            check(Tier::None, 0, &Capability::Missing { helper: helper() }),
            Ok(())
        );
    }

    #[test]
    fn any_tier_that_permits_a_host_needs_the_tap() {
        // Driven by `Tier::ALL` so a new tier cannot be added without
        // deciding this — and the answer comes from `permits_any_network`
        // rather than a second list, which is the `decide.rs`-owns-policy
        // rule.
        for tier in Tier::ALL {
            let expected = if tier.permits_any_network() {
                Some(Wanted::NetworkAllowlist)
            } else {
                None
            };
            assert_eq!(
                needs_tap(tier, 0),
                expected,
                "{tier:?} disagreed with permits_any_network"
            );
        }
    }

    #[test]
    fn a_forwarded_port_needs_the_tap_even_when_the_tier_denies_outbound() {
        // `16` §5.3's measurement is that the VM does not BOOT, and a
        // forwarded port needs the tap whatever the tier says about
        // outbound hosts. A check that only looked at the tier would let a
        // sealed-with-a-port project reach the hypervisor's own error.
        assert_eq!(needs_tap(Tier::None, 1), Some(Wanted::ForwardedPort));
        assert!(
            check(Tier::None, 1, &Capability::Missing { helper: helper() }).is_err(),
            "a sealed project with a forwarded port was allowed to start"
        );
    }

    // ---- only a present capability permits -------------------------------

    #[test]
    fn only_a_present_capability_can_create_a_tap() {
        // Both directions, per AGENTS.md: a gate asserted only negatively is
        // indistinguishable from one that always refuses, which would block
        // every networked project on a correctly configured host.
        assert!(Capability::Present.can_create_tap());
        assert!(!Capability::Missing { helper: helper() }.can_create_tap());
        assert!(!Capability::HelperAbsent {
            looked_for: helper()
        }
        .can_create_tap());
        assert!(!Capability::Unknown {
            why: "getcap not found".to_owned()
        }
        .can_create_tap());
    }

    #[test]
    fn a_present_capability_starts_a_networked_project() {
        // The positive path for `check` itself, not only for the predicate.
        assert_eq!(check(Tier::Allowlist, 0, &Capability::Present), Ok(()));
        assert_eq!(check(Tier::Allowlist, 3, &Capability::Present), Ok(()));
    }

    #[test]
    fn an_unknown_capability_refuses_rather_than_assuming_the_best() {
        // The dangerous direction. "We could not check" must not start a VM
        // whose enforcement nobody verified — the same rule as
        // `enforcement::Outcome::Inconclusive`, and this project has three
        // recorded false-negative measurements behind it (`11` §7, `13` §2).
        let error = check(
            Tier::Allowlist,
            0,
            &Capability::Unknown {
                why: "getcap is not on PATH".to_owned(),
            },
        )
        .expect_err("an unverified capability must refuse");
        let text = error.to_string();
        assert!(text.contains("could not be checked"), "{text}");
        assert!(text.contains("getcap is not on PATH"), "{text}");
    }

    // ---- the message 06 §7 specifies -------------------------------------

    #[test]
    fn no_line_of_a_refusal_wraps_on_an_eighty_column_terminal() {
        // Measured, not guessed: the first version's opening line was 87
        // characters and broke mid-sentence. `06` §7's own example wraps it
        // across two lines for this reason, and printing the block is what
        // caught it — the same lesson as `enforcement.rs`'s 115-character
        // attempt descriptions.
        for capability in [
            Capability::Missing { helper: helper() },
            Capability::HelperAbsent {
                looked_for: helper(),
            },
            Capability::Unknown {
                why: "getcap is not on PATH".to_owned(),
            },
        ] {
            for wanted in [Wanted::NetworkAllowlist, Wanted::ForwardedPort] {
                let text = Unenforceable {
                    wanted,
                    capability: capability.clone(),
                }
                .to_string();
                for line in text.lines() {
                    assert!(
                        line.chars().count() <= 76,
                        "{} chars will wrap: {line:?}",
                        line.chars().count()
                    );
                }
            }
        }
    }

    #[test]
    fn the_refusal_names_the_option_the_fix_and_the_way_out() {
        // `06` §7's format. `00` §3.3's rules apply: a message that does not
        // name the fix sends the user to a search engine, and this one has
        // three things to say — what asked, what is missing, and what to do.
        let error = check(
            Tier::Allowlist,
            0,
            &Capability::Missing { helper: helper() },
        )
        .expect_err("a missing capability must refuse");
        let text = error.to_string();

        assert!(text.contains("enforced network allowlist"), "{text}");
        assert!(text.contains("CAP_NET_ADMIN is missing"), "{text}");
        // The exact command, with the real path rather than a placeholder.
        assert!(
            text.contains("sudo setcap cap_net_admin+ep /usr/local/bin/rachna-netd"),
            "{text}"
        );
        // And the way out for a user who does not want to grant it, naming
        // the option in their file rather than "networking".
        assert!(text.contains("isolation.network.allow"), "{text}");
        assert!(text.contains("will not start"), "{text}");
    }

    #[test]
    fn a_forwarded_port_refusal_names_ports_not_the_allowlist() {
        // The message must name what is in the user's config. Telling
        // someone whose `ports` declaration caused this to remove
        // `isolation.network.allow` would send them to edit the wrong line.
        let text = check(Tier::None, 1, &Capability::Missing { helper: helper() })
            .expect_err("must refuse")
            .to_string();
        assert!(text.contains("a forwarded port"), "{text}");
        assert!(text.contains("ports"), "{text}");
        assert!(
            !text.contains("isolation.network.allow"),
            "a port problem blamed the allowlist: {text}"
        );
    }

    #[test]
    fn a_missing_helper_and_a_missing_capability_say_different_things() {
        // Different fixes — install a package versus run one command — so a
        // message that could not tell them apart would be wrong half the
        // time.
        let absent = check(
            Tier::Allowlist,
            0,
            &Capability::HelperAbsent {
                looked_for: helper(),
            },
        )
        .expect_err("must refuse")
        .to_string();
        let uncapped = check(
            Tier::Allowlist,
            0,
            &Capability::Missing { helper: helper() },
        )
        .expect_err("must refuse")
        .to_string();

        assert!(absent.contains("not installed"), "{absent}");
        assert!(!absent.contains("setcap"), "told to setcap a missing file");
        assert!(uncapped.contains("setcap"), "{uncapped}");
        assert_ne!(absent, uncapped);
    }

    // ---- where the helper is looked for ----------------------------------

    #[test]
    fn the_helper_is_looked_for_where_a_package_and_a_build_both_put_it() {
        // `06` §5 installs via a package manager; a contributor runs from a
        // build directory. A check knowing only the packaged path would tell
        // every contributor their install is broken.
        let paths = helper_search_paths(Path::new("/usr/local"), Path::new("/repo/target/debug"));
        assert_eq!(
            paths,
            [
                PathBuf::from("/usr/local/bin/rachna-netd"),
                PathBuf::from("/repo/target/debug/rachna-netd"),
            ]
        );
        // The installed location comes first, so a stale build artifact
        // cannot shadow the packaged helper that actually has the
        // capability.
        assert!(paths[0].starts_with("/usr/local"));
    }

    #[test]
    fn the_helper_has_one_name() {
        // Used by the search paths, the error messages and the install hook.
        // Three spellings is how `kind = "command"` came to be documented and
        // rejected (`21` §2.5).
        assert_eq!(HELPER_NAME, "rachna-netd");
        for path in helper_search_paths(Path::new("/p"), Path::new("/b")) {
            assert!(path.ends_with(HELPER_NAME));
        }
    }

    #[test]
    fn a_tap_refusal_is_attributable_to_the_network_category() {
        // `01` §2.7: these decisions land in the audit trail like any other,
        // so a refused start is attributable rather than only printed.
        assert_eq!(denied_category(), Category::Network);
    }
}
