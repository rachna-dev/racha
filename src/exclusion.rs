//! The mount exclusion check: does anything inside a share reach a file that
//! must stay outside it?
//!
//! `00-PRODUCT.md` §3.11 requires `rachna.nix` to be invisible to the guest,
//! because a guest that can edit its own policy has no policy. Excluding it
//! **by path** is not enough, and that is measured rather than assumed:
//!
//! | Attack | Measured |
//! |---|---|
//! | a hardlink inside the share pointing at the excluded file | ✅ succeeded (`13` §4) |
//! | `RACHNA.NIX` on a case-insensitive filesystem | ✅ succeeded (`12` §3) |
//!
//! Both defeat a name comparison, and **both are defeated by comparing
//! identity instead** — `(st_dev, st_ino)`. A hardlink *is* the same inode by
//! definition, and a case variant resolves to it, so one check closes both
//! (`14` §4).
//!
//! # Why this module holds no I/O
//!
//! The comparison is pure: it takes already-collected identities and decides.
//! Walking the tree and calling `stat` belongs to the backend, which is what
//! lets the security-critical decision be table-tested with no filesystem
//! (`01-ARCHITECTURE.md` §4). The cost is that the caller must collect
//! honestly, so [`Verdict`] names what it relied on.

use core::fmt;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A file's identity on a filesystem: the pair that a name cannot forge.
///
/// Two paths with the same [`FileId`] are the same file, whatever they are
/// called and however many links point at them. This is the whole mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileId {
    /// `st_dev` — which filesystem.
    pub device: u64,
    /// `st_ino` — which file on it.
    pub inode: u64,
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dev {} inode {}", self.device, self.inode)
    }
}

/// One entry found inside a share, with the facts the check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEntry {
    /// Where it was found, for the error message.
    pub path: PathBuf,
    /// Its identity.
    pub id: FileId,
    /// `st_nlink`. More than one means another name points at this file.
    pub links: u64,
}

/// Why a mount was refused.
///
/// Each variant names a *measured* attack rather than a hypothetical, so a
/// reader can trace it to the spike that found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// An entry inside the share is the same file as an excluded one.
    ///
    /// Covers the hardlink attack (`13` §4) and the case-variant attack
    /// (`12` §3): both produce a different name for the same inode.
    ReachesExcludedFile {
        /// The name inside the share. Deliberately reported — the attacker
        /// chose it, so it is evidence, and `14` §3 notes the name itself
        /// gives nothing away.
        entry: PathBuf,
        /// The identity it shares with something excluded.
        id: FileId,
    },
    /// An entry lives on a different filesystem than the share root.
    ///
    /// A mount point or bind inside the workspace that should not be there
    /// (`14` §3 step 3). Refused because the exclusion set was resolved
    /// against the share's own device, so an entry elsewhere was never
    /// checked against anything.
    CrossesFilesystem {
        entry: PathBuf,
        entry_device: u64,
        share_device: u64,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReachesExcludedFile { entry, id } => write!(
                f,
                "{} is the same file as an excluded one ({id}), so mounting \
                 this share would expose it",
                entry.display()
            ),
            Self::CrossesFilesystem {
                entry,
                entry_device,
                share_device,
            } => write!(
                f,
                "{} is on device {entry_device}, not the share's device \
                 {share_device} — a mount point inside the workspace",
                entry.display()
            ),
        }
    }
}

impl core::error::Error for Refusal {}

/// The result of checking a share, and what the check was able to rely on.
///
/// Carries the inputs it used so a caller cannot report "safe" for a check
/// that examined nothing. A walk that silently skipped an unreadable
/// directory, or an exclusion set that failed to resolve, is the difference
/// between a verdict and a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    refusals: Vec<Refusal>,
    entries_examined: usize,
    excluded_resolved: usize,
}

impl Verdict {
    /// Whether the share may be mounted.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.refusals.is_empty()
    }

    /// Every reason the share was refused.
    ///
    /// All of them, not the first: a user fixing one hardlink should not have
    /// to re-run to discover the second, which is the same batch-reporting
    /// principle as the denial report (`00-PRODUCT.md` §3.3).
    #[must_use]
    pub fn refusals(&self) -> &[Refusal] {
        &self.refusals
    }

    /// How many share entries the check examined.
    #[must_use]
    pub const fn entries_examined(&self) -> usize {
        self.entries_examined
    }

    /// How many excluded paths were resolved to an identity.
    ///
    /// **Zero means the check could not protect anything**, even though it
    /// will report no refusals. A caller must treat that as a failure rather
    /// than a pass — [`Self::is_vacuous`] says so directly.
    #[must_use]
    pub const fn excluded_resolved(&self) -> usize {
        self.excluded_resolved
    }

    /// Whether this verdict proves nothing.
    ///
    /// True when no excluded identity was supplied: there was nothing to
    /// compare against, so "allowed" is the absence of a check rather than
    /// the result of one. The distinction exists because a silently-vacuous
    /// security check is the failure mode `11` §7 and `23` §1.1 keep finding.
    #[must_use]
    pub const fn is_vacuous(&self) -> bool {
        self.excluded_resolved == 0
    }
}

/// Decides whether a share may be mounted.
///
/// `excluded` is the identity of every file that must stay outside the guest —
/// `rachna.nix`, the store, anything load-bearing — already resolved by the
/// caller. `entries` is what was found inside the share.
///
/// # The `links > 1` pre-filter is applied here, not by the caller
///
/// `14` §3 establishes it as sound: a hardlink necessarily has `nlink >= 2`,
/// so nothing can hide behind it, and almost every file in a normal project
/// has `nlink == 1`. Applying it here rather than in the walk means the walk
/// cannot accidentally filter *more* than this — the caller hands over
/// everything it saw, and the security decision stays in one place.
#[must_use]
pub fn check(
    share_root_device: u64,
    excluded: &BTreeSet<FileId>,
    entries: &[ShareEntry],
) -> Verdict {
    let mut refusals = Vec::new();

    for entry in entries {
        // Checked before the link filter: a mount point need not be a
        // hardlink, and an entry on another device was never compared against
        // an exclusion set resolved on this one.
        if entry.id.device != share_root_device {
            refusals.push(Refusal::CrossesFilesystem {
                entry: entry.path.clone(),
                entry_device: entry.id.device,
                share_device: share_root_device,
            });
            continue;
        }

        if entry.links > 1 && excluded.contains(&entry.id) {
            refusals.push(Refusal::ReachesExcludedFile {
                entry: entry.path.clone(),
                id: entry.id,
            });
        }
    }

    Verdict {
        refusals,
        entries_examined: entries.len(),
        excluded_resolved: excluded.len(),
    }
}

/// Whether `path` is excluded by name, as the first and weakest filter.
///
/// **Not a security boundary on its own** — this is what the hardlink and
/// case-variant attacks defeat. It exists because the exclusion set has to be
/// *built* from names before it can be resolved to identities, and because a
/// case-insensitive host makes even that step subtle.
///
/// Compared case-insensitively on purpose: on APFS, `RACHNA.NIX` and
/// `rachna.nix` are the same file (`12` §3), so a case-sensitive comparison
/// would fail to add the file to the excluded set at all — the check would
/// then be vacuous rather than wrong, which is worse because it looks fine.
#[must_use]
pub fn is_excluded_by_name(path: &Path, excluded_names: &[&str]) -> bool {
    path.file_name().is_some_and(|name| {
        let name = name.to_string_lossy();
        excluded_names
            .iter()
            .any(|excluded| name.eq_ignore_ascii_case(excluded))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARE_DEV: u64 = 1;

    /// The identity of `rachna.nix` — the file every attack below targets.
    const POLICY: FileId = FileId {
        device: SHARE_DEV,
        inode: 42,
    };

    fn excluded() -> BTreeSet<FileId> {
        [POLICY].into_iter().collect()
    }

    fn entry(path: &str, inode: u64, links: u64) -> ShareEntry {
        ShareEntry {
            path: PathBuf::from(path),
            id: FileId {
                device: SHARE_DEV,
                inode,
            },
            links,
        }
    }

    // ---- the three measured attacks --------------------------------------

    #[test]
    fn a_hardlink_to_the_policy_file_is_refused() {
        // `13` §4, measured succeeding on macOS: the policy file is excluded
        // by path, so the attacker's move is a second name for the same inode
        // INSIDE the share. This is the attack that actually matters (`14`
        // §3), because it defeats every name-based check.
        let entries = [entry("ws/innocuous.txt", POLICY.inode, 2)];
        let verdict = check(SHARE_DEV, &excluded(), &entries);

        assert!(!verdict.is_allowed());
        assert_eq!(
            verdict.refusals(),
            [Refusal::ReachesExcludedFile {
                entry: PathBuf::from("ws/innocuous.txt"),
                id: POLICY,
            }]
        );
    }

    #[test]
    fn a_case_variant_is_refused_by_the_same_check() {
        // `12` §3, measured succeeding on APFS: `RACHNA.NIX` resolves to
        // `rachna.nix`. It needs no separate rule — a case variant IS the same
        // inode, so the identity comparison closes both attacks at once
        // (`14` §4). Asserted so that claim is tested, not just stated.
        let entries = [entry("ws/RACHNA.NIX", POLICY.inode, 2)];
        assert!(!check(SHARE_DEV, &excluded(), &entries).is_allowed());
    }

    #[test]
    fn a_hardlink_nested_deep_in_the_tree_is_still_refused() {
        // `14` §3 tested this placement explicitly: hiding it several levels
        // down must not help.
        let entries = [entry("ws/a/b/c/d/e/sneaky", POLICY.inode, 2)];
        assert!(!check(SHARE_DEV, &excluded(), &entries).is_allowed());
    }

    #[test]
    fn an_entry_on_another_filesystem_is_refused() {
        // `14` §3 step 3. A mount point inside the workspace was never
        // compared against anything, because the exclusion set was resolved
        // on the share's own device.
        let foreign = ShareEntry {
            path: PathBuf::from("ws/mnt"),
            id: FileId {
                device: 99,
                inode: 7,
            },
            links: 1,
        };
        let verdict = check(SHARE_DEV, &excluded(), &[foreign]);
        assert_eq!(
            verdict.refusals(),
            [Refusal::CrossesFilesystem {
                entry: PathBuf::from("ws/mnt"),
                entry_device: 99,
                share_device: SHARE_DEV,
            }]
        );
    }

    // ---- the ordinary case must still work -------------------------------

    #[test]
    fn an_ordinary_project_tree_is_allowed() {
        let entries = [
            entry("ws/src/main.rs", 100, 1),
            entry("ws/Cargo.toml", 101, 1),
            entry("ws/README.md", 102, 1),
        ];
        let verdict = check(SHARE_DEV, &excluded(), &entries);
        assert!(verdict.is_allowed());
        assert!(verdict.refusals().is_empty());
        assert_eq!(verdict.entries_examined(), 3);
    }

    #[test]
    fn a_hardlink_to_something_not_excluded_is_allowed() {
        // Hardlinks are legitimate — build systems and package managers make
        // them. Only one pointing at an EXCLUDED file is an escape, and
        // refusing all of them would break real projects for no gain.
        let entries = [entry("ws/node_modules/.bin/tsc", 500, 3)];
        assert!(check(SHARE_DEV, &excluded(), &entries).is_allowed());
    }

    #[test]
    fn the_excluded_inode_with_a_single_link_is_allowed() {
        // The policy file itself, seen in its own directory with nlink == 1,
        // is not an escape: there is no second name. Refusing it would make
        // the check fire on every normal project.
        let entries = [entry("rachna.nix", POLICY.inode, 1)];
        assert!(check(SHARE_DEV, &excluded(), &entries).is_allowed());
    }

    // ---- batch reporting -------------------------------------------------

    #[test]
    fn every_refusal_is_reported_not_just_the_first() {
        // Same principle as the denial report (00 §3.3): a user fixing one
        // hardlink should not have to re-run to find the second.
        let entries = [
            entry("ws/one", POLICY.inode, 2),
            entry("ws/fine", 200, 1),
            entry("ws/two", POLICY.inode, 2),
        ];
        let verdict = check(SHARE_DEV, &excluded(), &entries);
        assert_eq!(verdict.refusals().len(), 2);
        assert_eq!(verdict.entries_examined(), 3);
    }

    #[test]
    fn a_refusal_explains_itself_with_the_evidence() {
        let entries = [entry("ws/innocuous.txt", POLICY.inode, 2)];
        let verdict = check(SHARE_DEV, &excluded(), &entries);
        let message = verdict.refusals()[0].to_string();
        assert!(message.contains("ws/innocuous.txt"), "{message}");
        assert!(message.contains("inode 42"), "{message}");
        assert!(message.contains("excluded"), "{message}");
    }

    // ---- the vacuous-check guard ----------------------------------------

    #[test]
    fn a_check_with_nothing_excluded_is_vacuous_not_safe() {
        // The failure mode this project keeps hitting (`11` §7, `23` §1.1): a
        // check that examined nothing reports success. An empty exclusion set
        // yields no refusals, so the verdict must say it proves nothing.
        let entries = [entry("ws/innocuous.txt", POLICY.inode, 2)];
        let verdict = check(SHARE_DEV, &BTreeSet::new(), &entries);
        assert!(verdict.is_allowed(), "nothing to compare against");
        assert!(
            verdict.is_vacuous(),
            "a check protecting nothing must admit it"
        );
        assert_eq!(verdict.excluded_resolved(), 0);
    }

    #[test]
    fn a_real_check_is_not_vacuous() {
        let verdict = check(SHARE_DEV, &excluded(), &[entry("ws/f", 9, 1)]);
        assert!(!verdict.is_vacuous());
        assert_eq!(verdict.excluded_resolved(), 1);
    }

    #[test]
    fn an_empty_share_is_allowed_but_still_records_what_it_checked() {
        let verdict = check(SHARE_DEV, &excluded(), &[]);
        assert!(verdict.is_allowed());
        assert_eq!(verdict.entries_examined(), 0);
        assert!(
            !verdict.is_vacuous(),
            "the exclusion set was still resolved"
        );
    }

    // ---- the name filter, and its documented weakness --------------------

    #[test]
    fn the_name_filter_is_case_insensitive() {
        // Deliberate: on APFS `RACHNA.NIX` and `rachna.nix` are the same file
        // (`12` §3), so a case-SENSITIVE comparison would fail to add it to
        // the excluded set — making the real check vacuous rather than wrong,
        // which is worse because it looks fine.
        for name in ["rachna.nix", "RACHNA.NIX", "Rachna.Nix"] {
            assert!(
                is_excluded_by_name(Path::new(name), &["rachna.nix"]),
                "{name} must be recognised"
            );
        }
    }

    #[test]
    fn the_name_filter_matches_on_the_file_name_not_the_path() {
        assert!(is_excluded_by_name(
            Path::new("/a/b/rachna.nix"),
            &["rachna.nix"]
        ));
        // A directory merely NAMED like the file is not it.
        assert!(!is_excluded_by_name(
            Path::new("/a/rachna.nix/inner.txt"),
            &["rachna.nix"]
        ));
    }

    #[test]
    fn the_name_filter_rejects_unrelated_names() {
        assert!(!is_excluded_by_name(
            Path::new("rachna.nix.bak"),
            &["rachna.nix"]
        ));
        assert!(!is_excluded_by_name(Path::new("main.rs"), &["rachna.nix"]));
        assert!(!is_excluded_by_name(Path::new("/"), &["rachna.nix"]));
    }

    #[test]
    fn the_name_filter_alone_does_not_catch_a_renamed_hardlink() {
        // Documents WHY the identity check exists. `ws/innocuous.txt` is a
        // hardlink to the policy file: the name filter says it is fine, and
        // the identity check refuses it. If this ever starts passing the name
        // filter, something has been conflated.
        let attack = Path::new("ws/innocuous.txt");
        assert!(!is_excluded_by_name(attack, &["rachna.nix"]));

        let entries = [entry("ws/innocuous.txt", POLICY.inode, 2)];
        assert!(!check(SHARE_DEV, &excluded(), &entries).is_allowed());
    }
}
