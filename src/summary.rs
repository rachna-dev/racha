//! The first-run access summary (`00-PRODUCT.md` §3.10c).
//!
//! On the first `start` of a grant set this machine has not run, Rachna prints
//! what the config grants and stops. This is **not** the permission prompt
//! §3.2 rules out: answering cannot create a grant that is absent from the
//! file, refusing cannot remove one, and `rachna.nix` is unchanged either way.
//! It is a read gate, not a write path.
//!
//! # Two properties carry the whole feature
//!
//! 1. **Completeness.** A category omitted from the output is a grant the user
//!    believes they do not have. Every [`Category`] appears, including empty
//!    ones — `secrets  none` is information, and its absence would read as
//!    "this config does not touch credentials".
//!
//! 2. **Keyed on the effective grant set, not the file.** Reformatting, a
//!    comment or a reordered list must not re-gate, or the acknowledgement
//!    becomes noise people learn to alias away. A grant *added* must.

use crate::decision::{Access, Category};
use crate::grant::Grant;
use crate::policy::{Profile, Tier};
use core::fmt;
use std::collections::BTreeSet;

/// What a config grants, grouped for display.
///
/// # Example
///
/// ```text
///   rachna.nix grants, first run:
///
///   network   github.com:443
///             registry.npmjs.org:443
///   fs        /Users/you/.npmrc  read-only
///             /workspace  read-write
///   tool      rust-analyzer  lsp, no network
///   port      3000 -> 3000
///   secret    aws  <- credential access
///
///   this config has not run here before.
///   review it, then:  rachna start --accept
/// ```
///
/// Built from an evaluated policy. Holds the axes as well as the grants
/// because `tier = open` grants network access that no [`Grant`] records —
/// omitting it would be a completeness hole of exactly the kind property 1
/// exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessSummary {
    tier: Tier,
    profile: Profile,
    lines: Vec<(Category, Vec<String>)>,
}

impl AccessSummary {
    /// Summarises what `grants` and the two axes permit.
    #[must_use]
    pub fn new(tier: Tier, profile: Profile, grants: &[Grant]) -> Self {
        let lines = Category::ALL
            .iter()
            .map(|&category| (category, Self::detail(category, tier, profile, grants)))
            .collect();
        Self {
            tier,
            profile,
            lines,
        }
    }

    /// The human-readable entries for one category, sorted for stability.
    ///
    /// Sorted rather than source-ordered so the rendering — and therefore the
    /// fingerprint built from it — does not change when a list is reordered
    /// in `rachna.nix` (property 2).
    fn detail(category: Category, tier: Tier, profile: Profile, grants: &[Grant]) -> Vec<String> {
        // A category the profile forbids is reported as forbidden, NOT as the
        // grants that happen to be written down.
        //
        // Found by the fingerprint/diff agreement test: with `profile =
        // sealed`, this listed `secret aws` for a config where `decide` denies
        // every secret at step 1 (`08` §1.2). Overstating access is the same
        // class of bug as omitting a category — the user reads a permission
        // they do not have — and it is the more dangerous direction here,
        // because it invites accepting a config on a false basis.
        if profile.forbids(category) {
            return vec![format!("none ({profile} profile forbids it)")];
        }

        // `open` and `internet` permit any host without an allowlist entry, so
        // the grants list would understate the access. This is the completeness
        // hole that made holding the axes necessary.
        if category == Category::Network && matches!(tier, Tier::Open | Tier::Internet) {
            return vec![format!("any host (tier = {tier})")];
        }

        let mut entries: BTreeSet<String> = BTreeSet::new();
        for grant in grants.iter().filter(|g| g.category() == category) {
            entries.insert(match grant {
                Grant::Network { endpoint } => endpoint.to_string(),
                Grant::Filesystem { path, access } => {
                    let access = match access {
                        Access::ReadOnly => "read-only",
                        Access::ReadWrite => "read-write",
                    };
                    format!("{}  {access}", path.display())
                }
                Grant::Tool {
                    name,
                    kind,
                    network,
                } => {
                    let net = if *network { "network" } else { "no network" };
                    format!("{name}  {kind}, {net}")
                }
                Grant::Port { guest, host } => format!("{guest} -> {host}"),
                // Marked, because credential access is the grant a user most
                // needs to notice in a repo they just cloned. Everything else
                // here is scoped; a credential is the thing that leaves.
                Grant::Secret { name } => format!("{name}  <- credential access"),
            });
        }
        entries.into_iter().collect()
    }

    /// Every granted entry as a flat set, for comparison.
    ///
    /// Built from the same `lines` the rendering and the fingerprint use, so
    /// a diff can never disagree with what was displayed.
    fn entries(&self) -> BTreeSet<(Category, String)> {
        let mut out = BTreeSet::new();
        for (category, entries) in &self.lines {
            for entry in entries {
                // A "forbidden" marker describes an absence, so it is not an
                // entry: counting it would make a sealed config look as though
                // it granted something, and would put it in the diff.
                if entry.starts_with("none (") {
                    continue;
                }
                out.insert((*category, entry.clone()));
            }
        }
        out
    }

    /// A stable identifier for *what this grants*, not for the file's bytes.
    ///
    /// Property 2. Two configs that permit exactly the same things share a
    /// fingerprint, so a reformat does not re-gate; adding or widening a grant
    /// changes it, so a `git pull` that adds one does.
    ///
    /// Written explicitly rather than derived from `Debug` or a serializer,
    /// because `08-POLICY-AND-STORE.md` §2 records that a format change
    /// orphans stored records and must therefore be a deliberate migration.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut out = format!("tier={}\nprofile={}\n", self.tier, self.profile);
        for (category, entries) in &self.lines {
            for entry in entries {
                out.push_str(category.as_str());
                out.push(' ');
                out.push_str(entry);
                out.push('\n');
            }
        }
        out
    }

    /// Whether this grants anything at all beyond the defaults.
    ///
    /// A `none (… forbids it)` line is not a grant, so a config whose profile
    /// forbids everything still reports as empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries().is_empty()
    }

    /// The categories that grant nothing.
    ///
    /// Rendered as `none` rather than skipped: a missing line reads as "this
    /// config does not touch credentials", which is a different claim.
    #[must_use]
    pub fn empty_categories(&self) -> Vec<Category> {
        let granted = self.entries();
        self.lines
            .iter()
            .filter(|(category, _)| !granted.iter().any(|(c, _)| c == category))
            .map(|(category, _)| *category)
            .collect()
    }
}

/// The longest list worth reviewing item by item.
///
/// `20`'s nine project shapes declare 1 to 5 reviewable grants, so this is
/// comfortably above every measured real config while still fitting a
/// terminal alongside the surrounding prompt. See
/// [`AccessSummary::too_long_to_itemise`].
pub const PER_ITEM_REVIEW_LIMIT: usize = 12;

/// One reviewable grant in a first-run or reload summary.
///
/// The unit a user says yes or no to. Numbered so the CLI can offer a
/// checkbox list — `00` §3.10c's summary shows five grants, and a user who
/// wants four should not have to find the right line in a Nix file by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reviewable {
    /// 1-based, as displayed.
    pub number: usize,
    /// Which category it falls under.
    pub category: Category,
    /// The entry as the summary renders it.
    pub entry: String,
}

/// A user's answer to a summary: which grants they want.
///
/// # This is not a stored subset, and that difference is the whole design
///
/// `00` §3.10c refuses *"a subset chosen at the prompt"*, and the reason is
/// not UI preference: a subset has to be stored somewhere, and that store
/// becomes **a second place a permission lives**. Then `rachna.nix` says one
/// thing, the machine does another, and a teammate cloning the repo gets a
/// different environment.
///
/// So a [`Selection`] is **never applied as policy**. It is turned into
/// [`Selection::revocations`] — the `rachna revoke …` commands that remove
/// the unwanted grants *from the file*. The grant set then changes, the
/// fingerprint changes, and the new summary is what gets approved. §3.10c's
/// own words: *"The grant set changed, so the fingerprint changed, so you are
/// shown the new summary and accept **that**."*
///
/// Checkboxes therefore compose an **edit**, not a policy — which means the
/// ergonomics a user wants and the invariant the design needs were never in
/// tension. They only looked that way while the edit had to be typed by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    accepted: Vec<Reviewable>,
    rejected: Vec<Reviewable>,
}

impl AccessSummary {
    /// The grants a user reviews, numbered as displayed.
    ///
    /// Ordered by category and then as rendered, matching the summary
    /// exactly — a number pointing at a different line than the one printed
    /// would be worse than no numbering.
    #[must_use]
    pub fn reviewable(&self) -> Vec<Reviewable> {
        let mut out = Vec::new();
        for (category, entries) in &self.lines {
            for entry in entries {
                // Same exclusion as `entries()`: a "forbidden" marker
                // describes an absence, and offering to revoke an absence
                // would be nonsense.
                if entry.starts_with("none (") {
                    continue;
                }
                out.push(Reviewable {
                    number: out.len() + 1,
                    category: *category,
                    entry: entry.clone(),
                });
            }
        }
        out
    }

    /// Whether this summary is too long to review item by item.
    ///
    /// **Measured, not guessed.** All nine project shapes in `20` declare
    /// **1 to 5** reviewable grants — the largest being three hosts and two
    /// ports. So the per-item list is the right default for every real
    /// config surveyed.
    ///
    /// But "does not happen in practice" is not a bound, and the case where
    /// it breaks is the one that matters most: `00` §3.10c exists for a
    /// *cloned, unreviewed* config, which is precisely where a 200-host
    /// allowlist would appear. A numbered list that long is not a review, it
    /// is a wall — and §3.10c's own warning is that a summary people stop
    /// reading is *"worse than nothing"*.
    ///
    /// Above the threshold the caller should group by category and ask per
    /// category, with the full list available on request. Twelve is the
    /// largest list that fits a terminal without scrolling alongside the
    /// surrounding prompt, and is comfortably above the measured maximum of
    /// five.
    #[must_use]
    pub fn too_long_to_itemise(&self) -> bool {
        self.reviewable().len() > PER_ITEM_REVIEW_LIMIT
    }

    /// How many grants there are per category, in display order.
    ///
    /// What a caller renders when [`Self::too_long_to_itemise`] is true:
    /// `network  47 hosts` is reviewable where 47 numbered lines are not.
    #[must_use]
    pub fn counts_by_category(&self) -> Vec<(Category, usize)> {
        let mut out: Vec<(Category, usize)> = Vec::new();
        for item in self.reviewable() {
            match out
                .iter_mut()
                .find(|(category, _)| *category == item.category)
            {
                Some((_, count)) => *count += 1,
                None => out.push((item.category, 1)),
            }
        }
        out
    }

    /// Splits the reviewable grants by the numbers a user ticked.
    ///
    /// Numbers outside the range are ignored rather than an error: a typo at
    /// a prompt should not discard the whole review, and the result still
    /// shows exactly what was kept.
    #[must_use]
    pub fn select(&self, wanted: &[usize]) -> Selection {
        let (accepted, rejected) = self
            .reviewable()
            .into_iter()
            .partition(|item| wanted.contains(&item.number));
        Selection { accepted, rejected }
    }

    /// Every grant, as if the user ticked "all".
    #[must_use]
    pub fn select_all(&self) -> Selection {
        Selection {
            accepted: self.reviewable(),
            rejected: Vec::new(),
        }
    }
}

impl Selection {
    /// What the user kept.
    #[must_use]
    pub fn accepted(&self) -> &[Reviewable] {
        &self.accepted
    }

    /// What the user declined.
    #[must_use]
    pub fn rejected(&self) -> &[Reviewable] {
        &self.rejected
    }

    /// Whether this is a plain "accept all".
    ///
    /// The common case, and the one needing no edit: nothing was declined,
    /// so the grant set already matches what is being approved.
    #[must_use]
    pub fn is_accept_all(&self) -> bool {
        self.rejected.is_empty()
    }

    /// The `rachna revoke …` commands that make the file match this
    /// selection.
    ///
    /// Empty for an accept-all, which is the point: approving everything
    /// requires no edit, so there is nothing to run.
    ///
    /// The commands use the same vocabulary as `rachna.nix` and the CLI
    /// (`fs`, not `files`), because `00` §3.10c requires one vocabulary
    /// across the config file, the CLI, the audit store and this summary.
    #[must_use]
    pub fn revocations(&self) -> Vec<String> {
        self.rejected
            .iter()
            .map(|item| {
                // The rendered entry carries display detail a command must
                // not: `~/.npmrc  read-only` and `aws  <- credential
                // access`. The target is the first whitespace-delimited
                // token, which is what the file and the CLI both name.
                let target = item.entry.split_whitespace().next().unwrap_or(&item.entry);
                format!("rachna revoke {} {target}", item.category.as_str())
            })
            .collect()
    }
}

/// What a user pressed at the review gate.
///
/// A keypress rather than a flag to retype, because `rachna start --accept`
/// makes a user run the command twice — once to see the summary, once to
/// accept it — and the second run is pure ceremony. Pressing `a` is the same
/// decision with the summary still on screen.
///
/// # Why this is not the prompt §3.2 forbids
///
/// `00` §3.10c already settles it, and the distinction is exact: this is a
/// **read gate**, not a write path. *"Answering 'yes' here cannot produce a
/// permission that is not in the file. Refusing cannot remove one."* The
/// keypress accepts the file **as written** — it grants nothing, stores no
/// subset, and leaves `rachna.nix` untouched either way. What §3.2 bans is a
/// prompt that *creates* a permission, and none of these can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Accept every grant the file declares, and start.
    AcceptAll,
    /// Start nothing. The default for anything unrecognised.
    Abort,
    /// Print the full list, then ask again.
    ///
    /// Only meaningful above [`PER_ITEM_REVIEW_LIMIT`], where the summary
    /// rolled up per category and the entries were not shown.
    ShowAll,
}

impl Answer {
    /// The answer for a keypress.
    ///
    /// **Anything unrecognised is [`Self::Abort`]**, which is the only safe
    /// default: a stray byte — a resized terminal, a bracketed-paste escape,
    /// a cat on the keyboard — must not accept a cloned config's
    /// permissions. The cost of a wrong abort is retyping one command; the
    /// cost of a wrong accept is `00` §3.10c's entire reason for existing.
    ///
    /// Case-insensitive, because a user with caps lock on means the same
    /// thing and refusing them would be pedantry at a security gate.
    #[must_use]
    pub const fn from_key(key: char) -> Self {
        match key.to_ascii_lowercase() {
            'a' => Self::AcceptAll,
            'l' => Self::ShowAll,
            _ => Self::Abort,
        }
    }

    /// Whether the environment should start.
    #[must_use]
    pub const fn starts(self) -> bool {
        matches!(self, Self::AcceptAll)
    }
}

/// Whether the review gate can be answered interactively.
///
/// False when stdin is not a terminal, which is not a detail: `00` §3.10c
/// records that **CI needs a flag** — `RACHNA_ACCEPT=1` or `--accept` — and a
/// pipeline blocking forever on a keypress nobody can send is worse than one
/// that refuses. So a non-TTY gets the printed commands and no prompt.
///
/// Takes the answer rather than reading stdin, so the decision is testable
/// without a terminal. The caller passes `std::io::stdin().is_terminal()`.
#[must_use]
pub const fn can_prompt(stdin_is_terminal: bool) -> bool {
    stdin_is_terminal
}

/// The two things a user can do with a first-run summary.
///
/// Rendered because *"accept all, or choose: 1,2,3,4,6"* told a user neither
/// how to accept nor how to choose. `00` §3.3's rules apply to this prompt as
/// to a denial: a message that names no command is not actionable, and
/// `00` §3.10c's whole point is that this is the moment it matters.
///
/// Both commands here are real: a test parses every one through
/// [`Invocation::from_argv`](crate::cli::Invocation::from_argv), because an
/// offered command the CLI rejects is worse than none.
#[must_use]
pub fn review_prompt(summary: &AccessSummary, interactive: bool) -> String {
    let total = summary.reviewable().len();
    if total == 0 {
        // Nothing granted. `00` §3.10c still requires the summary — "secrets
        // none is information" — but there is nothing to accept or decline,
        // so offering either would be noise.
        return "  this config grants nothing. `rachna start` needs no acknowledgement\n"
            .to_owned();
    }

    let mut out = String::new();
    out.push_str("  this config has not run here before.\n\n");

    if interactive {
        // A keypress, because `--accept` makes the user run the command
        // twice: once to see the summary, once to accept it. The second run
        // is ceremony.
        out.push_str("  [a] accept all and start\n");
        if summary.too_long_to_itemise() {
            out.push_str(&format!("  [l] list all {total} grants\n"));
        }
        out.push_str("  [q] quit, and change rachna.nix first\n");
        out.push_str("\n  to drop one:  rachna revoke <category> <target>\n");
    } else {
        // Not a TTY. `00` §3.10c: "CI needs a flag … RACHNA_ACCEPT=1 or
        // --accept in the pipeline." A pipeline blocked forever on a
        // keypress nobody can send is worse than one that refuses, so the
        // non-interactive path prints commands and prompts for nothing.
        out.push_str("  accept everything:   rachna start --accept\n");
        if summary.too_long_to_itemise() {
            out.push_str(&format!(
                "  review in full:      rachna config inspect   ({total} grants)\n"
            ));
        }
        // No backticks: this line is copied, not read. The test caught one
        // glued to `--accept`, which the parser then rejected as the flag
        // "--accept`" — an offered command that cannot work, which is the
        // defect this whole prompt exists to avoid.
        out.push_str("  drop one:            rachna revoke <category> <target>\n");
    }
    out
}

/// How a grant set changed since the last accepted one.
///
/// The edit loop in `00-PRODUCT.md` §3.10c is *review, edit, start again*, so
/// the second showing must answer "what changed" rather than reprinting the
/// whole list. Reprinting is what trains people to stop reading it.
///
/// Both directions are reported. A **removed** grant is as important as an
/// added one: it is the evidence that the edit you made actually took effect,
/// and silently showing only additions would leave a failed edit looking
/// identical to a successful one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantDiff {
    added: Vec<(Category, String)>,
    removed: Vec<(Category, String)>,
}

impl GrantDiff {
    /// What changed going from `previous` to `current`.
    #[must_use]
    pub fn between(previous: &AccessSummary, current: &AccessSummary) -> Self {
        let before = previous.entries();
        let after = current.entries();
        Self {
            added: after.difference(&before).cloned().collect(),
            removed: before.difference(&after).cloned().collect(),
        }
    }

    /// Whether anything changed at all.
    ///
    /// `true` means the fingerprint is unchanged, so no re-acknowledgement is
    /// needed — the two must never disagree, which a test asserts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// Whether this change grants anything that was not granted before.
    ///
    /// The question the gate actually turns on. A purely *narrowing* edit —
    /// removing grants and adding none — still changes the fingerprint, but a
    /// user who has already seen the wider set has nothing new to review.
    #[must_use]
    pub fn widens(&self) -> bool {
        !self.added.is_empty()
    }
}

impl fmt::Display for GrantDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (category, entry) in &self.removed {
            writeln!(f, "  - {:<7} {entry}", category.as_str())?;
        }
        for (category, entry) in &self.added {
            writeln!(f, "  + {:<7} {entry}", category.as_str())?;
        }
        Ok(())
    }
}

impl fmt::Display for AccessSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  rachna.nix grants, first run:")?;
        writeln!(f)?;
        for (category, entries) in &self.lines {
            let label = category.as_str();
            match entries.split_first() {
                None => writeln!(f, "  {label:<9} none")?,
                Some((first, rest)) => {
                    writeln!(f, "  {label:<9} {first}")?;
                    for entry in rest {
                        writeln!(f, "  {:<9} {entry}", "")?;
                    }
                }
            }
        }
        // Trailing blank line, so a caller appending the acknowledgement
        // prompt does not have to remember one.
        writeln!(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::{endpoint, ToolKind};
    use std::path::PathBuf;

    fn realistic_grants() -> Vec<Grant> {
        vec![
            Grant::Network {
                endpoint: endpoint("registry.npmjs.org", 443),
            },
            Grant::Network {
                endpoint: endpoint("github.com", 443),
            },
            Grant::Filesystem {
                path: PathBuf::from("/workspace"),
                access: Access::ReadWrite,
            },
            Grant::Port {
                guest: 3000,
                host: 3000,
            },
            Grant::Secret {
                name: "aws".to_owned(),
            },
            Grant::Tool {
                name: "rust-analyzer".to_owned(),
                kind: ToolKind::Lsp,
                network: false,
            },
        ]
    }

    // ---- reviewing grants one at a time, or all at once -------------------

    fn realistic() -> AccessSummary {
        AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants())
    }

    #[test]
    fn every_grant_is_reviewable_and_numbered_as_displayed() {
        // A number pointing at a different line than the one printed would
        // be worse than no numbering, so the order is pinned against the
        // rendered summary rather than asserted independently.
        let summary = realistic();
        let items = summary.reviewable();
        assert_eq!(items.len(), realistic_grants().len());

        let rendered = summary.to_string();
        let mut last_position = 0;
        for (index, item) in items.iter().enumerate() {
            assert_eq!(item.number, index + 1, "numbering is not 1-based or dense");
            let position = rendered
                .find(item.entry.as_str())
                .unwrap_or_else(|| panic!("`{}` is numbered but not displayed", item.entry));
            assert!(
                position >= last_position,
                "item {} is numbered before `{}` but printed after it",
                item.number,
                item.entry
            );
            last_position = position;
        }
    }

    #[test]
    fn accepting_all_requires_no_edit() {
        // The common case. Approving everything already matches the file, so
        // there is nothing to run — and a non-empty list here would send a
        // user to revoke grants they just said yes to.
        let selection = realistic().select_all();
        assert!(selection.is_accept_all());
        assert!(selection.rejected().is_empty());
        assert!(
            selection.revocations().is_empty(),
            "accept-all produced edits: {:?}",
            selection.revocations()
        );
        assert_eq!(selection.accepted().len(), realistic_grants().len());
    }

    #[test]
    fn declining_one_grant_produces_the_edit_that_removes_it() {
        // `00` §3.10c's worked example: "You do not want the credential. You
        // delete that line — or run `rachna revoke secret aws`". The
        // checkbox composes exactly that command rather than storing a
        // subset, which is what keeps the file the only authority.
        let summary = realistic();
        let secret = summary
            .reviewable()
            .into_iter()
            .find(|item| item.category == Category::Secret)
            .expect("the fixture grants a secret");

        let wanted: Vec<usize> = summary
            .reviewable()
            .iter()
            .map(|item| item.number)
            .filter(|number| *number != secret.number)
            .collect();
        let selection = summary.select(&wanted);

        assert!(!selection.is_accept_all());
        assert_eq!(selection.rejected().len(), 1);
        assert_eq!(selection.rejected()[0].category, Category::Secret);
        assert_eq!(selection.revocations(), vec!["rachna revoke secret aws"]);
    }

    #[test]
    fn every_revocation_the_summary_offers_actually_parses() {
        // The test that stops this being a nice-looking dead end. A command
        // the parser rejects is worse than no command, because the user now
        // believes they tried — the same defect as `enforcement.rs`'s
        // invented `--verify-enforcement` flag, caught the same way.
        //
        // Declining EVERY grant, so each category's command is exercised.
        let summary = realistic();
        let selection = summary.select(&[]);
        assert_eq!(selection.rejected().len(), realistic_grants().len());

        let commands = selection.revocations();
        assert_eq!(commands.len(), realistic_grants().len());
        for command in &commands {
            let argv: Vec<std::ffi::OsString> = command
                .split_whitespace()
                .map(std::ffi::OsString::from)
                .collect();
            let parsed = crate::cli::Invocation::from_argv(&argv);
            assert!(
                parsed.is_ok(),
                "the summary offers `{command}`, which the parser rejects: {:?}",
                parsed.err()
            );
        }
    }

    #[test]
    fn a_revocation_names_the_target_without_display_detail() {
        // `summary.rs` renders `~/.npmrc  read-only` and `aws  <- credential
        // access` for humans. A command carrying that detail would not
        // parse, and a command carrying the wrong token would revoke the
        // wrong grant.
        let summary = realistic();
        let selection = summary.select(&[]);
        for command in selection.revocations() {
            assert!(
                !command.contains("<-") && !command.contains("read-only"),
                "a revocation carried display detail: {command}"
            );
            // Exactly four words: rachna, revoke, category, target.
            assert_eq!(
                command.split_whitespace().count(),
                4,
                "malformed revocation: {command}"
            );
        }
    }

    #[test]
    fn a_number_out_of_range_is_ignored_rather_than_fatal() {
        // A typo at a prompt should not discard the whole review. The result
        // still shows exactly what was kept, so the user sees the mistake.
        let summary = realistic();
        let selection = summary.select(&[1, 999]);
        assert_eq!(selection.accepted().len(), 1);
        assert_eq!(selection.accepted()[0].number, 1);
        assert_eq!(
            selection.rejected().len(),
            realistic_grants().len() - 1,
            "an out-of-range number changed what was rejected"
        );
    }

    #[test]
    fn a_forbidden_marker_is_not_offered_for_revocation() {
        // A sealed profile prints `none (profile forbids it)`, which
        // describes an absence. Offering to revoke an absence would be
        // nonsense, and the command would not parse.
        let sealed = AccessSummary::new(Tier::None, Profile::Sealed, &[]);
        assert!(
            sealed.reviewable().is_empty(),
            "a forbidden marker was offered as a grant: {:?}",
            sealed.reviewable()
        );
        assert!(sealed.select_all().revocations().is_empty());
    }

    #[test]
    fn only_a_deliberate_key_accepts_and_everything_else_aborts() {
        // THE safety property. A stray byte — a resized terminal, a
        // bracketed-paste escape sequence, a cat on the keyboard — must not
        // accept a cloned config's permissions. The cost of a wrong abort is
        // retyping one command; the cost of a wrong accept is `00` §3.10c's
        // entire reason for existing.
        //
        // First assert the thing under attack exists: `a` DOES accept, so
        // the rejections below are not vacuous.
        assert_eq!(Answer::from_key('a'), Answer::AcceptAll);
        assert!(Answer::from_key('a').starts());

        for key in [
            'q', 'n', 'y', 'Y', '\n', '\r', ' ', '\t', '\0', 'z', '1',
            // The bytes a terminal actually sends unbidden: escape, and the
            // tail of an arrow key or a bracketed paste.
            '\u{1b}', '[', '2', '0', '~',
        ] {
            if key.eq_ignore_ascii_case(&'a') || key.eq_ignore_ascii_case(&'l') {
                continue;
            }
            assert_eq!(
                Answer::from_key(key),
                Answer::Abort,
                "`{key:?}` was not treated as an abort"
            );
            assert!(!Answer::from_key(key).starts(), "`{key:?}` started the env");
        }
    }

    #[test]
    fn the_accept_key_is_case_insensitive() {
        // A user with caps lock on means the same thing, and refusing them
        // at a security gate is pedantry — they would press it again.
        assert_eq!(Answer::from_key('A'), Answer::AcceptAll);
        assert_eq!(Answer::from_key('L'), Answer::ShowAll);
    }

    #[test]
    fn only_accepting_starts_the_environment() {
        // `ShowAll` must not start: it prints the list and asks again. A
        // version that started after showing would mean pressing `l` to read
        // the grants silently accepted them.
        assert!(Answer::AcceptAll.starts());
        assert!(!Answer::ShowAll.starts());
        assert!(!Answer::Abort.starts());
    }

    #[test]
    fn a_pipe_is_never_prompted() {
        // `00` §3.10c: "CI needs a flag … RACHNA_ACCEPT=1 or --accept in the
        // pipeline." A pipeline blocked forever on a keypress nobody can
        // send is worse than one that refuses.
        assert!(!can_prompt(false));
        assert!(can_prompt(true));
    }

    #[test]
    fn the_prompt_tells_the_user_how_to_accept_and_how_to_choose() {
        // The gap this closes: "accept all, or choose: 1,2,3,4,6" told a
        // user NEITHER. `00` §3.3's rules apply to this prompt as to a
        // denial — a message naming no command is not actionable.
        // Non-interactive: names the flag, because CI cannot press a key.
        let piped = review_prompt(&realistic(), false);
        assert!(piped.contains("rachna start --accept"), "{piped}");
        assert!(piped.contains("rachna revoke"), "{piped}");

        // Interactive: offers the keypress, and does NOT tell a user at a
        // terminal to retype a command they can answer in one character.
        let tty = review_prompt(&realistic(), true);
        assert!(tty.contains("[a] accept all"), "{tty}");
        assert!(tty.contains("[q] quit"), "{tty}");
        assert!(
            !tty.contains("start --accept"),
            "a terminal user was told to retype the command: {tty}"
        );
        // The edit path is still offered, since that is how a subset works.
        assert!(tty.contains("rachna revoke"), "{tty}");
    }

    #[test]
    fn every_command_the_prompt_offers_parses() {
        // Same rule as the revocations: an offered command the CLI rejects
        // is worse than none. Placeholders in angle brackets are the one
        // exception — they are a form to fill in, not a command to run — so
        // they are substituted with a real target first.
        for summary in [realistic(), long_summary()] {
            for interactive in [true, false] {
                for line in review_prompt(&summary, interactive).lines() {
                    let text = line.split('#').next().unwrap_or("").trim();
                    let Some(start) = text.find("rachna ") else {
                        continue;
                    };
                    let command = text[start..]
                        .replace("<category>", "network")
                        .replace("<target>", "a.test:443");
                    // Drop a trailing parenthetical like "(47 grants)".
                    let command = command.split('(').next().unwrap_or(&command).trim();
                    let argv: Vec<std::ffi::OsString> = command
                        .split_whitespace()
                        .map(std::ffi::OsString::from)
                        .collect();
                    let parsed = crate::cli::Invocation::from_argv(&argv);
                    assert!(
                        parsed.is_ok(),
                        "the prompt offers `{command}`, which the parser rejects: {:?}",
                        parsed.err()
                    );
                }
            }
        }
    }

    /// A summary with more grants than anyone would review one by one.
    fn long_summary() -> AccessSummary {
        let grants: Vec<Grant> = (0..40)
            .map(|n| Grant::Network {
                endpoint: endpoint(&format!("host{n}.test"), 443),
            })
            .collect();
        AccessSummary::new(Tier::Allowlist, Profile::Online, &grants)
    }

    #[test]
    fn a_realistic_config_is_reviewed_item_by_item() {
        // MEASURED: all nine project shapes in `20` declare 1 to 5
        // reviewable grants, so the per-item list must be the default for
        // every real config — a threshold that excluded them would make the
        // feature useless where it is wanted.
        assert!(
            !realistic().too_long_to_itemise(),
            "a 6-grant config was treated as too long to review"
        );
        // And the measured worst case, with headroom.
        let five = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants()[..5]);
        assert!(!five.too_long_to_itemise());
    }

    #[test]
    fn the_threshold_is_inclusive_at_its_limit() {
        // A mutation survivor: `>` and `>=` were indistinguishable because
        // no test sat exactly at the limit. Off by one here is not cosmetic
        // — it decides whether a 12-grant config gets the itemised list it
        // is sized for, so the boundary is pinned on both sides.
        let at_limit: Vec<Grant> = (0..PER_ITEM_REVIEW_LIMIT)
            .map(|n| Grant::Network {
                endpoint: endpoint(&format!("h{n}.test"), 443),
            })
            .collect();
        let summary = AccessSummary::new(Tier::Allowlist, Profile::Online, &at_limit);
        assert_eq!(summary.reviewable().len(), PER_ITEM_REVIEW_LIMIT);
        assert!(
            !summary.too_long_to_itemise(),
            "exactly {PER_ITEM_REVIEW_LIMIT} grants should still be itemised"
        );

        let one_over: Vec<Grant> = (0..=PER_ITEM_REVIEW_LIMIT)
            .map(|n| Grant::Network {
                endpoint: endpoint(&format!("h{n}.test"), 443),
            })
            .collect();
        let summary = AccessSummary::new(Tier::Allowlist, Profile::Online, &one_over);
        assert_eq!(summary.reviewable().len(), PER_ITEM_REVIEW_LIMIT + 1);
        assert!(
            summary.too_long_to_itemise(),
            "{} grants should roll up",
            PER_ITEM_REVIEW_LIMIT + 1
        );
    }

    #[test]
    fn a_very_long_list_is_not_offered_item_by_item() {
        // The case `00` §3.10c cares about most: a CLONED config, which is
        // exactly where a 40-host allowlist appears. A numbered list that
        // long is a wall rather than a review, and §3.10c's own warning is
        // that a summary people stop reading is "worse than nothing".
        let long = long_summary();
        assert!(long.too_long_to_itemise());

        // The per-category rollup is what makes it reviewable at all.
        let counts = long.counts_by_category();
        assert_eq!(counts, vec![(Category::Network, 40)]);

        // And the prompt changes shape: it points at `config inspect`
        // rather than implying the user should read 40 numbered lines.
        let prompt = review_prompt(&long, false);
        assert!(prompt.contains("config inspect"), "{prompt}");
        assert!(prompt.contains("40 grants"), "{prompt}");
        // Interactively, the same case offers `l` rather than a command —
        // the entries were rolled up, so there has to be a way to see them.
        let tty = review_prompt(&long, true);
        assert!(tty.contains("[l] list all 40 grants"), "{tty}");
    }

    #[test]
    fn counts_by_category_agree_with_the_itemised_list() {
        // Two views of one thing, so they must sum. A rollup that
        // disagreed with the list would make the long-config path report a
        // different total from the short one.
        let summary = realistic();
        let counts = summary.counts_by_category();
        let total: usize = counts.iter().map(|(_, count)| count).sum();
        assert_eq!(total, summary.reviewable().len());
        // Category order matches the display, so the rollup reads in the
        // same order as the list it replaces.
        let displayed: Vec<Category> = summary
            .reviewable()
            .iter()
            .map(|item| item.category)
            .collect();
        let mut seen: Vec<Category> = Vec::new();
        for category in displayed {
            if !seen.contains(&category) {
                seen.push(category);
            }
        }
        assert_eq!(counts.iter().map(|(c, _)| *c).collect::<Vec<_>>(), seen);
    }

    #[test]
    fn a_config_granting_nothing_asks_for_nothing() {
        // `00` §3.10c requires the summary even when empty — "secrets none
        // is information" — but offering accept-or-decline for an empty set
        // is noise.
        let sealed = AccessSummary::new(Tier::None, Profile::Sealed, &[]);
        for interactive in [true, false] {
            let prompt = review_prompt(&sealed, interactive);
            assert!(prompt.contains("grants nothing"), "{prompt}");
            assert!(!prompt.contains("--accept"), "{prompt}");
            assert!(!prompt.contains("[a]"), "{prompt}");
        }
    }

    // ---- property 1: completeness ----------------------------------------

    #[test]
    fn every_category_appears_even_when_it_grants_nothing() {
        // A category omitted from the output is a grant the user believes they
        // do not have. This is the property the whole feature rests on, so it
        // is asserted over Category::ALL rather than spot-checked.
        let summary = AccessSummary::new(Tier::Allowlist, Profile::Sealed, &[]);
        let rendered = summary.to_string();
        for category in Category::ALL {
            assert!(
                rendered.contains(category.as_str()),
                "{category} is missing from an empty summary:\n{rendered}"
            );
        }
        assert_eq!(summary.empty_categories(), Category::ALL.to_vec());
        assert!(summary.is_empty());
    }

    #[test]
    fn an_empty_category_renders_as_none_rather_than_being_skipped() {
        // "secrets none" is information; a missing line reads as "this config
        // does not touch credentials", which is a different claim.
        let summary = AccessSummary::new(Tier::Allowlist, Profile::Sealed, &[]);
        let rendered = summary.to_string();
        assert!(rendered.contains("secret    none"), "{rendered}");
    }

    #[test]
    fn empty_categories_names_exactly_the_ones_with_no_grants() {
        // Mutation testing found this: existing tests only checked the
        // all-empty and all-granted extremes, so a comparison flipped to `!=`
        // — reporting the categories that DO have grants — survived. A mixed
        // config is the case that distinguishes them.
        let summary = AccessSummary::new(
            Tier::Allowlist,
            Profile::Online,
            &[
                Grant::Secret {
                    name: "aws".to_owned(),
                },
                Grant::Port {
                    guest: 3000,
                    host: 3000,
                },
            ],
        );
        let empty = summary.empty_categories();
        for category in Category::ALL {
            let granted = matches!(category, Category::Secret | Category::Port);
            assert_eq!(
                empty.contains(&category),
                !granted,
                "{category}: granted={granted} but empty_categories disagrees"
            );
        }
    }

    #[test]
    fn a_realistic_config_renders_every_grant() {
        let summary = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let rendered = summary.to_string();
        for expected in [
            "registry.npmjs.org:443",
            "github.com:443",
            "/workspace  read-write",
            "3000 -> 3000",
            "aws",
            "rust-analyzer  lsp, no network",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected}:\n{rendered}"
            );
        }
        assert!(!summary.is_empty());
        assert!(summary.empty_categories().is_empty());
    }

    #[test]
    fn an_open_tier_is_reported_even_though_no_grant_records_it() {
        // The completeness hole that made holding the axes necessary: `open`
        // and `internet` permit any host WITHOUT an allowlist entry, so a
        // summary built from grants alone would show "network none" for a
        // config with unrestricted network access.
        for tier in [Tier::Open, Tier::Internet] {
            let summary = AccessSummary::new(tier, Profile::Development, &[]);
            let rendered = summary.to_string();
            assert!(
                rendered.contains("any host"),
                "tier {tier} understated network access:\n{rendered}"
            );
            assert!(
                !summary.is_empty(),
                "tier {tier} reported as granting nothing"
            );
        }
    }

    #[test]
    fn an_allowlist_tier_with_no_grants_reports_no_network() {
        // The converse: `allowlist` with nothing allowed really is no network,
        // so it must NOT claim "any host".
        let summary = AccessSummary::new(Tier::Allowlist, Profile::Development, &[]);
        assert!(!summary.to_string().contains("any host"));
    }

    // ---- property 2: keyed on the grant set, not the file ----------------

    #[test]
    fn reordering_grants_does_not_change_the_fingerprint() {
        // Property 2. If a reordered list re-gated, the acknowledgement would
        // become noise and people would alias it away.
        let mut reversed = realistic_grants();
        reversed.reverse();
        let a = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let b = AccessSummary::new(Tier::Allowlist, Profile::Online, &reversed);
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a, b, "the summary itself must be order-independent");
    }

    #[test]
    fn a_duplicated_grant_does_not_change_the_fingerprint() {
        // Declaring the same host twice grants no more than once.
        let mut doubled = realistic_grants();
        doubled.push(Grant::Network {
            endpoint: endpoint("github.com", 443),
        });
        let a = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let b = AccessSummary::new(Tier::Allowlist, Profile::Online, &doubled);
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn adding_a_grant_changes_the_fingerprint() {
        // The other half: a `git pull` that adds a grant must re-gate. This is
        // §3.11's supply-chain case arriving for free.
        let mut widened = realistic_grants();
        widened.push(Grant::Network {
            endpoint: endpoint("evil.example", 443),
        });
        let a = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let b = AccessSummary::new(Tier::Allowlist, Profile::Online, &widened);
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn widening_an_existing_grant_changes_the_fingerprint() {
        // The subtle case: the same path at a higher access level is a
        // different permission, and keying on a path alone would miss it.
        let read_only = vec![Grant::Filesystem {
            path: PathBuf::from("/workspace"),
            access: Access::ReadOnly,
        }];
        let read_write = vec![Grant::Filesystem {
            path: PathBuf::from("/workspace"),
            access: Access::ReadWrite,
        }];
        let a = AccessSummary::new(Tier::Allowlist, Profile::Online, &read_only);
        let b = AccessSummary::new(Tier::Allowlist, Profile::Online, &read_write);
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn changing_an_axis_changes_the_fingerprint() {
        // Both axes are part of what a config grants, so a tier or profile
        // change must re-gate even with identical grants.
        let grants = realistic_grants();
        let base = AccessSummary::new(Tier::Allowlist, Profile::Development, &grants);
        assert_ne!(
            base.fingerprint(),
            AccessSummary::new(Tier::Open, Profile::Development, &grants).fingerprint(),
            "tier must participate"
        );
        assert_ne!(
            base.fingerprint(),
            AccessSummary::new(Tier::Allowlist, Profile::Online, &grants).fingerprint(),
            "profile must participate"
        );
    }

    #[test]
    fn a_tool_gaining_network_access_changes_the_fingerprint() {
        // A tool is a distinct principal (00 §11.2), so the same tool with
        // network access is a different grant.
        let offline = vec![Grant::Tool {
            name: "rust-analyzer".to_owned(),
            kind: ToolKind::Lsp,
            network: false,
        }];
        let online = vec![Grant::Tool {
            name: "rust-analyzer".to_owned(),
            kind: ToolKind::Lsp,
            network: true,
        }];
        assert_ne!(
            AccessSummary::new(Tier::Allowlist, Profile::Online, &offline).fingerprint(),
            AccessSummary::new(Tier::Allowlist, Profile::Online, &online).fingerprint()
        );
    }

    #[test]
    fn the_fingerprint_is_stable_across_calls() {
        // It is written to disk to decide whether to re-gate, so instability
        // would re-prompt on every start.
        let summary = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        assert_eq!(summary.fingerprint(), summary.fingerprint());
    }

    /// Parses the rendering back into (category, entries), so tests can assert
    /// an entry appears under the RIGHT label rather than merely somewhere.
    ///
    /// Added because mutation testing killed nothing on the two category
    /// comparisons in `detail`: every existing test asserted only that a
    /// string was present, so mutants that filed grants under the wrong
    /// category survived. "Present somewhere" is not the property — the
    /// summary's whole job is saying *which* access you are granting.
    fn parse(summary: &AccessSummary) -> Vec<(String, Vec<String>)> {
        let mut out: Vec<(String, Vec<String>)> = Vec::new();
        for line in summary.to_string().lines() {
            let Some(rest) = line.strip_prefix("  ") else {
                continue;
            };
            if rest.is_empty() || rest.starts_with("rachna.nix") {
                continue;
            }
            let (label, entry) = rest.split_at(9);
            let (label, entry) = (label.trim(), entry.trim());
            if label.is_empty() {
                // A continuation line belongs to the preceding category.
                if let Some((_, entries)) = out.last_mut() {
                    entries.push(entry.to_owned());
                }
            } else {
                out.push((label.to_owned(), vec![entry.to_owned()]));
            }
        }
        out
    }

    #[test]
    fn each_grant_is_listed_under_its_own_category() {
        // Kills the `g.category() == category` mutant: with `!=`, every grant
        // would be filed under the wrong categories, which is a worse
        // completeness failure than omitting it — the user reads an access
        // they do not have and misses one they do.
        let summary = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let parsed = parse(&summary);
        let find = |label: &str| -> Vec<String> {
            parsed
                .iter()
                .find(|(l, _)| l == label)
                .map(|(_, e)| e.clone())
                .unwrap_or_default()
        };
        assert_eq!(
            find("network"),
            vec!["github.com:443", "registry.npmjs.org:443"]
        );
        assert_eq!(find("fs"), vec!["/workspace  read-write"]);
        assert_eq!(find("port"), vec!["3000 -> 3000"]);
        assert_eq!(find("secret"), vec!["aws  <- credential access"]);
        assert_eq!(find("tool"), vec!["rust-analyzer  lsp, no network"]);
    }

    #[test]
    fn an_open_tier_reports_any_host_under_network_and_nowhere_else() {
        // Kills the `category == Category::Network` mutant: with `!=`, every
        // category except network would claim "any host" — telling the user
        // their filesystem and credentials are unrestricted.
        let summary = AccessSummary::new(Tier::Open, Profile::Development, &[]);
        for (label, entries) in parse(&summary) {
            let claims_any_host = entries.iter().any(|e| e.contains("any host"));
            if label == "network" {
                assert!(claims_any_host, "network must report the open tier");
            } else {
                assert!(
                    !claims_any_host,
                    "{label} claimed 'any host', which is network's axis alone"
                );
            }
        }
    }

    #[test]
    fn a_credential_grant_is_visible_in_the_rendering() {
        // The grant a user most needs to notice in a cloned repo.
        let summary = AccessSummary::new(
            Tier::Allowlist,
            Profile::Online,
            &[Grant::Secret {
                name: "aws".to_owned(),
            }],
        );
        let rendered = summary.to_string();
        assert!(rendered.contains("secret"), "{rendered}");
        assert!(rendered.contains("aws"), "{rendered}");
        // Flagged explicitly: everything else in this summary is scoped, and
        // a credential is the thing that leaves the machine.
        assert!(rendered.contains("<- credential access"), "{rendered}");
    }

    // ---- the edit loop: selective acceptance by editing the file --------

    #[test]
    fn removing_the_credential_shows_as_a_removal() {
        // The §3.10c flow: you do not want the credential, so you delete it
        // and start again. The second summary must show that the edit took
        // effect, which is why removals are reported and not only additions.
        let before = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let narrowed: Vec<Grant> = realistic_grants()
            .into_iter()
            .filter(|g| g.category() != Category::Secret)
            .collect();
        let after = AccessSummary::new(Tier::Allowlist, Profile::Online, &narrowed);

        let diff = GrantDiff::between(&before, &after);
        assert_eq!(diff.to_string(), "  - secret  aws  <- credential access\n");
        assert!(!diff.is_empty());
        // The key property: narrowing does not need a fresh review.
        assert!(!diff.widens(), "removing a grant must not re-gate");
    }

    #[test]
    fn an_added_grant_widens_and_a_removed_one_does_not() {
        let base = AccessSummary::new(Tier::Allowlist, Profile::Online, &[]);
        let wider = AccessSummary::new(
            Tier::Allowlist,
            Profile::Online,
            &[Grant::Secret {
                name: "aws".to_owned(),
            }],
        );
        assert!(GrantDiff::between(&base, &wider).widens());
        assert!(!GrantDiff::between(&wider, &base).widens());
    }

    #[test]
    fn a_diff_reports_both_directions_at_once() {
        // An edit that swaps one host for another is both, and showing only
        // the addition would hide that the old grant is gone.
        let before = AccessSummary::new(
            Tier::Allowlist,
            Profile::Online,
            &[Grant::Network {
                endpoint: endpoint("old.example", 443),
            }],
        );
        let after = AccessSummary::new(
            Tier::Allowlist,
            Profile::Online,
            &[Grant::Network {
                endpoint: endpoint("new.example", 443),
            }],
        );
        let rendered = GrantDiff::between(&before, &after).to_string();
        assert!(rendered.contains("- network old.example:443"), "{rendered}");
        assert!(rendered.contains("+ network new.example:443"), "{rendered}");
    }

    #[test]
    fn an_unchanged_grant_set_produces_an_empty_diff() {
        let a = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let mut reordered = realistic_grants();
        reordered.reverse();
        let b = AccessSummary::new(Tier::Allowlist, Profile::Online, &reordered);
        let diff = GrantDiff::between(&a, &b);
        assert!(diff.is_empty(), "a reorder is not a change");
        assert!(!diff.widens());
        assert_eq!(diff.to_string(), "");
    }

    #[test]
    fn an_empty_diff_and_an_equal_fingerprint_always_agree() {
        // These two answer the same question by different routes — "must this
        // re-gate?" — so disagreement would mean either a silent re-prompt or
        // a silently-skipped review. Checked across a realistic set of edits.
        let base = AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants());
        let mut widened = realistic_grants();
        widened.push(Grant::Port {
            guest: 9999,
            host: 9999,
        });
        let variants = [
            AccessSummary::new(Tier::Allowlist, Profile::Online, &realistic_grants()),
            AccessSummary::new(Tier::Allowlist, Profile::Online, &widened),
            AccessSummary::new(Tier::Open, Profile::Online, &realistic_grants()),
            AccessSummary::new(Tier::Allowlist, Profile::Sealed, &realistic_grants()),
            AccessSummary::new(Tier::Allowlist, Profile::Online, &[]),
        ];
        for variant in &variants {
            let same_fingerprint = base.fingerprint() == variant.fingerprint();
            let empty_diff = GrantDiff::between(&base, variant).is_empty();
            assert_eq!(
                same_fingerprint, empty_diff,
                "fingerprint and diff disagree for {variant:?}"
            );
        }
    }

    #[test]
    fn a_forbidden_category_is_reported_as_forbidden_not_as_its_grants() {
        // The bug the fingerprint/diff agreement test found. A sealed profile
        // denies every secret at step 1 of the matching order (08 §1.2), so
        // listing `secret aws` would tell the user they have a credential
        // grant that `decide` will refuse.
        //
        // Overstating access is the same class of bug as omitting a category,
        // and the more dangerous direction: it invites accepting a config on
        // a false basis.
        let summary = AccessSummary::new(
            Tier::Allowlist,
            Profile::Sealed,
            &[Grant::Secret {
                name: "aws".to_owned(),
            }],
        );
        let rendered = summary.to_string();
        assert!(
            rendered.contains("none (sealed profile forbids it)"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("aws"),
            "a forbidden grant must not be listed as granted:\n{rendered}"
        );
        // And it is not counted as a grant.
        assert!(summary.is_empty());
        assert!(summary.empty_categories().contains(&Category::Secret));
    }

    #[test]
    fn changing_a_profile_shows_up_in_the_diff() {
        // Profiles gate whole categories, so tightening one is a real change
        // to what is granted and must be visible in the diff rather than only
        // in the fingerprint.
        let grants = vec![Grant::Secret {
            name: "aws".to_owned(),
        }];
        let online = AccessSummary::new(Tier::Allowlist, Profile::Online, &grants);
        let sealed = AccessSummary::new(Tier::Allowlist, Profile::Sealed, &grants);
        let diff = GrantDiff::between(&online, &sealed);
        assert!(!diff.is_empty(), "sealing a profile is a change");
        assert!(!diff.widens(), "sealing only removes access");
        assert!(diff.to_string().contains("- secret"), "{diff}");
    }

    #[test]
    fn changing_a_tier_shows_up_in_the_diff() {
        // The axes are part of what is granted, so a tier change must appear
        // in the diff and not only in the fingerprint.
        let before = AccessSummary::new(Tier::Allowlist, Profile::Online, &[]);
        let after = AccessSummary::new(Tier::Open, Profile::Online, &[]);
        let diff = GrantDiff::between(&before, &after);
        assert!(diff.widens(), "opening the network is a widening");
        assert!(diff.to_string().contains("any host"), "{diff}");
    }

    #[test]
    fn multiple_entries_in_one_category_are_all_shown() {
        // A summary that truncated would be a completeness hole.
        let grants: Vec<Grant> = (0..5)
            .map(|i| Grant::Port {
                guest: 3000 + i,
                host: 3000 + i,
            })
            .collect();
        // Online, not Sealed: the sealed profile forbids ports, so a sealed
        // config would correctly report them as forbidden rather than listing
        // them — which is what this test's first draft got wrong.
        let rendered = AccessSummary::new(Tier::None, Profile::Online, &grants).to_string();
        for i in 0..5 {
            assert!(
                rendered.contains(&format!("{} -> {}", 3000 + i, 3000 + i)),
                "{rendered}"
            );
        }
    }
}
