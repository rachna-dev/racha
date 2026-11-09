//! Named snapshots: taking them, listing them, choosing one to resume.
//!
//! # Why names rather than one file per project
//!
//! The first implementation kept exactly one snapshot, `memory.vzvmsave`,
//! overwritten on every suspend. That makes `suspend` destructive in a way
//! nothing announces: park a working environment, park a second one, and
//! the first is gone.
//!
//! `00` §7's Layer A is "close the laptop and come back", and the realistic
//! version of that has more than one thing parked — a known-good state
//! before an upgrade, a clean database, yesterday's debugging session.
//!
//! # What a name may be
//!
//! A name becomes a **filename**, so it is validated rather than trusted:
//! the same reasoning as [`ProjectId`](crate::layout::ProjectId), which is
//! the model this follows. A name with a `/` in it is an attempt to write
//! outside the snapshot directory, whether or not anyone meant it that way.

use crate::layout::ProjectPaths;
use std::path::PathBuf;

/// The extension every snapshot file carries.
///
/// Apple's own, so a user who finds one in Finder sees something their
/// system recognises rather than an opaque blob.
const EXTENSION: &str = "vzvmsave";

/// The name used when `suspend` is given none.
///
/// Not a timestamp: the common case is one parked environment per project,
/// and `rachna resume` with no argument should find it. A timestamped
/// default would make the simple case require a lookup.
pub const DEFAULT_NAME: &str = "latest";

/// A validated snapshot name.
///
/// A newtype rather than a `String`, so a name that reached a path was
/// checked on the way in — the pattern `untrusted.rs` applies to config
/// input and `ProjectId` applies to project directories.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SnapshotName(String);

/// Why a name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// Empty, which would name the directory itself.
    Empty,
    /// Longer than a filesystem will reliably carry.
    TooLong,
    /// Contains a path separator, or is `.` or `..`.
    NotASingleComponent,
    /// Contains something other than letters, digits, `-`, `_` or `.`.
    ///
    /// Deliberately narrow. A snapshot name is typed at a shell prompt and
    /// appears in `rachna snapshots` output, so spaces and quotes would
    /// make it awkward to use in exactly the place it is used.
    UnusableCharacter,
}

impl std::fmt::Display for NameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "a snapshot name cannot be empty"),
            Self::TooLong => write!(f, "a snapshot name must be {MAX_NAME} characters or fewer"),
            Self::NotASingleComponent => write!(
                f,
                "a snapshot name cannot contain `/` or `\\`, or be `.` or `..` \
                 — it is a name, not a path"
            ),
            Self::UnusableCharacter => write!(
                f,
                "a snapshot name may use letters, digits, `-`, `_` and `.` \
                 (it has to be typeable at a prompt)"
            ),
        }
    }
}

impl std::error::Error for NameError {}

/// The longest name accepted.
///
/// Well inside every filesystem's 255-byte limit, with room for the
/// extension — and short enough to line up in a listing.
const MAX_NAME: usize = 64;

impl SnapshotName {
    /// Validates a name.
    ///
    /// # Errors
    ///
    /// [`NameError`] saying which rule it broke, because "invalid name" does
    /// not tell a user what to type instead.
    pub fn new(name: impl Into<String>) -> Result<Self, NameError> {
        let name = name.into();
        if name.is_empty() {
            return Err(NameError::Empty);
        }
        if name.len() > MAX_NAME {
            return Err(NameError::TooLong);
        }
        // Checked BEFORE the character rule, so `..` gets the message about
        // paths rather than the one about characters — `.` is a legal
        // character and the problem with `..` is what it means.
        if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
            return Err(NameError::NotASingleComponent);
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(NameError::UnusableCharacter);
        }
        Ok(Self(name))
    }

    /// The default, which is always valid.
    #[must_use]
    pub fn default_name() -> Self {
        Self(DEFAULT_NAME.to_owned())
    }

    /// The name as typed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Where this snapshot's memory lives.
    #[must_use]
    pub fn path(&self, paths: &ProjectPaths) -> PathBuf {
        paths.snapshot_dir().join(format!("{}.{EXTENSION}", self.0))
    }
}

impl std::fmt::Display for SnapshotName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One snapshot on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Its name.
    pub name: SnapshotName,
    /// Bytes of memory written.
    pub bytes: u64,
    /// When it was taken, in seconds before now.
    ///
    /// Relative rather than absolute because that is what a user reads it
    /// as — "2 hours ago" answers the question "is this the one I want",
    /// and a timestamp makes them do the subtraction.
    pub age_seconds: u64,
}

impl Snapshot {
    /// The age, in the roughest unit that is still useful.
    ///
    /// One unit, not two: `2h ago` rather than `2h 14m ago`. A listing is
    /// scanned, and the minutes never change which snapshot you pick.
    #[must_use]
    pub fn age(&self) -> String {
        let s = self.age_seconds;
        if s < 60 {
            return "just now".to_owned();
        }
        if s < 3600 {
            return format!("{}m ago", s / 60);
        }
        if s < 86_400 {
            return format!("{}h ago", s / 3600);
        }
        format!("{}d ago", s / 86_400)
    }

    /// The size, as a user reads sizes.
    #[must_use]
    pub fn size(&self) -> String {
        let mib = self.bytes / (1024 * 1024);
        if mib >= 1024 {
            // One decimal place: the difference between 1.2G and 1.9G
            // matters when deciding what to prune.
            let tenths = (self.bytes * 10) / (1024 * 1024 * 1024);
            return format!("{}.{}G", tenths / 10, tenths % 10);
        }
        format!("{mib}M")
    }
}

/// Every snapshot in a project, newest first.
///
/// Newest first because the thing you just parked is the thing you most
/// likely want back.
///
/// # Errors
///
/// Nothing: a project with no snapshot directory has no snapshots, which is
/// an answer rather than a failure. An unreadable entry is skipped — but a
/// skipped entry is not silently dropped from a count, because the caller
/// only ever shows what is listed.
#[must_use]
pub fn list(paths: &ProjectPaths) -> Vec<Snapshot> {
    let dir = paths.snapshot_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let now = std::time::SystemTime::now();

    let mut found: Vec<Snapshot> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension()? != EXTENSION {
                return None;
            }
            let stem = path.file_stem()?.to_str()?;
            // Validated on the way OUT too. A file someone dropped in by
            // hand with a name we would refuse is not listed as a snapshot
            // we would resume — `resume` has to be able to trust a name it
            // read from this listing.
            let name = SnapshotName::new(stem).ok()?;
            let metadata = entry.metadata().ok()?;
            let age = metadata
                .modified()
                .ok()
                .and_then(|taken| now.duration_since(taken).ok())
                .map_or(0, |elapsed| elapsed.as_secs());
            Some(Snapshot {
                name,
                bytes: metadata.len(),
                age_seconds: age,
            })
        })
        .collect();

    found.sort_by(|a, b| a.age_seconds.cmp(&b.age_seconds).then(a.name.cmp(&b.name)));
    found
}

/// Finds one snapshot by name.
#[must_use]
pub fn find(paths: &ProjectPaths, name: &SnapshotName) -> Option<Snapshot> {
    list(paths).into_iter().find(|found| &found.name == name)
}

/// Which snapshot the live supervisor is holding, if any.
///
/// Read from the marker the supervisor writes when it suspends. [`None`]
/// when nothing is held — either no supervisor, or one with a running
/// guest rather than a parked one.
///
/// The name is validated on the way out for the same reason [`list`] does
/// it: a caller uses this to decide what to offer, and an unusable name
/// must not reach that decision.
#[must_use]
pub fn held_by_supervisor(paths: &ProjectPaths) -> Option<SnapshotName> {
    let marker = crate::supervise::held_marker(paths);
    let text = std::fs::read_to_string(marker).ok()?;
    SnapshotName::new(text.trim()).ok()
}

/// Renders a listing as a table.
///
/// `held` names the snapshot whose supervisor is still running, if any —
/// that one can be resumed, and the others cannot until `02` §6.11's
/// limitation is lifted. **Marked rather than hidden**, because a user who
/// cannot resume a snapshot still needs to see that it exists.
#[must_use]
pub fn render(snapshots: &[Snapshot], held: Option<&SnapshotName>) -> String {
    if snapshots.is_empty() {
        return "no snapshots. `rachna suspend` takes one\n".to_owned();
    }

    let widest = snapshots
        .iter()
        .map(|s| s.name.as_str().len())
        .max()
        .unwrap_or(4)
        .max(4);

    let mut out = String::new();
    out.push_str(&format!(
        "  {:<widest$}  {:>9}  {:>6}  {}\n",
        "NAME", "TAKEN", "SIZE", "STATE"
    ));
    for snapshot in snapshots {
        let is_held = held == Some(&snapshot.name);
        out.push_str(&format!(
            "{} {:<widest$}  {:>9}  {:>6}  {}\n",
            if is_held { "*" } else { " " },
            snapshot.name.as_str(),
            snapshot.age(),
            snapshot.size(),
            if is_held { "resumable" } else { "on disk" }
        ));
    }
    if held.is_some() {
        out.push_str("\n* its environment is still held, so `rachna resume` can restore it\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::ProjectId;

    fn paths(name: &str) -> (ProjectPaths, PathBuf) {
        let root = std::env::temp_dir().join(format!("rachna-snaps-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let project = ProjectId::new("demo-0001").expect("id");
        let paths = ProjectPaths::new(&root, &project);
        std::fs::create_dir_all(paths.snapshot_dir()).expect("dirs");
        (paths, root)
    }

    fn write(paths: &ProjectPaths, name: &str, bytes: usize) {
        let path = paths.snapshot_dir().join(format!("{name}.{EXTENSION}"));
        std::fs::write(path, vec![0_u8; bytes]).expect("write");
    }

    // ---- names are validated, because they become filenames ------------

    #[test]
    fn a_name_cannot_escape_the_snapshot_directory() {
        // The attack, and `ProjectId` is the model: a name with a separator
        // is an attempt to write elsewhere, whether or not it was meant as
        // one. First assert a NORMAL name works, or the rejections below
        // prove nothing.
        assert!(SnapshotName::new("before-upgrade").is_ok());

        for attempt in ["../escape", "a/b", "a\\b", "..", "."] {
            assert_eq!(
                SnapshotName::new(attempt),
                Err(NameError::NotASingleComponent),
                "`{attempt}` was accepted as a snapshot name"
            );
        }
    }

    #[test]
    fn a_name_stays_typeable_at_a_prompt() {
        // A name is typed back to resume by it, so the charset is narrow on
        // purpose. The message says what IS allowed, not just what is not.
        for attempt in ["my snapshot", "quote'd", "a;b", "sn*p"] {
            assert_eq!(
                SnapshotName::new(attempt),
                Err(NameError::UnusableCharacter),
                "`{attempt}` would be awkward to type back"
            );
        }
        for fine in ["clean-db", "v1.2", "pre_migrate", "Snap2"] {
            assert!(SnapshotName::new(fine).is_ok(), "`{fine}` was refused");
        }
    }

    #[test]
    fn every_name_error_says_what_to_do_instead() {
        // `00` §3.3: a message that names no action is not actionable, and
        // this one is read while retyping a command.
        for error in [
            NameError::Empty,
            NameError::TooLong,
            NameError::NotASingleComponent,
            NameError::UnusableCharacter,
        ] {
            let text = error.to_string();
            assert!(text.len() > 25, "{error:?} says too little: {text}");
        }
        // And the length limit states the number rather than "too long".
        assert!(
            NameError::TooLong.to_string().contains("64"),
            "{}",
            NameError::TooLong
        );
    }

    #[test]
    fn a_name_is_bounded_well_inside_what_a_filesystem_carries() {
        assert!(SnapshotName::new("a".repeat(MAX_NAME)).is_ok());
        assert_eq!(
            SnapshotName::new("a".repeat(MAX_NAME + 1)),
            Err(NameError::TooLong)
        );
    }

    // ---- listing --------------------------------------------------------

    #[test]
    fn a_project_with_no_snapshots_lists_nothing_rather_than_failing() {
        // `00` §5.2's spirit: these commands are safe to type when you are
        // not sure what is going on.
        let (paths, root) = paths("empty");
        assert!(list(&paths).is_empty());
        assert!(render(&[], None).contains("rachna suspend"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn snapshots_are_listed_newest_first() {
        // The one you just parked is the one you most likely want back.
        let (paths, root) = paths("order");
        write(&paths, "oldest", 16);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        write(&paths, "newest", 16);

        let found = list(&paths);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].name.as_str(), "newest", "{found:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn only_snapshot_files_are_listed() {
        // A console log or a stray file in the directory is not a snapshot,
        // and listing one would offer a resume that cannot work.
        let (paths, root) = paths("filter");
        write(&paths, "real", 16);
        std::fs::write(paths.snapshot_dir().join("notes.txt"), b"x").expect("write");
        std::fs::write(paths.snapshot_dir().join("grants.fingerprint"), b"x").expect("write");

        let found = list(&paths);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].name.as_str(), "real");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_file_whose_name_we_would_refuse_is_not_listed_as_resumable() {
        // Validated on the way OUT as well as in: `resume` trusts a name it
        // read from this listing, so a hand-dropped file with an unusable
        // name must not appear there.
        let (paths, root) = paths("refuse");
        write(&paths, "fine", 16);
        std::fs::write(
            paths.snapshot_dir().join(format!("has space.{EXTENSION}")),
            b"x",
        )
        .expect("write");

        let found = list(&paths);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].name.as_str(), "fine");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn find_locates_a_snapshot_by_name_and_misses_cleanly() {
        let (paths, root) = paths("find");
        write(&paths, "wanted", 16);

        let name = SnapshotName::new("wanted").expect("valid");
        assert!(find(&paths, &name).is_some());
        let absent = SnapshotName::new("absent").expect("valid");
        assert!(find(&paths, &absent).is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    // ---- rendering ------------------------------------------------------

    #[test]
    fn the_listing_marks_which_snapshot_can_actually_be_resumed() {
        // `02` §6.11: only the process that saved a snapshot can restore
        // it, so at most one is resumable. Marked rather than hidden — a
        // user who cannot resume one still needs to know it exists.
        let held = SnapshotName::new("held").expect("valid");
        let snapshots = vec![
            Snapshot {
                name: held.clone(),
                bytes: 132 * 1024 * 1024,
                age_seconds: 120,
            },
            Snapshot {
                name: SnapshotName::new("cold").expect("valid"),
                bytes: 118 * 1024 * 1024,
                age_seconds: 90_000,
            },
        ];

        let rendered = render(&snapshots, Some(&held));
        assert!(rendered.contains("held"), "{rendered}");
        assert!(rendered.contains("cold"), "{rendered}");
        assert!(rendered.contains("resumable"), "{rendered}");
        assert!(rendered.contains("on disk"), "{rendered}");
        // And it explains the asterisk rather than leaving it decorative.
        assert!(rendered.contains("still held"), "{rendered}");

        // With nothing held, no asterisk legend — an explanation of a mark
        // that is not there is noise.
        let cold_only = render(&snapshots, None);
        assert!(!cold_only.contains("still held"), "{cold_only}");
    }

    #[test]
    fn sizes_and_ages_read_the_way_a_person_reads_them() {
        let snapshot = |bytes: u64, age: u64| Snapshot {
            name: SnapshotName::new("x").expect("valid"),
            bytes,
            age_seconds: age,
        };
        assert_eq!(snapshot(126 * 1024 * 1024, 0).size(), "126M");
        // Over a gibibyte, one decimal: the difference between 1.2G and
        // 1.9G decides what gets pruned.
        assert_eq!(snapshot(1_288_490_188, 0).size(), "1.1G");

        assert_eq!(snapshot(0, 12).age(), "just now");
        assert_eq!(snapshot(0, 600).age(), "10m ago");
        assert_eq!(snapshot(0, 7200).age(), "2h ago");
        assert_eq!(snapshot(0, 180_000).age(), "2d ago");
    }

    #[test]
    fn the_listing_columns_line_up_whatever_the_names() {
        // Scanned, not read: a listing whose columns move is one a user has
        // to parse rather than skim.
        let snapshots = vec![
            Snapshot {
                name: SnapshotName::new("a").expect("valid"),
                bytes: 1024 * 1024,
                age_seconds: 60,
            },
            Snapshot {
                name: SnapshotName::new("a-very-long-snapshot-name").expect("valid"),
                bytes: 1024 * 1024,
                age_seconds: 60,
            },
        ];
        let rendered = render(&snapshots, None);
        let lines: Vec<&str> = rendered.lines().collect();
        // Header plus both rows, each with SIZE ending in the same column.
        let size_column = |line: &str| line.find('M').expect("a size");
        assert_eq!(
            size_column(lines[1]),
            size_column(lines[2]),
            "columns do not line up:\n{rendered}"
        );
    }
}
