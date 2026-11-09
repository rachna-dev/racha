//! Argument parsing, and the multi-call shim.
//!
//! `17-DEPENDENCIES.md` §1 chose `lexopt` over `clap` for reasons specific to
//! this design: **~37 KB against ~574 KB**, and a shim is spawned *per editor
//! tool invocation*, so startup cost is what we are most sensitive to.
//!
//! # Multi-call dispatch happens before any parsing
//!
//! `.rachna/bin/rust-analyzer` must pass `--help` to the **guest** tool, not
//! have a parser interpret it. So [`Invocation::from_argv`] looks at
//! `argv[0]` *first* and returns [`Invocation::Shim`] with the arguments
//! untouched — flag-eating is structurally impossible rather than carefully
//! avoided.
//!
//! # Why this module parses but does not act
//!
//! It turns `argv` into a [`Command`] or a refusal. No filesystem, no
//! process spawning, no VM — so every verb and every malformed invocation is
//! table-testable, which is what makes step 10's "demoable with no VM"
//! claim checkable rather than aspirational.

use crate::decision::{Access, Category};
// `ToolKind` is grant.rs's, not a second copy. An earlier version of this
// module defined its own with FOUR variants against grant.rs's three — two
// lists that disagreed, and the config parser rejected the spelling `00`
// §6.4 documents. The variant was added to the owner and this copy deleted.
use crate::grant::ToolKind;
use core::fmt;
use std::ffi::OsString;

/// What the binary was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// Invoked as `rachna`, with a subcommand.
    Rachna(Command),
    /// Invoked under a tool's name, as a shim.
    ///
    /// Carries the arguments **verbatim**: a shim's job is to hand them to
    /// the guest tool unchanged, so anything that looked at them would be a
    /// bug. `17` §1 verified `lexopt::raw_args()` hands them back untouched,
    /// and this type is what preserves that property upward.
    Shim {
        /// The tool name, from `argv[0]`.
        tool: String,
        /// Every argument after `argv[0]`, uninterpreted.
        args: Vec<OsString>,
    },
}

/// A change to `rachna.nix` that a verb is asking for.
///
/// `00` §5.3 lists seven verbs that all do the same thing — `revoke`,
/// `expose`, `unexpose`, `add`, `port`, `set` and `secret` — and the reason
/// they are one type rather than seven `Command` variants is that they share
/// the part that is hard. Rule 2 of §5.3 applies to every one of them:
///
/// > Surgical, comment-preserving edits via an rnix CST — not AST
/// > re-printing. If the file uses a construct that can't be safely modified,
/// > **refuse and print the snippet to paste.** Never silently rewrite.
///
/// Seven variants would mean seven places to get that refusal wrong. One type
/// means the editor and the fallback snippet are written once.
///
/// # Why these are not in `Command` individually
///
/// `21` §2.5 found these seven missing while eight others were correctly
/// deferred for needing a backend. These need nothing — they edit a file —
/// which is why they belong here now and the other eight do not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    /// `rachna allow <category> <target>...`
    ///
    /// Grants access. `Access` rather than two bools: `00` §5.3's example
    /// `allow fs ~/.npmrc --read-only` has to distinguish read from write,
    /// and `decision.rs` already owns that distinction.
    Allow {
        category: Category,
        targets: Vec<String>,
        access: Option<Access>,
    },
    /// `rachna revoke <category> <target>...`
    ///
    /// The inverse of `Allow`, and deliberately the same shape: a user who
    /// can write the grant can remove it by retyping it with a different
    /// verb. No `--all`, because `00` §10 is explicit that there is one
    /// authority and removing a grant you cannot name is how you remove one
    /// you did not mean to.
    Revoke {
        category: Category,
        targets: Vec<String>,
    },
    /// `rachna expose <kind> <name>`
    ///
    /// `00` §6.4: exposing a tool is a *declared permission*, not a shim
    /// directory entry. The kind is required because it decides the scope a
    /// tool gets — an LSP needs the workspace read-write, a formatter does
    /// not.
    Expose { kind: ToolKind, name: String },
    /// `rachna unexpose <name>`
    ///
    /// No kind: the name is already unique in `tools.expose`, and asking for
    /// the kind again to remove something would mean a user who got it wrong
    /// could not undo it.
    Unexpose { name: String },
    /// `rachna add package <name>`
    ///
    /// `00` §5.3's example. The `package` word is kept rather than implied so
    /// the verb can grow a second noun without changing meaning.
    AddPackage { name: String },
    /// `rachna port <number>`
    ///
    /// A `u16` because that is what a port is; a port of 70000 is a usage
    /// error caught by the parser rather than a policy error caught later.
    Port { number: u16 },
    /// `rachna set <path> <value>`
    ///
    /// `00` §5.3's example is `set resources.memory 8GB`. The path is not
    /// validated here: `00` §5.3 rule 4 requires an unknown key to be an
    /// **error**, and the thing that can tell is `lib.evalModules`, not a
    /// parser. Refusing here on a guess would reject valid options.
    Set { path: String, value: String },
    /// `rachna secret <name>`
    ///
    /// Declares a credential placeholder (`00` §3.6). Name only — the same
    /// rule as [`Grant::Secret`](crate::grant::Grant::Secret), which holds a
    /// name and never a value, so a secret cannot reach the store or a log by
    /// passing through this type.
    Secret { name: String },
}

impl Edit {
    /// The verb a user typed to ask for this edit.
    #[must_use]
    pub const fn verb(&self) -> &'static str {
        match self {
            Self::Allow { .. } => "allow",
            Self::Revoke { .. } => "revoke",
            Self::Expose { .. } => "expose",
            Self::Unexpose { .. } => "unexpose",
            Self::AddPackage { .. } => "add",
            Self::Port { .. } => "port",
            Self::Set { .. } => "set",
            Self::Secret { .. } => "secret",
        }
    }

    /// Whether this edit widens what the project may do.
    ///
    /// The distinction `00` §3 rests on, surfaced as a question the type can
    /// answer: a widening edit is one a reviewer must look at, and
    /// `rachna.nix` landing in a diff is the whole review mechanism. Removing
    /// access needs no such scrutiny.
    ///
    /// `Set` counts as widening because `resources.memory` and
    /// `isolation.network.default` go through the same verb, and a parser
    /// cannot tell which without the module schema. Treating the unknown case
    /// as widening is the safe direction.
    #[must_use]
    pub const fn widens_access(&self) -> bool {
        match self {
            Self::Allow { .. }
            | Self::Expose { .. }
            | Self::AddPackage { .. }
            | Self::Port { .. }
            | Self::Secret { .. }
            | Self::Set { .. } => true,
            Self::Revoke { .. } | Self::Unexpose { .. } => false,
        }
    }
}

/// A `rachna` subcommand.
///
/// `00-PRODUCT.md` §5.2 lists the surface. Only the verbs reachable without a
/// hypervisor are represented so far — the rest land with the backend, and
/// inventing them now would mean a CLI that accepts commands nothing can
/// execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `rachna init [--template <url>]`
    Init { template: Option<String> },
    /// `rachna start [--accept]`
    ///
    /// Also the resume path: there is no separate `resume` verb.
    ///
    /// `--accept` acknowledges the access summary **in CI only**. At a
    /// terminal it is ignored, because `00` §3.10c makes the gate a
    /// keypress: a flag that worked interactively would let a user accept a
    /// cloned config's permissions in the same breath as asking to start
    /// it, which is the one thing the gate exists to prevent.
    Start { accept: bool },
    /// `rachna stop`
    Stop,
    /// `rachna status`
    Status,
    /// `rachna doctor`
    Doctor,
    /// `rachna config inspect | diff | validate`
    Config { action: ConfigAction },
    /// `rachna audit [--narrow] [--ci]`
    Audit { narrow: bool, ci: bool },
    /// `rachna explain <run-id>`
    Explain { run_id: String },
    /// A change to `rachna.nix`: `allow`, `revoke`, `expose`, `unexpose`,
    /// `add`, `port`, `set` or `secret`.
    ///
    /// One variant rather than eight, because `00` §5.3 rule 2 applies
    /// identically to all of them — see [`Edit`].
    Edit(Edit),
    /// `rachna --version`
    Version,
    /// `rachna --help` or no arguments.
    Help,
}

impl Command {
    /// The verb a user typed to get here.
    ///
    /// Lives on the type rather than in `main.rs`, which is where it started.
    /// Mutation testing is why it moved: `main` is not tested without a
    /// process, so the only caller could not observe the return value and
    /// every mutant replacing it with a constant survived. Here the
    /// round-trip against [`Invocation::from_argv`] kills them — the same
    /// shape as [`ConfigAction::as_str`], and the same conclusion as the
    /// wrappers deleted for being indistinguishable from constants.
    #[must_use]
    pub const fn verb(&self) -> &'static str {
        match self {
            Self::Init { .. } => "init",
            Self::Start { .. } => "start",
            Self::Stop => "stop",
            Self::Status => "status",
            Self::Doctor => "doctor",
            Self::Config { action } => match action {
                ConfigAction::Inspect => "config inspect",
                ConfigAction::Diff => "config diff",
                ConfigAction::Validate => "config validate",
            },
            Self::Audit { .. } => "audit",
            Self::Explain { .. } => "explain",
            // Delegated rather than listed: the edit verbs' names live on
            // `Edit`, so there is one list, not two that can disagree.
            Self::Edit(edit) => edit.verb(),
            Self::Version => "--version",
            Self::Help => "--help",
        }
    }
}

/// What `rachna config` was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigAction {
    /// The fully-evaluated effective config.
    Inspect,
    /// Live runtime versus the file.
    Diff,
    /// Check without applying.
    Validate,
}

impl ConfigAction {
    /// Every action.
    pub const ALL: [Self; 3] = [Self::Inspect, Self::Diff, Self::Validate];

    /// The word a user types.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Diff => "diff",
            Self::Validate => "validate",
        }
    }

    /// Parses the word.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|action| action.as_str() == word)
    }
}

/// Why an invocation could not be understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// No such subcommand.
    ///
    /// Carries a suggestion when one is close, reusing the same
    /// nearest-match idea as the config renderer — a confident wrong
    /// suggestion is worse than none, so the cutoff is the same.
    UnknownCommand {
        given: String,
        suggestion: Option<&'static str>,
    },
    /// A subcommand needed an argument it did not get.
    MissingArgument {
        command: &'static str,
        what: &'static str,
    },
    /// A flag this subcommand does not take.
    UnexpectedFlag { command: &'static str, flag: String },
    /// Two mutually exclusive flags.
    ConflictingFlags {
        first: &'static str,
        second: &'static str,
    },
    /// An argument was not valid UTF-8 where UTF-8 is required.
    ///
    /// Not a lossy conversion: `17` §1 establishes that a lossy path does not
    /// round-trip, and a hostname or run-id that cannot be represented must
    /// be refused rather than silently altered.
    NotUtf8 { command: &'static str },
    /// More arguments than the verb takes.
    ///
    /// Its own variant rather than reusing [`Self::UnexpectedFlag`], because
    /// the two have different fixes: a bad flag is a typo, while an extra
    /// argument usually means the user expected the verb to take a list.
    TooManyArguments {
        command: &'static str,
        expected: &'static str,
    },
    /// Not one of the five access categories.
    ///
    /// Caught at parse time rather than at policy time: `allow nework x`
    /// previously produced a `String` the parser accepted and something later
    /// rejected, which is the "declared and never enforced" shape `00` §5.3
    /// rule 4 argues against.
    UnknownCategory { given: String },
    /// Not one of the four tool kinds.
    UnknownToolKind { given: String },
    /// The verb took a noun it does not know, as in `add thing`.
    UnknownNoun {
        command: &'static str,
        given: String,
        expected: &'static str,
    },
    /// Not a usable port number.
    NotAPort { given: String },
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand { given, suggestion } => {
                write!(f, "unknown command `{given}`")?;
                if let Some(suggestion) = suggestion {
                    write!(f, " — did you mean `{suggestion}`?")?;
                }
                Ok(())
            }
            Self::MissingArgument { command, what } => {
                write!(f, "`rachna {command}` needs {what}")
            }
            Self::UnexpectedFlag { command, flag } => {
                write!(f, "`rachna {command}` does not take `{flag}`")
            }
            Self::ConflictingFlags { first, second } => {
                write!(f, "`{first}` and `{second}` cannot both be given")
            }
            Self::NotUtf8 { command } => {
                write!(
                    f,
                    "`rachna {command}` was given an argument that is not valid UTF-8"
                )
            }
            Self::TooManyArguments { command, expected } => {
                write!(f, "`rachna {command}` takes {expected}")
            }
            // Each of these names the valid set rather than only rejecting,
            // because `22` §4.2's format and `00` §3.3's rules both require a
            // message to carry the fix. "unknown category" alone makes the
            // user go and find the list.
            Self::UnknownCategory { given } => {
                write!(
                    f,
                    "`{given}` is not an access category. The five are: {}",
                    Category::ALL.map(Category::as_str).join(", ")
                )
            }
            Self::UnknownToolKind { given } => {
                write!(
                    f,
                    "`{given}` is not a tool kind. The four are: {}",
                    ToolKind::ALL.map(ToolKind::as_str).join(", ")
                )
            }
            Self::UnknownNoun {
                command,
                given,
                expected,
            } => {
                write!(
                    f,
                    "`rachna {command} {given}` is not a thing to {command} — \
                     try `rachna {command} {expected} <name>`"
                )
            }
            Self::NotAPort { given } => {
                write!(f, "`{given}` is not a port number: a port is 1 to 65535")
            }
        }
    }
}

impl core::error::Error for CliError {}

impl Invocation {
    /// Dispatches on `argv[0]`, then parses.
    ///
    /// # Errors
    ///
    /// [`CliError`] when the `rachna` path cannot be understood. A shim never
    /// errors: its arguments are not ours to validate.
    pub fn from_argv(argv: &[OsString]) -> Result<Self, CliError> {
        let program = argv
            .first()
            .map(basename)
            .unwrap_or_else(|| "rachna".to_owned());

        // THE multi-call check, before anything looks at a flag. A shim must
        // hand `--help` to the guest tool, and a parser that saw it first
        // would answer for itself.
        if program != "rachna" {
            return Ok(Self::Shim {
                tool: program,
                args: argv.iter().skip(1).cloned().collect(),
            });
        }

        // `get(1..)` rather than `&argv[1..]`: an empty argv is not
        // reachable from a shell, but indexing would PANIC rather than
        // refuse — and a panic in argument parsing is the one failure a
        // user cannot act on. Found by a test written for exactly this.
        let args = split_equals(argv.get(1..).unwrap_or(&[]));
        Ok(Self::Rachna(parse_command(&args)?))
    }
}

/// The file name of a path, as a lossy string.
///
/// Lossy is correct *here* and only here: this is a comparison against known
/// ASCII names for dispatch, and a non-UTF-8 program name cannot be `rachna`
/// or a declared tool. Everywhere a value is *used* rather than dispatched
/// on, `OsString` is preserved — `17` §1's rule.
fn basename(arg: &OsString) -> String {
    std::path::Path::new(arg).file_name().map_or_else(
        || arg.to_string_lossy().into_owned(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// Splits `--flag=value` into `--flag` `value`.
///
/// Users type both forms and `--template=https://…` was rejected before this
/// existed — found by running the binary, not by reading the parser. Done in
/// one pass up front rather than per flag, so every option gets it and none
/// can be forgotten.
///
/// **Only for the `rachna` path.** A shim's arguments are never normalised:
/// `17` §1 requires them handed to the guest tool untouched, and splitting a
/// tool's own `--flag=value` would corrupt it.
///
/// Splits on the FIRST `=` only, so a value containing one survives —
/// `--template=https://x/?a=b` keeps its query string.
fn split_equals(args: &[OsString]) -> Vec<OsString> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        let text = arg.to_string_lossy();
        match text
            .strip_prefix("--")
            .and_then(|rest| rest.split_once('='))
        {
            Some((flag, value)) if !flag.is_empty() => {
                out.push(OsString::from(format!("--{flag}")));
                out.push(OsString::from(value));
            }
            // Not a `--flag=value`: pushed unchanged, preserving the original
            // OsString rather than the lossy text, so a non-UTF-8 argument
            // still reaches its command intact to be refused there.
            _ => out.push(arg.clone()),
        }
    }
    out
}

/// Every subcommand name, for suggestions.
/// Every verb the parser accepts.
///
/// Used both for dispatch's nearest-match suggestion and by the test that
/// every one of these appears in `--help`. One list, so a verb cannot be
/// added to the parser and missed by either.
const COMMANDS: &[&str] = &[
    "init", "start", "stop", "status", "doctor", "config", "audit", "explain",
    // The `rachna.nix`-editing verbs (`00` §5.3). `21` §2.5 found these
    // missing from step 10 while the backend verbs were correctly deferred.
    "allow", "revoke", "expose", "unexpose", "add", "port", "set", "secret",
];

fn parse_command(args: &[OsString]) -> Result<Command, CliError> {
    let Some(first) = args.first() else {
        return Ok(Command::Help);
    };
    let word = first.to_string_lossy();

    match word.as_ref() {
        "--version" | "-V" => return Ok(Command::Version),
        "--help" | "-h" | "help" => return Ok(Command::Help),
        _ => {}
    }

    let rest = &args[1..];
    match word.as_ref() {
        "init" => parse_init(rest),
        "start" => parse_start(rest),
        "stop" => expect_no_args("stop", rest, Command::Stop),
        "status" => expect_no_args("status", rest, Command::Status),
        "doctor" => expect_no_args("doctor", rest, Command::Doctor),
        "config" => parse_config(rest),
        "audit" => parse_audit(rest),
        "explain" => parse_explain(rest),
        "allow" => parse_allow(rest),
        "revoke" => parse_revoke(rest),
        "expose" => parse_expose(rest),
        "unexpose" => parse_unexpose(rest),
        "add" => parse_add(rest),
        "port" => parse_port(rest),
        "set" => parse_set(rest),
        "secret" => parse_secret(rest),
        other => Err(CliError::UnknownCommand {
            given: other.to_owned(),
            suggestion: nearest_command(other),
        }),
    }
}

fn parse_init(args: &[OsString]) -> Result<Command, CliError> {
    let mut template = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.to_string_lossy().as_ref() {
            "--template" => {
                let value = iter.next().ok_or(CliError::MissingArgument {
                    command: "init",
                    what: "a URL after `--template`",
                })?;
                template = Some(
                    value
                        .to_str()
                        .ok_or(CliError::NotUtf8 { command: "init" })?
                        .to_owned(),
                );
            }
            flag => {
                return Err(CliError::UnexpectedFlag {
                    command: "init",
                    flag: flag.to_owned(),
                })
            }
        }
    }
    Ok(Command::Init { template })
}

fn parse_start(args: &[OsString]) -> Result<Command, CliError> {
    let mut accept = false;
    for arg in args {
        match arg.to_string_lossy().as_ref() {
            "--accept" => accept = true,
            flag => {
                return Err(CliError::UnexpectedFlag {
                    command: "start",
                    flag: flag.to_owned(),
                })
            }
        }
    }
    Ok(Command::Start { accept })
}

fn parse_config(args: &[OsString]) -> Result<Command, CliError> {
    let Some(word) = args.first() else {
        return Err(CliError::MissingArgument {
            command: "config",
            what: "one of inspect, diff, validate",
        });
    };
    let action =
        ConfigAction::parse(&word.to_string_lossy()).ok_or_else(|| CliError::UnknownCommand {
            given: word.to_string_lossy().into_owned(),
            suggestion: ConfigAction::ALL
                .into_iter()
                .map(ConfigAction::as_str)
                .find(|known| known.starts_with(&word.to_string_lossy()[..1])),
        })?;
    expect_no_args("config", &args[1..], Command::Config { action })
}

fn parse_audit(args: &[OsString]) -> Result<Command, CliError> {
    let mut narrow = false;
    let mut ci = false;
    for arg in args {
        match arg.to_string_lossy().as_ref() {
            "--narrow" => narrow = true,
            "--ci" => ci = true,
            flag => {
                return Err(CliError::UnexpectedFlag {
                    command: "audit",
                    flag: flag.to_owned(),
                })
            }
        }
    }
    Ok(Command::Audit { narrow, ci })
}

fn parse_explain(args: &[OsString]) -> Result<Command, CliError> {
    let run_id = args.first().ok_or(CliError::MissingArgument {
        command: "explain",
        what: "a run id",
    })?;
    let run_id = run_id
        .to_str()
        .ok_or(CliError::NotUtf8 { command: "explain" })?
        .to_owned();
    expect_no_args("explain", &args[1..], Command::Explain { run_id })
}

/// A category plus one or more targets, shared by `allow` and `revoke`.
///
/// One function because the two verbs take the same arguments and must
/// disagree about nothing: a user who can write a grant must be able to name
/// it identically to remove it.
fn parse_category_and_targets(
    command: &'static str,
    args: &[OsString],
) -> Result<(Category, Vec<String>, Option<Access>), CliError> {
    let mut category_word = None;
    let mut targets = Vec::new();
    let mut read_only = false;
    let mut read_write = false;

    for arg in args {
        let word = arg.to_string_lossy();
        match word.as_ref() {
            "--read-only" => read_only = true,
            "--read-write" => read_write = true,
            flag if flag.starts_with("--") => {
                return Err(CliError::UnexpectedFlag {
                    command,
                    flag: flag.to_owned(),
                })
            }
            _ if category_word.is_none() => {
                category_word = Some(
                    arg.to_str()
                        .ok_or(CliError::NotUtf8 { command })?
                        .to_owned(),
                );
            }
            _ => targets.push(
                arg.to_str()
                    .ok_or(CliError::NotUtf8 { command })?
                    .to_owned(),
            ),
        }
    }

    // Both flags given is a contradiction, not a widening: silently picking
    // read-write would grant more than one of the two things the user asked
    // for, and picking read-only would grant less. Refusing makes them say.
    if read_only && read_write {
        return Err(CliError::ConflictingFlags {
            first: "--read-only",
            second: "--read-write",
        });
    }

    let word = category_word.ok_or(CliError::MissingArgument {
        command,
        what: "a category: network, fs, port, secret or tool",
    })?;
    // Parsed through `Category` rather than kept as a `String`, so
    // `rachna allow nework github.com` is a usage error here instead of a
    // confusing policy error much later. `Category::parse` lives next to
    // `as_str`, which is the one definition of these words.
    let category = Category::parse(&word).ok_or(CliError::UnknownCategory { given: word })?;

    if targets.is_empty() {
        return Err(CliError::MissingArgument {
            command,
            what: "at least one target",
        });
    }

    let access = match (read_only, read_write) {
        (true, _) => Some(Access::ReadOnly),
        (_, true) => Some(Access::ReadWrite),
        _ => None,
    };
    Ok((category, targets, access))
}

fn parse_allow(args: &[OsString]) -> Result<Command, CliError> {
    let (category, targets, access) = parse_category_and_targets("allow", args)?;
    Ok(Command::Edit(Edit::Allow {
        category,
        targets,
        access,
    }))
}

fn parse_revoke(args: &[OsString]) -> Result<Command, CliError> {
    // `revoke` accepts the access flags and ignores them rather than
    // refusing: a user copying their own `allow` line and changing the verb
    // is doing the obvious thing, and `fs ~/.npmrc --read-only` names exactly
    // one grant whether or not the flag is repeated.
    let (category, targets, _) = parse_category_and_targets("revoke", args)?;
    Ok(Command::Edit(Edit::Revoke { category, targets }))
}

fn parse_expose(args: &[OsString]) -> Result<Command, CliError> {
    let mut words = Vec::new();
    for arg in args {
        let word = arg.to_string_lossy();
        if word.starts_with("--") {
            return Err(CliError::UnexpectedFlag {
                command: "expose",
                flag: word.into_owned(),
            });
        }
        words.push(
            arg.to_str()
                .ok_or(CliError::NotUtf8 { command: "expose" })?,
        );
    }
    let (kind_word, name) = match words.as_slice() {
        [] => {
            return Err(CliError::MissingArgument {
                command: "expose",
                what: "a kind: lsp, formatter, debugger or command",
            })
        }
        [_] => {
            return Err(CliError::MissingArgument {
                command: "expose",
                what: "the tool's name, as in `expose formatter prettier`",
            })
        }
        [kind, name] => (*kind, *name),
        // Deliberately refused rather than exposing the first: `00` §6.4
        // gives each tool its own scope, so two names mean two decisions.
        _ => {
            return Err(CliError::TooManyArguments {
                command: "expose",
                expected: "one kind and one tool name",
            })
        }
    };
    let kind = ToolKind::parse(kind_word).ok_or(CliError::UnknownToolKind {
        given: kind_word.to_owned(),
    })?;
    Ok(Command::Edit(Edit::Expose {
        kind,
        name: name.to_owned(),
    }))
}

fn parse_unexpose(args: &[OsString]) -> Result<Command, CliError> {
    let name = exactly_one("unexpose", args, "the tool's name")?;
    Ok(Command::Edit(Edit::Unexpose { name }))
}

fn parse_add(args: &[OsString]) -> Result<Command, CliError> {
    let mut words = Vec::new();
    for arg in args {
        let word = arg.to_string_lossy();
        if word.starts_with("--") {
            return Err(CliError::UnexpectedFlag {
                command: "add",
                flag: word.into_owned(),
            });
        }
        words.push(arg.to_str().ok_or(CliError::NotUtf8 { command: "add" })?);
    }
    match words.as_slice() {
        // `00` §5.3's spelling is `add package <name>`. The noun is required
        // rather than implied so a future `add service` cannot change what an
        // existing command means.
        ["package", name] => Ok(Command::Edit(Edit::AddPackage {
            name: (*name).to_owned(),
        })),
        [] => Err(CliError::MissingArgument {
            command: "add",
            what: "what to add: `add package <name>`",
        }),
        [other] => Err(CliError::UnknownNoun {
            command: "add",
            given: (*other).to_owned(),
            expected: "package",
        }),
        [other, ..] if *other != "package" => Err(CliError::UnknownNoun {
            command: "add",
            given: (*other).to_owned(),
            expected: "package",
        }),
        _ => Err(CliError::TooManyArguments {
            command: "add",
            expected: "one package name",
        }),
    }
}

fn parse_port(args: &[OsString]) -> Result<Command, CliError> {
    let word = exactly_one("port", args, "a port number")?;
    // A port is a `u16`, so 70000 is refused here rather than becoming a
    // policy error later. `00` §3.3's rule applies: say what is wrong at the
    // point the user can still fix it cheaply.
    let number: u16 = word
        .parse()
        .map_err(|_| CliError::NotAPort { given: word })?;
    if number == 0 {
        return Err(CliError::NotAPort {
            given: "0".to_owned(),
        });
    }
    Ok(Command::Edit(Edit::Port { number }))
}

fn parse_set(args: &[OsString]) -> Result<Command, CliError> {
    let mut words = Vec::new();
    for arg in args {
        let word = arg.to_string_lossy();
        // Checked before collecting, because a value may legitimately look
        // like a flag (`set isolation.network.default --deny` is a user
        // meaning `deny`), and guessing which is which is worse than asking.
        if word.starts_with("--") {
            return Err(CliError::UnexpectedFlag {
                command: "set",
                flag: word.into_owned(),
            });
        }
        words.push(arg.to_str().ok_or(CliError::NotUtf8 { command: "set" })?);
    }
    match words.as_slice() {
        [path, value] => Ok(Command::Edit(Edit::Set {
            path: (*path).to_owned(),
            value: (*value).to_owned(),
        })),
        [] => Err(CliError::MissingArgument {
            command: "set",
            what: "an option path, as in `set resources.memory 8GB`",
        }),
        [_] => Err(CliError::MissingArgument {
            command: "set",
            what: "a value for that option",
        }),
        _ => Err(CliError::TooManyArguments {
            command: "set",
            expected: "one option path and one value",
        }),
    }
}

fn parse_secret(args: &[OsString]) -> Result<Command, CliError> {
    let name = exactly_one("secret", args, "the secret's name")?;
    Ok(Command::Edit(Edit::Secret { name }))
}

/// Exactly one non-flag argument, or a specific error about what was wrong.
///
/// Shared by the three verbs that take a single name, so "none given" and
/// "two given" are distinguished identically everywhere rather than
/// three times with slightly different wording.
fn exactly_one(
    command: &'static str,
    args: &[OsString],
    what: &'static str,
) -> Result<String, CliError> {
    let mut found = None;
    for arg in args {
        let word = arg.to_string_lossy();
        if word.starts_with("--") {
            return Err(CliError::UnexpectedFlag {
                command,
                flag: word.into_owned(),
            });
        }
        let value = arg.to_str().ok_or(CliError::NotUtf8 { command })?;
        if found.is_some() {
            return Err(CliError::TooManyArguments {
                command,
                expected: what,
            });
        }
        found = Some(value.to_owned());
    }
    found.ok_or(CliError::MissingArgument { command, what })
}

fn expect_no_args(
    command: &'static str,
    args: &[OsString],
    parsed: Command,
) -> Result<Command, CliError> {
    match args.first() {
        None => Ok(parsed),
        Some(extra) => Err(CliError::UnexpectedFlag {
            command,
            flag: extra.to_string_lossy().into_owned(),
        }),
    }
}

/// The nearest subcommand, if one is close enough to suggest.
///
/// Reuses the renderer's cutoff shape: at most 3 edits and at most a third of
/// the longer word, because a confident wrong suggestion sends the user to
/// run the wrong command.
fn nearest_command(given: &str) -> Option<&'static str> {
    COMMANDS
        .iter()
        .map(|known| (*known, crate::render::edit_distance(given, known)))
        .filter(|(known, distance)| *distance <= 3 && *distance * 3 <= given.len().max(known.len()))
        .min_by_key(|(_, distance)| *distance)
        .map(|(known, _)| known)
}

/// The hand-written help text.
///
/// `17` §1 accepted "no generated help" as the cost of `lexopt`, and `21`
/// §2.4 recorded the gap. The mitigation it named is a test asserting every
/// parsed verb appears here.
///
/// That mitigation did not exist. This function lived in `main.rs`, which no
/// test runs — so the claim "cheap to keep correct because a test asserts
/// every parsed verb appears here" described a test that had never been
/// written, and a verb could have been added to the parser and omitted from
/// help with nothing to catch it. Found while moving [`Command::verb`] for
/// the same reason (AGENTS.md, "Unfalsifiable code"): `main.rs` is untested
/// by design, so nothing with observable behaviour belongs in it.
#[must_use]
pub fn help() -> String {
    format!(
        "\
rachna {version} — a declarative, isolated development environment

USAGE
  rachna <command> [options]

ENVIRONMENT
  init [--template <url>]   write a starting rachna.nix
  start [--accept]          start or resume. Shows what rachna.nix permits
                            every time; asks for `a` when the grants are
                            new or wider. --accept is for CI only — at a
                            terminal it is ignored and you press `a`
  stop                      stop the environment
  status                    what is running, and what it is allowed
  doctor                    check this host, and verify enforcement

CONFIG
  config inspect            the effective config, with defaults visible
  config diff               live runtime versus the file
  config validate           check without applying

PERMISSIONS  (every one of these edits rachna.nix; there is no
              temporary grant, because rachna.nix is the only authority)
  allow <category> <target>...
                            add a grant. category is one of:
                            network, fs, port, secret, tool
                            fs takes --read-only or --read-write
  revoke <category> <target>...
                            remove a grant, named the same way
  expose <kind> <name>      declare a tool. kind is one of:
                            lsp, formatter, debugger, command
  unexpose <name>           stop declaring a tool
  add package <name>        add a package to the environment
  port <number>             forward a port
  set <path> <value>        set an option, e.g. set resources.memory 8GB
  secret <name>             declare a credential placeholder

AUDIT
  audit [--narrow] [--ci]   find unused and over-broad grants
  explain <run-id>          every decision in one run

  --version                 print the version
  --help                    this text

rachna.nix is the only authority. Every command above that changes
permissions edits that file; nothing grants anything that is not written
down.
",
        version = crate::version()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    fn parse(parts: &[&str]) -> Result<Invocation, CliError> {
        Invocation::from_argv(&argv(parts))
    }

    fn command(parts: &[&str]) -> Command {
        match parse(parts).expect("parses") {
            Invocation::Rachna(command) => command,
            Invocation::Shim { tool, .. } => panic!("dispatched to the {tool} shim"),
        }
    }

    // ---- multi-call dispatch: the property that chose lexopt ------------

    #[test]
    fn a_shim_receives_its_arguments_completely_untouched() {
        // THE reason `17` §1 chose lexopt over clap:
        // `.rachna/bin/rust-analyzer --help` must pass `--help` to the GUEST
        // tool, not have a parser answer for itself. Dispatch happens on
        // argv[0] before anything looks at a flag, so flag-eating is
        // structurally impossible rather than carefully avoided.
        let parsed = parse(&[
            "/proj/.rachna/bin/rust-analyzer",
            "--help",
            "--version",
            "--stdio",
        ])
        .expect("a shim never errors");
        match parsed {
            Invocation::Shim { tool, args } => {
                assert_eq!(tool, "rust-analyzer");
                assert_eq!(args, argv(&["--help", "--version", "--stdio"]));
            }
            Invocation::Rachna(command) => {
                panic!("a parser interpreted a shim's flags: {command:?}")
            }
        }
    }

    #[test]
    fn a_shim_never_errors_whatever_it_is_given() {
        // A shim's arguments are not ours to validate. Refusing one would
        // break a tool for reasons that have nothing to do with the tool.
        for hostile in [
            vec!["/p/.rachna/bin/gopls", "--not-a-real-flag"],
            vec!["/p/.rachna/bin/prettier", "-"],
            vec!["/p/.rachna/bin/x", "--read-only", "--read-write"],
            vec!["/p/.rachna/bin/y"],
        ] {
            assert!(
                matches!(parse(&hostile), Ok(Invocation::Shim { .. })),
                "{hostile:?} was not dispatched as a shim"
            );
        }
    }

    #[test]
    fn dispatch_is_on_the_file_name_not_the_whole_path() {
        // The shim lives at `.rachna/bin/<tool>`, so the path differs per
        // project while the name is what identifies the tool.
        for path in [
            "rachna",
            "/usr/local/bin/rachna",
            "./target/debug/rachna",
            "/nix/store/abc-rachna-0.1/bin/rachna",
        ] {
            assert!(
                matches!(parse(&[path, "status"]), Ok(Invocation::Rachna(_))),
                "{path} was not recognised as rachna"
            );
        }
    }

    #[test]
    fn a_tool_whose_name_merely_contains_rachna_is_still_a_shim() {
        // `rachna-analyzer` is a tool, not us. An `is_empty`-style prefix
        // check would have mis-dispatched it.
        match parse(&["/p/.rachna/bin/rachna-analyzer", "--stdio"]) {
            Ok(Invocation::Shim { tool, .. }) => assert_eq!(tool, "rachna-analyzer"),
            other => panic!("mis-dispatched: {other:?}"),
        }
    }

    #[test]
    fn an_empty_argv_is_help_rather_than_a_panic() {
        // Not reachable from a shell, but a caller with an empty argv must
        // not index out of bounds.
        assert_eq!(
            Invocation::from_argv(&[]).expect("no panic"),
            Invocation::Rachna(Command::Help)
        );
    }

    // ---- the verbs --------------------------------------------------------

    // ---- help: the mitigation 17 §1 promised -----------------------------

    #[test]
    fn every_verb_the_parser_accepts_appears_in_help() {
        // THE test `17` §1 named as the price of hand-written help, and which
        // did not exist until now — `help()` lived in `main.rs`, where no test
        // could call it, while its own doc comment claimed this test did.
        //
        // First: assert the thing under attack exists, per AGENTS.md. A
        // `help()` returning "" would make every `contains` below vacuous.
        let text = help();
        assert!(
            text.contains("USAGE"),
            "help does not look like help: {text}"
        );
        assert!(text.len() > 400, "help is suspiciously short");

        // Driven by `COMMANDS` — the parser's OWN list — rather than a list
        // written out here. The first version of this test enumerated
        // commands by hand and then failed to notice seven verbs being added,
        // which is the exact drift it exists to prevent: a test with its own
        // copy of the list only checks the copy.
        assert!(
            COMMANDS.len() >= 16,
            "COMMANDS has shrunk to {}; is dispatch still reading it?",
            COMMANDS.len()
        );
        for verb in COMMANDS {
            assert!(
                text.contains(verb),
                "`{verb}` parses but is undocumented in help"
            );
        }

        // And every verb is actually dispatched, not merely listed: a word in
        // COMMANDS that the parser rejects would make the loop above pass
        // while `rachna <verb>` says "unknown command".
        for verb in COMMANDS {
            let parsed = parse(&["rachna", verb]);
            assert!(
                !matches!(parsed, Err(CliError::UnknownCommand { .. })),
                "`{verb}` is listed and documented but not dispatched"
            );
        }

        // The flags and sub-actions, which are as easy to forget as a verb
        // and more confusing to omit.
        for action in ConfigAction::ALL {
            let phrase = format!("config {}", action.as_str());
            assert!(
                text.contains(&phrase),
                "`{phrase}` parses but is undocumented in help"
            );
        }
        for flag in ["--template", "--accept", "--narrow", "--ci", "--read-only"] {
            assert!(
                text.contains(flag),
                "`{flag}` is accepted but undocumented in help"
            );
        }
        // Both long-form switches, which have no verb to carry them.
        for switch in ["--version", "--help"] {
            assert!(text.contains(switch), "`{switch}` is undocumented");
        }
    }

    // ---- the rachna.nix-editing verbs (00 §5.3, found missing by 21 §2.5)

    #[test]
    fn every_edit_verb_parses_the_spec_example_verbatim() {
        // `00` §5.3 gives six concrete examples. They are typed here exactly
        // as written, because a surface that does not accept its own
        // documentation is a surface that was never run.
        assert_eq!(
            command(&["rachna", "allow", "network", "registry.npmjs.org"]),
            Command::Edit(Edit::Allow {
                category: Category::Network,
                targets: vec!["registry.npmjs.org".to_owned()],
                access: None,
            })
        );
        assert_eq!(
            command(&["rachna", "allow", "fs", "~/.npmrc", "--read-only"]),
            Command::Edit(Edit::Allow {
                category: Category::Filesystem,
                targets: vec!["~/.npmrc".to_owned()],
                access: Some(Access::ReadOnly),
            })
        );
        assert_eq!(
            command(&["rachna", "expose", "formatter", "prettier"]),
            Command::Edit(Edit::Expose {
                kind: ToolKind::Formatter,
                name: "prettier".to_owned(),
            })
        );
        assert_eq!(
            command(&["rachna", "add", "package", "postgresql_16"]),
            Command::Edit(Edit::AddPackage {
                name: "postgresql_16".to_owned(),
            })
        );
        assert_eq!(
            command(&["rachna", "port", "3000"]),
            Command::Edit(Edit::Port { number: 3000 })
        );
        assert_eq!(
            command(&["rachna", "set", "resources.memory", "8GB"]),
            Command::Edit(Edit::Set {
                path: "resources.memory".to_owned(),
                value: "8GB".to_owned(),
            })
        );
    }

    #[test]
    fn a_misspelled_category_is_refused_at_parse_time() {
        // The reason `Category` replaced a `String`. Previously
        // `allow nework github.com` parsed fine and failed somewhere later —
        // the same "declared and silently means nothing" shape `00` §5.3
        // rule 4 rejects for config keys.
        //
        // First assert the attack target exists: the correct spelling works.
        assert!(matches!(
            command(&["rachna", "allow", "network", "x"]),
            Command::Edit(Edit::Allow { .. })
        ));

        let error = parse(&["rachna", "allow", "nework", "github.com"])
            .expect_err("a misspelled category must not parse");
        assert!(matches!(error, CliError::UnknownCategory { .. }), "{error}");
        // The message lists the valid set, so the user does not go looking.
        let text = error.to_string();
        for category in Category::ALL {
            assert!(
                text.contains(category.as_str()),
                "the error omits `{category}`: {text}"
            );
        }
    }

    #[test]
    fn a_misspelled_tool_kind_is_refused_and_lists_the_kinds() {
        assert!(matches!(
            command(&["rachna", "expose", "lsp", "rust-analyzer"]),
            Command::Edit(Edit::Expose { .. })
        ));
        let error = parse(&["rachna", "expose", "linter", "eslint"])
            .expect_err("`linter` is not one of 00 §6.4's kinds");
        assert!(matches!(error, CliError::UnknownToolKind { .. }), "{error}");
        let text = error.to_string();
        for kind in ToolKind::ALL {
            assert!(
                text.contains(kind.as_str()),
                "the error omits `{}`",
                kind.as_str()
            );
        }
    }

    #[test]
    fn every_tool_kind_round_trips() {
        for kind in ToolKind::ALL {
            assert_eq!(ToolKind::parse(kind.as_str()), Some(kind));
            assert_eq!(
                command(&["rachna", "expose", kind.as_str(), "t"]),
                Command::Edit(Edit::Expose {
                    kind,
                    name: "t".to_owned(),
                })
            );
        }
        for rejected in ["", "LSP", "lint", "formatters"] {
            assert_eq!(ToolKind::parse(rejected), None, "`{rejected}` accepted");
        }
    }

    #[test]
    fn a_port_outside_the_range_is_a_usage_error_not_a_policy_error() {
        // Caught where the user can still fix it cheaply, rather than
        // becoming a confusing failure after the config is written.
        assert_eq!(
            command(&["rachna", "port", "65535"]),
            Command::Edit(Edit::Port { number: 65535 })
        );
        for rejected in ["70000", "-1", "0", "3000.5", "http", ""] {
            let error =
                parse(&["rachna", "port", rejected]).expect_err("`{rejected}` is not a port");
            assert!(
                matches!(error, CliError::NotAPort { .. }),
                "`{rejected}` gave {error:?}"
            );
            assert!(
                error.to_string().contains("1 to 65535"),
                "the error must say the range"
            );
        }
    }

    #[test]
    fn a_verb_taking_one_name_refuses_none_and_refuses_two() {
        // Both directions, because "too few" and "too many" have different
        // fixes and a single `Missing` for both would mislead.
        for verb in ["unexpose", "secret"] {
            let missing = parse(&["rachna", verb]).expect_err("needs a name");
            assert!(
                matches!(missing, CliError::MissingArgument { .. }),
                "{verb}: {missing:?}"
            );
            let extra = parse(&["rachna", verb, "one", "two"]).expect_err("takes one name");
            assert!(
                matches!(extra, CliError::TooManyArguments { .. }),
                "{verb}: {extra:?}"
            );
        }
        // And one name works, so the above is not rejecting everything.
        assert_eq!(
            command(&["rachna", "unexpose", "lldb-dap"]),
            Command::Edit(Edit::Unexpose {
                name: "lldb-dap".to_owned(),
            })
        );
        assert_eq!(
            command(&["rachna", "secret", "AWS_ACCESS_KEY_ID"]),
            Command::Edit(Edit::Secret {
                name: "AWS_ACCESS_KEY_ID".to_owned(),
            })
        );
    }

    #[test]
    fn add_requires_its_noun_and_names_the_one_it_knows() {
        let unknown = parse(&["rachna", "add", "service", "redis"])
            .expect_err("`service` is not a thing to add");
        assert!(
            matches!(unknown, CliError::UnknownNoun { .. }),
            "{unknown:?}"
        );
        assert!(unknown.to_string().contains("package"), "{unknown}");
        // A bare `add` says what shape it wants rather than only refusing.
        let bare = parse(&["rachna", "add"]).expect_err("needs a noun");
        assert!(bare.to_string().contains("add package"), "{bare}");
    }

    #[test]
    fn set_needs_both_halves_and_distinguishes_which_is_missing() {
        let no_path = parse(&["rachna", "set"]).expect_err("needs a path");
        assert!(no_path.to_string().contains("option path"), "{no_path}");
        let no_value = parse(&["rachna", "set", "resources.memory"]).expect_err("needs a value");
        assert!(no_value.to_string().contains("a value"), "{no_value}");
        // An option path is NOT validated here: `00` §5.3 rule 4 makes an
        // unknown key an error, and the thing that can tell is
        // `lib.evalModules`. Refusing on a guess would reject valid options,
        // so a plausible-but-unknown path must parse.
        assert_eq!(
            command(&["rachna", "set", "some.future.option", "v"]),
            Command::Edit(Edit::Set {
                path: "some.future.option".to_owned(),
                value: "v".to_owned(),
            })
        );
    }

    #[test]
    fn revoke_takes_exactly_what_allow_takes() {
        // The property that matters: a user must be able to remove a grant by
        // retyping the line that created it with a different verb. If the two
        // parsers ever diverge, a grant becomes unremovable by the obvious
        // means.
        for args in [
            vec!["network", "github.com"],
            vec!["fs", "~/.npmrc", "--read-only"],
            vec!["secret", "AWS_SECRET"],
            vec!["network", "a.com", "b.com", "c.com"],
        ] {
            let mut allow_parts = vec!["rachna", "allow"];
            allow_parts.extend(args.iter().copied());
            let mut revoke_parts = vec!["rachna", "revoke"];
            revoke_parts.extend(args.iter().copied());

            let Command::Edit(Edit::Allow {
                category: ac,
                targets: at,
                ..
            }) = command(&allow_parts)
            else {
                panic!("allow {args:?} did not parse as an allow")
            };
            let Command::Edit(Edit::Revoke {
                category: rc,
                targets: rt,
            }) = command(&revoke_parts)
            else {
                panic!("revoke {args:?} did not parse as a revoke")
            };
            assert_eq!(ac, rc, "{args:?} disagreed on category");
            assert_eq!(at, rt, "{args:?} disagreed on targets");
        }
    }

    #[test]
    fn an_edit_knows_whether_it_widens_access() {
        // The distinction a reviewer needs: `rachna.nix` in a diff is the
        // whole review mechanism, so "does this grant more" must be a
        // question the type answers rather than a judgement at a call site.
        let widening = [
            Edit::Allow {
                category: Category::Network,
                targets: vec!["x".to_owned()],
                access: None,
            },
            Edit::Expose {
                kind: ToolKind::Lsp,
                name: "t".to_owned(),
            },
            Edit::AddPackage {
                name: "p".to_owned(),
            },
            Edit::Port { number: 1 },
            Edit::Secret {
                name: "s".to_owned(),
            },
            // `set` counts as widening because a parser cannot tell
            // `resources.memory` from `isolation.network.default` without the
            // module schema, and unknown must mean "look at it".
            Edit::Set {
                path: "p".to_owned(),
                value: "v".to_owned(),
            },
        ];
        for edit in widening {
            assert!(edit.widens_access(), "{edit:?} should widen");
        }
        let narrowing = [
            Edit::Revoke {
                category: Category::Network,
                targets: vec!["x".to_owned()],
            },
            Edit::Unexpose {
                name: "t".to_owned(),
            },
        ];
        for edit in narrowing {
            assert!(!edit.widens_access(), "{edit:?} should not widen");
        }
    }

    #[test]
    fn no_edit_verb_silently_accepts_an_unknown_flag() {
        // `00` §5.3 rule 1: there is no `--persist`, because there is no
        // non-persistent alternative. A user who types one must be told,
        // not quietly ignored — an ignored flag means the user believes
        // something happened that did not.
        for parts in [
            vec!["rachna", "allow", "network", "x", "--persist"],
            vec!["rachna", "revoke", "network", "x", "--once"],
            vec!["rachna", "expose", "lsp", "t", "--global"],
            vec!["rachna", "unexpose", "t", "--force"],
            vec!["rachna", "add", "package", "p", "--dev"],
            vec!["rachna", "port", "3000", "--host"],
            vec!["rachna", "set", "a.b", "--deny"],
            vec!["rachna", "secret", "S", "--env"],
        ] {
            let error = parse(&parts).expect_err("an unknown flag must be refused");
            assert!(
                matches!(error, CliError::UnexpectedFlag { .. }),
                "{parts:?} gave {error:?}"
            );
        }
    }

    #[test]
    fn help_states_where_authority_lives() {
        // `00` §3.1: rachna.nix is the only authority. The help text is where
        // most users meet that claim, so it is pinned rather than left to
        // drift — this is a product promise, not prose.
        let text = help();
        assert!(text.contains("rachna.nix is the only authority"), "{text}");
        assert!(text.contains("nothing grants anything"), "{text}");
    }

    #[test]
    fn a_verb_name_round_trips_through_the_parser() {
        // First: assert the thing under attack EXISTS, per AGENTS.md — a
        // `verb()` that returned nothing useful would make the rest vacuous.
        assert_eq!(Command::Stop.verb(), "stop");

        // Every command's `verb()`, typed back in, must parse to a command
        // reporting that same verb. This is the property `main.rs` could not
        // test: `verb()` lived there with one caller inside an untested
        // `main`, so nothing observed its result and every mutant replacing
        // it with a constant survived. A constant cannot satisfy TWELVE
        // distinct round-trips.
        let commands = [
            Command::Init { template: None },
            Command::Start { accept: false },
            Command::Stop,
            Command::Status,
            Command::Doctor,
            Command::Config {
                action: ConfigAction::Inspect,
            },
            Command::Config {
                action: ConfigAction::Diff,
            },
            Command::Config {
                action: ConfigAction::Validate,
            },
            Command::Version,
            Command::Help,
        ];
        for original in commands {
            let verb = original.verb();
            // `config inspect` is two words, and a verb has to be typeable.
            let typed: Vec<&str> = core::iter::once("rachna").chain(verb.split(' ')).collect();
            let reparsed = command(&typed);
            assert_eq!(
                reparsed.verb(),
                verb,
                "`{verb}` did not round-trip: parsed back as {reparsed:?}"
            );
        }

        // The two verbs that need an argument, checked separately because
        // they cannot round-trip from the verb alone.
        assert_eq!(command(&["rachna", "explain", "run/x"]).verb(), "explain");
        assert_eq!(
            command(&["rachna", "allow", "network", "crates.io"]).verb(),
            "allow"
        );

        // And no two commands share a name, which is what makes the verb
        // usable in a message at all.
        let mut names: Vec<&str> = [
            Command::Init { template: None },
            Command::Start { accept: false },
            Command::Stop,
            Command::Status,
            Command::Doctor,
            Command::Config {
                action: ConfigAction::Inspect,
            },
            Command::Config {
                action: ConfigAction::Diff,
            },
            Command::Config {
                action: ConfigAction::Validate,
            },
            Command::Audit {
                narrow: false,
                ci: false,
            },
            Command::Explain {
                run_id: "r".to_owned(),
            },
            Command::Edit(Edit::Allow {
                category: Category::Network,
                targets: vec![],
                access: None,
            }),
            Command::Version,
            Command::Help,
        ]
        .iter()
        .map(Command::verb)
        .collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "two commands report the same verb");
    }

    #[test]
    fn every_verb_parses() {
        assert_eq!(
            command(&["rachna", "init"]),
            Command::Init { template: None }
        );
        assert_eq!(
            command(&["rachna", "init", "--template", "https://x/t.nix"]),
            Command::Init {
                template: Some("https://x/t.nix".to_owned())
            }
        );
        assert_eq!(
            command(&["rachna", "start"]),
            Command::Start { accept: false }
        );
        assert_eq!(
            command(&["rachna", "start", "--accept"]),
            Command::Start { accept: true }
        );
        assert_eq!(command(&["rachna", "stop"]), Command::Stop);
        assert_eq!(command(&["rachna", "status"]), Command::Status);
        assert_eq!(command(&["rachna", "doctor"]), Command::Doctor);
        assert_eq!(
            command(&["rachna", "audit", "--narrow", "--ci"]),
            Command::Audit {
                narrow: true,
                ci: true
            }
        );
        assert_eq!(
            command(&["rachna", "explain", "run/a3f2"]),
            Command::Explain {
                run_id: "run/a3f2".to_owned()
            }
        );
    }

    #[test]
    fn a_flag_takes_its_value_in_either_form() {
        // Users type both. `--template=url` was REJECTED before `split_equals`
        // existed — found by running the binary, not by reading the parser.
        let expected = Command::Init {
            template: Some("https://x/t.nix".to_owned()),
        };
        assert_eq!(
            command(&["rachna", "init", "--template", "https://x/t.nix"]),
            expected
        );
        assert_eq!(
            command(&["rachna", "init", "--template=https://x/t.nix"]),
            expected
        );
    }

    #[test]
    fn a_value_containing_an_equals_survives() {
        // Split on the FIRST `=` only, so a query string is not truncated.
        assert_eq!(
            command(&["rachna", "init", "--template=https://x/t.nix?a=b&c=d"]),
            Command::Init {
                template: Some("https://x/t.nix?a=b&c=d".to_owned())
            }
        );
    }

    #[test]
    fn a_shims_arguments_are_never_normalised() {
        // `17` §1 requires them handed to the guest tool untouched, and
        // splitting a tool's own `--flag=value` would corrupt it. A tool that
        // wants `--log-file=/tmp/x` must receive exactly that.
        match parse(&["/p/.rachna/bin/gopls", "--log-file=/tmp/x", "--rpc.trace"]) {
            Ok(Invocation::Shim { args, .. }) => {
                assert_eq!(args, argv(&["--log-file=/tmp/x", "--rpc.trace"]));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_empty_flag_name_is_not_split() {
        // `--=value` has no flag name. Without the `!flag.is_empty()` guard
        // it becomes `--` plus `value`, so `rachna init --=x` would be read
        // as `rachna init -- x` — two arguments the user never typed, and a
        // confusing refusal about the wrong one. Mutation testing found this;
        // the bare-`--` test below does not reach it, since `--` has no `=`.
        assert!(parse(&["rachna", "init", "--=x"]).is_err());
        match parse(&["rachna", "init", "--=x"]) {
            Err(CliError::UnexpectedFlag { flag, .. }) => {
                assert_eq!(flag, "--=x", "the argument was split");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_bare_double_dash_is_not_split() {
        // `--` has no flag name, so it must not become an empty flag plus an
        // empty value. It reaches the command to be refused there.
        assert!(parse(&["rachna", "--"]).is_err());
    }

    #[test]
    fn a_target_containing_an_equals_is_not_split() {
        // Only `--flag=value` splits. A target like `KEY=value` is a value.
        assert_eq!(
            command(&["rachna", "allow", "secret", "KEY=value"]),
            Command::Edit(Edit::Allow {
                category: Category::Secret,
                targets: vec!["KEY=value".to_owned()],
                access: None,
            })
        );
    }

    #[test]
    fn every_config_action_parses_and_round_trips() {
        for action in ConfigAction::ALL {
            assert_eq!(
                command(&["rachna", "config", action.as_str()]),
                Command::Config { action }
            );
            assert_eq!(ConfigAction::parse(action.as_str()), Some(action));
        }
        assert_eq!(ConfigAction::parse("nonsense"), None);
    }

    #[test]
    fn version_and_help_are_recognised_in_every_spelling() {
        for spelling in [vec!["--version"], vec!["-V"]] {
            let mut parts = vec!["rachna"];
            parts.extend(spelling);
            assert_eq!(command(&parts), Command::Version);
        }
        for spelling in [vec!["--help"], vec!["-h"], vec!["help"], vec![]] {
            let mut parts = vec!["rachna"];
            parts.extend(spelling);
            assert_eq!(command(&parts), Command::Help);
        }
    }

    // ---- allow, the one with real arguments ------------------------------

    #[test]
    fn allow_takes_a_category_and_several_targets() {
        // The denial report suggests `rachna allow network a b c` for several
        // hosts at once (`00` §3.3), so one invocation must take them all —
        // otherwise the suggested command would not work as printed.
        assert_eq!(
            command(&[
                "rachna",
                "allow",
                "network",
                "registry.npmjs.org:443",
                "github.com:443"
            ]),
            Command::Edit(Edit::Allow {
                category: Category::Network,
                targets: vec![
                    "registry.npmjs.org:443".to_owned(),
                    "github.com:443".to_owned()
                ],
                access: None,
            })
        );
    }

    #[test]
    fn allow_accepts_an_access_flag_in_any_position() {
        // The report prints `rachna allow fs ~/.npmrc --read-only`, so a
        // trailing flag must work; a user typing it first must work too.
        for parts in [
            vec!["rachna", "allow", "fs", "/w", "--read-only"],
            vec!["rachna", "allow", "--read-only", "fs", "/w"],
        ] {
            assert_eq!(
                command(&parts),
                Command::Edit(Edit::Allow {
                    category: Category::Filesystem,
                    targets: vec!["/w".to_owned()],
                    access: Some(Access::ReadOnly),
                }),
                "{parts:?}"
            );
        }
    }

    #[test]
    fn allow_refuses_both_access_flags() {
        // A contradiction, not a widening: picking read-write would grant
        // more than one of the two things asked for, and read-only less.
        // Refusing makes the user say which.
        assert_eq!(
            parse(&["rachna", "allow", "fs", "/w", "--read-only", "--read-write"]),
            Err(CliError::ConflictingFlags {
                first: "--read-only",
                second: "--read-write",
            })
        );
    }

    #[test]
    fn allow_needs_a_category_and_a_target() {
        assert!(matches!(
            parse(&["rachna", "allow"]),
            Err(CliError::MissingArgument {
                command: "allow",
                ..
            })
        ));
        assert!(matches!(
            parse(&["rachna", "allow", "network"]),
            Err(CliError::MissingArgument {
                command: "allow",
                ..
            })
        ));
    }

    // ---- refusals ---------------------------------------------------------

    #[test]
    fn an_unknown_command_suggests_the_nearest() {
        for (typo, expected) in [
            ("statu", "status"),
            ("strt", "start"),
            ("audi", "audit"),
            ("explian", "explain"),
        ] {
            match parse(&["rachna", typo]) {
                Err(CliError::UnknownCommand {
                    suggestion: Some(suggestion),
                    ..
                }) => assert_eq!(suggestion, expected, "{typo}"),
                other => panic!("{typo} -> {other:?}"),
            }
        }
    }

    #[test]
    fn an_unknown_flag_to_allow_is_refused_not_taken_as_a_target() {
        // Mutation testing found the `starts_with("--")` guard untested:
        // without it an unknown flag falls through to the target list, so
        // `rachna allow network --recursive host` would GRANT a host named
        // `--recursive` and silently ignore what the user meant.
        assert!(matches!(
            parse(&["rachna", "allow", "network", "--recursive", "a.test:443"]),
            Err(CliError::UnexpectedFlag {
                command: "allow",
                ..
            })
        ));
        // And a target that merely looks unusual is still a target.
        assert_eq!(
            command(&["rachna", "allow", "fs", "-weird-name"]),
            Command::Edit(Edit::Allow {
                category: Category::Filesystem,
                targets: vec!["-weird-name".to_owned()],
                access: None,
            })
        );
    }

    #[test]
    fn a_short_abbreviation_is_not_treated_as_a_command_typo() {
        // The same cutoff gap as render.rs: both bounds are needed, and
        // every earlier input agreed under either alone. `ini` is 1 edit
        // from `init` but 3*1 > 3, so only the ratio rejects it — and
        // suggesting `init` for someone who typed `ini` deliberately would
        // be wrong, while suggesting a command for `st` would be a guess.
        // `st` USED to be here as "2 edits on a 2-letter word". Adding the
        // `00` §5.3 verbs made it 1 edit from `set`, which passes both bounds
        // — and suggesting `set` to someone who typed `st` is a reasonable
        // correction rather than a guess, so the right answer changed with
        // the vocabulary. Recorded rather than quietly deleted: the rule is
        // about distance and length, not about a fixed list of words, so a
        // new verb legitimately changes which fragments are near-misses.
        assert_eq!(nearest_command("st"), Some("set"));
        assert_eq!(nearest_command("au"), None, "2 edits on a 2-letter word");
        // Three-letter fragments: 3 edits against a 5-7 letter command. These
        // are what distinguish `d * 3 <= max_len` from `d + 3 <= max_len` —
        // found by enumerating the two formulations rather than guessing,
        // after a mutant on that operator survived everything above.
        // Suggesting `audit` for someone who typed `aut` is a guess, not a
        // correction.
        assert_eq!(nearest_command("aut"), None);
        assert_eq!(nearest_command("ats"), None);
        // Real typos still land.
        assert_eq!(nearest_command("statu"), Some("status"));
        assert_eq!(nearest_command("initt"), Some("init"));
    }

    #[test]
    fn a_long_word_sharing_a_prefix_is_still_a_near_miss() {
        // Corrected: I assumed `statusxyz` would be rejected. It is not, and
        // should not be — 3 edits against a 9-letter word passes BOTH bounds
        // (3 <= 3, and 3*3 <= 9), so `status` really is the nearest command.
        // Computed rather than guessed, after the first version of this test
        // asserted the opposite and failed.
        assert_eq!(nearest_command("statusxyz"), Some("status"));
    }

    #[test]
    fn an_unrelated_word_gets_no_suggestion() {
        // A confident wrong suggestion sends the user to run the wrong
        // command — the same cutoff reasoning as the config renderer, whose
        // edit_distance this reuses rather than re-implements.
        match parse(&["rachna", "xyzzy"]) {
            Err(CliError::UnknownCommand { suggestion, .. }) => assert_eq!(suggestion, None),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_verb_that_takes_nothing_refuses_extra_arguments() {
        // Silently ignoring them would mean `rachna stop --force` appears to
        // do something it does not.
        for parts in [
            vec!["rachna", "stop", "--force"],
            vec!["rachna", "status", "extra"],
            vec!["rachna", "doctor", "--ide"],
            vec!["rachna", "explain", "run/1", "extra"],
        ] {
            assert!(
                matches!(parse(&parts), Err(CliError::UnexpectedFlag { .. })),
                "{parts:?} was accepted"
            );
        }
    }

    #[test]
    fn a_flag_a_verb_does_not_take_is_refused() {
        assert!(matches!(
            parse(&["rachna", "start", "--narrow"]),
            Err(CliError::UnexpectedFlag {
                command: "start",
                ..
            })
        ));
        assert!(matches!(
            parse(&["rachna", "audit", "--accept"]),
            Err(CliError::UnexpectedFlag {
                command: "audit",
                ..
            })
        ));
    }

    #[test]
    fn template_needs_a_value() {
        assert!(matches!(
            parse(&["rachna", "init", "--template"]),
            Err(CliError::MissingArgument {
                command: "init",
                ..
            })
        ));
    }

    #[test]
    fn config_needs_an_action() {
        assert!(matches!(
            parse(&["rachna", "config"]),
            Err(CliError::MissingArgument {
                command: "config",
                ..
            })
        ));
    }

    #[test]
    fn explain_needs_a_run_id() {
        assert!(matches!(
            parse(&["rachna", "explain"]),
            Err(CliError::MissingArgument {
                command: "explain",
                ..
            })
        ));
    }

    #[test]
    fn every_error_explains_itself_actionably() {
        let every = [
            CliError::UnknownCommand {
                given: "statu".to_owned(),
                suggestion: Some("status"),
            },
            CliError::MissingArgument {
                command: "allow",
                what: "a category",
            },
            CliError::UnexpectedFlag {
                command: "stop",
                flag: "--force".to_owned(),
            },
            CliError::ConflictingFlags {
                first: "--read-only",
                second: "--read-write",
            },
            CliError::NotUtf8 { command: "explain" },
        ];
        for error in every {
            let message = error.to_string();
            assert!(
                message.len() > 15,
                "{error:?} renders too briefly: {message}"
            );
        }
    }

    // ---- non-UTF-8, which the path rule cares about ---------------------

    #[test]
    fn a_non_utf8_value_is_refused_rather_than_silently_altered() {
        // `17` §1: a lossy conversion does not round-trip, so a run-id or
        // host that cannot be represented must be refused. Silently altering
        // it would mean looking up a run that does not exist, or granting a
        // host the user did not type.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let invalid = OsString::from_vec(vec![0x66, 0x80, 0x6f]);
            let mut parts = argv(&["rachna", "explain"]);
            parts.push(invalid);
            assert_eq!(
                Invocation::from_argv(&parts),
                Err(CliError::NotUtf8 { command: "explain" })
            );
        }
    }
}
