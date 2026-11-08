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
    /// `--accept` acknowledges the first-run access summary (`00` §3.10c).
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
    /// `rachna allow <category> <target>...`
    Allow {
        category: String,
        targets: Vec<String>,
        read_only: bool,
        read_write: bool,
    },
    /// `rachna --version`
    Version,
    /// `rachna --help` or no arguments.
    Help,
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
const COMMANDS: &[&str] = &[
    "init", "start", "stop", "status", "doctor", "config", "audit", "explain", "allow",
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

fn parse_allow(args: &[OsString]) -> Result<Command, CliError> {
    let mut category = None;
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
                    command: "allow",
                    flag: flag.to_owned(),
                })
            }
            value if category.is_none() => {
                category = Some(
                    arg.to_str()
                        .ok_or(CliError::NotUtf8 { command: "allow" })?
                        .to_owned(),
                );
                let _ = value;
            }
            _ => targets.push(
                arg.to_str()
                    .ok_or(CliError::NotUtf8 { command: "allow" })?
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

    let category = category.ok_or(CliError::MissingArgument {
        command: "allow",
        what: "a category: network, fs, port, secret or tool",
    })?;
    if targets.is_empty() {
        return Err(CliError::MissingArgument {
            command: "allow",
            what: "at least one target",
        });
    }
    Ok(Command::Allow {
        category,
        targets,
        read_only,
        read_write,
    })
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
            Command::Allow {
                category: "secret".to_owned(),
                targets: vec!["KEY=value".to_owned()],
                read_only: false,
                read_write: false,
            }
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
            Command::Allow {
                category: "network".to_owned(),
                targets: vec![
                    "registry.npmjs.org:443".to_owned(),
                    "github.com:443".to_owned()
                ],
                read_only: false,
                read_write: false,
            }
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
                Command::Allow {
                    category: "fs".to_owned(),
                    targets: vec!["/w".to_owned()],
                    read_only: true,
                    read_write: false,
                },
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
            Command::Allow {
                category: "fs".to_owned(),
                targets: vec!["-weird-name".to_owned()],
                read_only: false,
                read_write: false,
            }
        );
    }

    #[test]
    fn a_short_abbreviation_is_not_treated_as_a_command_typo() {
        // The same cutoff gap as render.rs: both bounds are needed, and
        // every earlier input agreed under either alone. `ini` is 1 edit
        // from `init` but 3*1 > 3, so only the ratio rejects it — and
        // suggesting `init` for someone who typed `ini` deliberately would
        // be wrong, while suggesting a command for `st` would be a guess.
        assert_eq!(nearest_command("st"), None, "2 edits on a 2-letter word");
        assert_eq!(nearest_command("au"), None);
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
