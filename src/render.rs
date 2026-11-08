//! Rendering a config error against the user's file.
//!
//! `22-ERROR-MESSAGES.md` §4.2 specifies the output and four rules. The
//! motivation is not polish: `rachna.nix` is the only interface, so a bad
//! error message is the product's single surface failing.
//!
//! ```text
//! error: unknown option `netwrk`
//!   ┌─ rachna.nix:3:3
//!   │
//! 3 │   netwrk.allow = [ "registry.npmjs.org" ];
//!   │   ^^^^^^ no such option
//!   │
//!   = did you mean `network`?
//!   = fix it with:  rachna allow network registry.npmjs.org
//! ```
//!
//! # The four rules, and where each is enforced
//!
//! 1. **Never show a `/nix/store` path.** Enforced by construction: this
//!    module renders against the user's file and has no way to name another.
//! 2. **Always point at the user's file**, with a snippet and a caret. The
//!    span comes from [`locate`], because Nix reports `null` positions for
//!    option errors and its `--show-trace` frames all point inside nixpkgs
//!    (`22` §4.2 rule 2, measured).
//! 3. **Translate the option path into English** — `network.allow."[definition
//!    1-entry 1]"` is accurate and unreadable.
//! 4. **End with the command that fixes it.** Rachna's CLI edits the same
//!    file (`00` §5), so nearly every config error has a one-liner.

use crate::config::ConfigError;
use codespan_reporting::diagnostic::{Diagnostic, Label};
use codespan_reporting::files::SimpleFiles;
use codespan_reporting::term;
use core::ops::Range;

/// Where a config error should point in the source.
///
/// Byte offsets, because that is what the renderer wants and what a parser
/// produces. A `None` span still renders — the message and notes are more
/// useful than nothing, and silently dropping the error would be worse.
pub type Span = Option<Range<usize>>;

/// Finds where `path` is written in `source`, for the caret.
///
/// # Why a text search rather than a parse
///
/// `rnix` is the right tool and is already chosen (`17`) — this is the
/// deliberate stand-in until the editing module that needs a full CST lands.
/// The weakness is explicit: this finds the first *textual* occurrence, so a
/// key that also appears in a comment or a string will point at the wrong
/// one. That is a wrong caret on an error whose message is still correct,
/// which is an acceptable interim cost; a wrong *verdict* would not be.
///
/// Only the last segment is searched: `network.allow` is written as
/// `network.allow` in some configs and as a nested `network = { allow = … }`
/// in others, and the leaf is what both have in common.
#[must_use]
pub fn locate(source: &str, path: &str) -> Span {
    let leaf = path.rsplit('.').next().unwrap_or(path);
    // Strip a trailing list index: `network.allow[0]` is written as
    // `network.allow`, and the index is explained in the message instead.
    let leaf = leaf.split('[').next().unwrap_or(leaf);
    if leaf.is_empty() {
        return None;
    }
    let at = source.find(leaf)?;
    Some(at..at + leaf.len())
}

/// Renders one error against `source`, as `22` §4.2 specifies.
///
/// `filename` is what appears in the gutter — the user's own path, never a
/// store path (rule 1).
#[must_use]
pub fn render(filename: &str, source: &str, error: &ConfigError) -> String {
    let mut files = SimpleFiles::new();
    let id = files.add(filename, source);

    let (message, label, notes) = describe(error);
    let mut diagnostic = Diagnostic::error().with_message(message);

    if let Some(span) = locate(source, at_of(error)) {
        diagnostic = diagnostic.with_labels(vec![Label::primary(id, span).with_message(label)]);
    }
    if !notes.is_empty() {
        diagnostic = diagnostic.with_notes(notes);
    }

    let mut buffer = Vec::new();
    let config = term::Config::default();
    // Writing to a Vec cannot fail, and a rendering failure must never hide
    // the error — so the raw message is the fallback rather than a panic.
    if term::emit_to_io_write(&mut buffer, &config, &files, &diagnostic).is_err() {
        return format!("error: {error}\n");
    }
    String::from_utf8(buffer).unwrap_or_else(|_| format!("error: {error}\n"))
}

/// Renders every error, one report each.
///
/// Batched for the same reason the parser collects them (`00` §3.3): three
/// typos should produce three reports, not three runs.
#[must_use]
pub fn render_all(filename: &str, source: &str, errors: &[ConfigError]) -> String {
    errors
        .iter()
        .map(|error| render(filename, source, error))
        .collect()
}

/// The config path an error concerns.
fn at_of(error: &ConfigError) -> &str {
    match error {
        ConfigError::NotAnObject => "",
        ConfigError::WrongType { at, .. }
        | ConfigError::NotOneOf { at, .. }
        | ConfigError::UnknownKey { at }
        | ConfigError::Missing { at }
        | ConfigError::MalformedEndpoint { at, .. } => at,
    }
}

/// The headline, the caret label, and the note lines for one error.
///
/// Rules 3 and 4 live here: the option path is turned into English, and every
/// error that *has* a fixing command carries it.
fn describe(error: &ConfigError) -> (String, String, Vec<String>) {
    match error {
        ConfigError::NotAnObject => (
            "rachna.nix must evaluate to an attribute set".to_owned(),
            String::new(),
            vec!["a config is `{ tier = \"…\"; profile = \"…\"; }`".to_owned()],
        ),

        ConfigError::UnknownKey { at } => (
            format!("unknown option `{at}`"),
            "no such option".to_owned(),
            // The module system already computes suggestions (`22` finding
            // 7), so this does not reimplement them — it carries ours for the
            // top-level keys the parser knows.
            suggestion_notes(at),
        ),

        ConfigError::Missing { at } => (
            format!("{} is required", quoted(at)),
            "missing here".to_owned(),
            required_notes(at),
        ),

        ConfigError::WrongType {
            at,
            expected,
            found,
        } => (
            format!("{} must be {expected}", quoted(at)),
            format!("found {found}"),
            Vec::new(),
        ),

        ConfigError::NotOneOf { at, found, allowed } => (
            format!("`{found}` is not a valid {}", quoted(at)),
            "not one of the accepted values".to_owned(),
            vec![format!("accepted: {}", allowed.join(", "))],
        ),

        ConfigError::MalformedEndpoint { at, found } => (
            format!("`{found}` is not a host and port"),
            "expected host:port".to_owned(),
            vec![
                format!("{} entries look like \"example.com:443\"", quoted(at)),
                "a port is required: a grant without one would be a grant you \
                 did not write"
                    .to_owned(),
            ],
        ),
    }
}

/// [`english`], with a plain key backticked and a phrase left bare.
///
/// `` `tier` `` is a key the user can search for; *guest of the 1st entry of
/// ports* is a description, and backticking it makes it read as a literal
/// attribute name that does not exist in the file.
fn quoted(path: &str) -> String {
    let rendered = english(path);
    if rendered == path {
        format!("`{rendered}`")
    } else {
        rendered
    }
}

/// Turns a config path into something readable (rule 3).
///
/// `network.allow[0]` becomes `the 1st entry of network.allow`. Nix's own
/// rendering of the same thing is `network.allow."[definition 1-entry 1]"`,
/// which is accurate and unreadable.
#[must_use]
pub fn english(path: &str) -> String {
    let Some((head, rest)) = path.split_once('[') else {
        return path.to_owned();
    };
    let Some((index, tail)) = rest.split_once(']') else {
        return path.to_owned();
    };
    let Ok(index) = index.parse::<usize>() else {
        return path.to_owned();
    };
    let ordinal = ordinal(index + 1);
    // `ports[0].guest` -> "guest of the 1st entry of ports"
    let field = tail.strip_prefix('.').filter(|f| !f.is_empty());
    match field {
        Some(field) => format!("{field} of the {ordinal} entry of {head}"),
        None => format!("the {ordinal} entry of {head}"),
    }
}

/// `1` -> `1st`, `2` -> `2nd`, and the teens that break the pattern.
fn ordinal(n: usize) -> String {
    let suffix = match (n % 10, n % 100) {
        (_, 11..=13) => "th",
        (1, _) => "st",
        (2, _) => "nd",
        (3, _) => "rd",
        _ => "th",
    };
    format!("{n}{suffix}")
}

/// Notes for an unknown key: the nearest known option, and how to add it.
fn suggestion_notes(at: &str) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(nearest) = nearest_option(at) {
        notes.push(format!("did you mean `{nearest}`?"));
    }
    notes.push("`rachna config inspect` lists every option".to_owned());
    notes
}

/// Notes for a missing required field, with the command that supplies it.
fn required_notes(at: &str) -> Vec<String> {
    match at {
        "tier" => vec![
            "accepted: open, internet, allowlist, none".to_owned(),
            "fix it with:  rachna set tier allowlist".to_owned(),
        ],
        "profile" => vec![
            "accepted: sealed, development, online".to_owned(),
            "fix it with:  rachna set profile development".to_owned(),
        ],
        _ => Vec::new(),
    }
}

/// The known option closest to `typo`, if one is close enough to suggest.
///
/// Edit distance with a cutoff: suggesting `ports` for `secrets` would be
/// worse than suggesting nothing, because a confident wrong suggestion sends
/// the user to edit the wrong line.
fn nearest_option(typo: &str) -> Option<&'static str> {
    const KNOWN: &[&str] = &[
        "tier",
        "profile",
        "network",
        "filesystem",
        "ports",
        "tools",
        "secrets",
    ];
    // At most a third of the longer word may differ, and never more than 3
    // edits. Both bounds are needed: a ratio alone accepts 4 edits on a long
    // word, and a fixed cap alone accepts 3 edits on a 4-letter word.
    KNOWN
        .iter()
        .map(|known| (*known, edit_distance(typo, known)))
        .filter(|(known, d)| *d <= 3 && *d * 3 <= typo.len().max(known.len()))
        .min_by_key(|(_, d)| *d)
        .map(|(known, _)| known)
}

/// Levenshtein distance.
///
/// `pub(crate)` because the CLI needs the same nearest-match cutoff for
/// subcommands, and a second implementation would be a place the two could
/// disagree about what counts as a near miss (`AGENTS.md`, "extend the
/// owner").
pub(crate) fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(ca != cb);
            current[j + 1] = substitution.min(previous[j + 1] + 1).min(current[j] + 1);
        }
        core::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "{\n  tier = \"allowist\";\n  netwrk.allow = [ \"a\" ];\n  ports = [ { guest = \"3000\"; } ];\n}\n";

    // ---- rule 1: never a store path --------------------------------------

    #[test]
    fn no_rendering_can_name_a_nix_store_path() {
        // Enforced by construction: `render` takes the user's filename and
        // source, and has no way to name another file. Asserted so a future
        // change that threads a trace through here is caught.
        let every = [
            ConfigError::NotAnObject,
            ConfigError::UnknownKey {
                at: "netwrk".to_owned(),
            },
            ConfigError::Missing {
                at: "tier".to_owned(),
            },
            ConfigError::WrongType {
                at: "tier".to_owned(),
                expected: "a string",
                found: "a number",
            },
            ConfigError::NotOneOf {
                at: "tier".to_owned(),
                found: "x".to_owned(),
                allowed: &["open"],
            },
            ConfigError::MalformedEndpoint {
                at: "network.allow[0]".to_owned(),
                found: "x".to_owned(),
            },
        ];
        for error in &every {
            let rendered = render("rachna.nix", SOURCE, error);
            assert!(
                !rendered.contains("/nix/store"),
                "{error:?} leaked a store path:\n{rendered}"
            );
            assert!(
                rendered.contains("rachna.nix") || rendered.contains("attribute set"),
                "{error:?} named no file:\n{rendered}"
            );
        }
    }

    // ---- rule 2: point at the user's file --------------------------------

    #[test]
    fn the_caret_lands_on_the_offending_key() {
        let rendered = render(
            "rachna.nix",
            SOURCE,
            &ConfigError::UnknownKey {
                at: "netwrk".to_owned(),
            },
        );
        assert!(rendered.contains("rachna.nix:3:3"), "{rendered}");
        assert!(rendered.contains("^^^^^^"), "{rendered}");
        assert!(rendered.contains("no such option"), "{rendered}");
    }

    #[test]
    fn a_nested_path_locates_its_leaf() {
        // `network.allow` may be written nested or dotted; the leaf is what
        // both spellings share.
        let source = "{\n  network = {\n    allow = [ \"bad\" ];\n  };\n}\n";
        let span = locate(source, "network.allow[0]");
        let span = span.expect("the leaf is present");
        assert_eq!(&source[span], "allow");
    }

    #[test]
    fn a_missing_key_renders_without_a_caret_rather_than_a_wrong_one() {
        // `profile` is absent from SOURCE, so there is nothing to point at.
        // A caret on an unrelated line would be worse than none.
        let rendered = render(
            "rachna.nix",
            SOURCE,
            &ConfigError::Missing {
                at: "profile".to_owned(),
            },
        );
        assert!(rendered.contains("is required"), "{rendered}");
        assert!(
            !rendered.contains("^^^"),
            "pointed at something:\n{rendered}"
        );
    }

    #[test]
    fn an_absent_key_locates_nothing() {
        assert_eq!(locate("{ tier = \"none\"; }", "profile"), None);
        assert_eq!(locate("", "tier"), None);
    }

    // ---- rule 3: English, not Nix's rendering ----------------------------

    #[test]
    fn a_list_index_becomes_an_ordinal() {
        // Nix renders the same thing as
        // `network.allow."[definition 1-entry 1]"`.
        assert_eq!(
            english("network.allow[0]"),
            "the 1st entry of network.allow"
        );
        assert_eq!(english("ports[1]"), "the 2nd entry of ports");
        assert_eq!(english("ports[2]"), "the 3rd entry of ports");
        assert_eq!(english("ports[3]"), "the 4th entry of ports");
    }

    #[test]
    fn a_field_inside_a_list_entry_reads_naturally() {
        assert_eq!(english("ports[0].guest"), "guest of the 1st entry of ports");
    }

    #[test]
    fn a_plain_path_is_left_alone() {
        assert_eq!(english("tier"), "tier");
        assert_eq!(english("network.allow"), "network.allow");
    }

    #[test]
    fn the_teens_get_th_not_st() {
        // 11th, 12th, 13th break the 1st/2nd/3rd pattern.
        assert_eq!(english("ports[10]"), "the 11th entry of ports");
        assert_eq!(english("ports[11]"), "the 12th entry of ports");
        assert_eq!(english("ports[12]"), "the 13th entry of ports");
        // And 21st resumes it.
        assert_eq!(english("ports[20]"), "the 21st entry of ports");
    }

    #[test]
    fn a_malformed_index_is_passed_through_unchanged() {
        // Garbage in must not produce a confident wrong ordinal.
        assert_eq!(english("ports[x]"), "ports[x]");
        assert_eq!(english("ports[0"), "ports[0");
    }

    #[test]
    fn only_a_real_key_is_backticked() {
        // `tier` is searchable in the file; "guest of the 1st entry" is a
        // description, and backticking it reads as an attribute that does not
        // exist.
        let key = render(
            "rachna.nix",
            SOURCE,
            &ConfigError::Missing {
                at: "tier".to_owned(),
            },
        );
        assert!(key.contains("`tier` is required"), "{key}");

        let phrase = render(
            "rachna.nix",
            SOURCE,
            &ConfigError::WrongType {
                at: "ports[0].guest".to_owned(),
                expected: "a port number",
                found: "a string",
            },
        );
        assert!(
            phrase.contains("guest of the 1st entry of ports must be"),
            "{phrase}"
        );
        assert!(
            !phrase.contains("`guest of"),
            "backticked a phrase:\n{phrase}"
        );
    }

    // ---- rule 4: the fixing command --------------------------------------

    #[test]
    fn a_missing_axis_carries_the_command_that_supplies_it() {
        // Rachna's CLI edits the same file (00 §5), so the error can hand
        // over a one-liner — the same refund-the-tax idea as the denial
        // report (00 §3.3).
        for (key, expected) in [
            ("tier", "rachna set tier allowlist"),
            ("profile", "rachna set profile development"),
        ] {
            let rendered = render(
                "rachna.nix",
                SOURCE,
                &ConfigError::Missing { at: key.to_owned() },
            );
            assert!(rendered.contains(expected), "{key}:\n{rendered}");
        }
    }

    #[test]
    fn an_unrecognised_value_lists_what_is_accepted() {
        let rendered = render(
            "rachna.nix",
            SOURCE,
            &ConfigError::NotOneOf {
                at: "tier".to_owned(),
                found: "allowist".to_owned(),
                allowed: &["open", "internet", "allowlist", "none"],
            },
        );
        assert!(
            rendered.contains("accepted: open, internet, allowlist, none"),
            "{rendered}"
        );
    }

    #[test]
    fn a_malformed_endpoint_explains_why_a_port_is_required() {
        // Not arbitrary strictness: a grant without a port would be a grant
        // the user did not write (00 §3.2).
        let rendered = render(
            "rachna.nix",
            SOURCE,
            &ConfigError::MalformedEndpoint {
                at: "network.allow[0]".to_owned(),
                found: "github.com".to_owned(),
            },
        );
        assert!(rendered.contains("example.com:443"), "{rendered}");
        assert!(rendered.contains("did not write"), "{rendered}");
    }

    // ---- suggestions ------------------------------------------------------

    #[test]
    fn a_near_miss_is_suggested() {
        for (typo, expected) in [
            ("netwrk", "network"),
            ("tiers", "tier"),
            ("port", "ports"),
            ("secret", "secrets"),
        ] {
            let rendered = render(
                "rachna.nix",
                SOURCE,
                &ConfigError::UnknownKey {
                    at: typo.to_owned(),
                },
            );
            assert!(
                rendered.contains(&format!("did you mean `{expected}`?")),
                "{typo} -> expected {expected}:\n{rendered}"
            );
        }
    }

    #[test]
    fn an_unrelated_key_gets_no_suggestion() {
        // A confident wrong suggestion sends the user to edit the wrong line,
        // which is worse than no suggestion at all.
        let rendered = render(
            "rachna.nix",
            SOURCE,
            &ConfigError::UnknownKey {
                at: "xyzzy".to_owned(),
            },
        );
        assert!(!rendered.contains("did you mean"), "{rendered}");
        // But the discovery path is still offered.
        assert!(rendered.contains("config inspect"), "{rendered}");
    }

    #[test]
    fn suggestions_require_closeness_relative_to_length() {
        // Real typos, suggested.
        assert_eq!(nearest_option("netwrk"), Some("network"));
        assert_eq!(nearest_option("filesystm"), Some("filesystem"));
        // 3 edits from a 4-letter word is not a near miss.
        assert_eq!(nearest_option("abcd"), None);
        assert_eq!(nearest_option("xyzzy"), None);
    }

    #[test]
    fn a_short_abbreviation_is_not_treated_as_a_typo() {
        // Mutation testing found this gap: the test above asserted the
        // claim that BOTH bounds are needed, but every input it used agreed
        // under either bound alone, so three mutants of the cutoff survived.
        //
        // These are the inputs that actually distinguish them, and they are
        // realistic: someone typing an abbreviation rather than misspelling a
        // word. Suggesting `tier` for `tyr` would send them to edit a line
        // they did not mean.
        assert_eq!(nearest_option("tyr"), None, "2 edits on a 3-letter word");
        assert_eq!(nearest_option("pro"), None, "abbreviation, not a typo");
    }

    #[test]
    fn a_long_key_with_a_short_prefix_match_is_not_suggested() {
        // `toolsxyz` is 3 edits from `tools`, and 3 <= 3 passes the cap. Only
        // the ratio rejects it: 3 * 3 = 9 > 8. Without both bounds a user
        // gets told they meant `tools` when they wrote something else
        // entirely.
        assert_eq!(nearest_option("toolsxyz"), None);
    }

    #[test]
    fn the_distance_function_is_a_metric_on_the_cases_that_matter() {
        assert_eq!(edit_distance("", ""), 0);
        assert_eq!(edit_distance("tier", "tier"), 0);
        assert_eq!(edit_distance("", "tier"), 4);
        assert_eq!(edit_distance("tier", ""), 4);
        // One of each edit kind.
        assert_eq!(edit_distance("tier", "tiers"), 1, "insertion");
        assert_eq!(edit_distance("tiers", "tier"), 1, "deletion");
        assert_eq!(edit_distance("tier", "tien"), 1, "substitution");
        // Symmetric.
        assert_eq!(
            edit_distance("netwrk", "network"),
            edit_distance("network", "netwrk")
        );
    }

    // ---- batching ---------------------------------------------------------

    #[test]
    fn every_error_gets_its_own_report() {
        let errors = [
            ConfigError::UnknownKey {
                at: "netwrk".to_owned(),
            },
            ConfigError::Missing {
                at: "profile".to_owned(),
            },
        ];
        let rendered = render_all("rachna.nix", SOURCE, &errors);
        assert_eq!(rendered.matches("error:").count(), 2, "{rendered}");
    }

    #[test]
    fn rendering_nothing_produces_nothing() {
        assert_eq!(render_all("rachna.nix", SOURCE, &[]), "");
    }

    #[test]
    fn a_not_an_object_error_still_says_something_useful() {
        // No path to point at, so the shape of a config is the note.
        let rendered = render("rachna.nix", SOURCE, &ConfigError::NotAnObject);
        assert!(rendered.contains("attribute set"), "{rendered}");
        assert!(rendered.contains("tier"), "{rendered}");
    }
}
