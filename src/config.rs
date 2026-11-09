//! Parsing evaluated `rachna.nix` JSON into a [`Policy`].
//!
//! The shape is what `nix eval --json` actually emits for a realistic config,
//! captured rather than assumed:
//!
//! ```json
//! {
//!   "tier": "allowlist",
//!   "profile": "development",
//!   "network":    { "allow": ["registry.npmjs.org:443"] },
//!   "filesystem": { "mounts": [{ "source": "/p", "target": "/workspace",
//!                                "access": "read-write" }] },
//!   "ports":      [{ "guest": 3000, "host": 3000 }],
//!   "tools":      { "expose": [{ "name": "rust-analyzer", "kind": "lsp",
//!                                "network": false }] },
//!   "secrets":    ["aws"]
//! }
//! ```
//!
//! # Refuse, never partially apply
//!
//! `18-NIX-BOUNDARY.md` §2 requires that a broken config keep the last-good
//! policy rather than disturb a running environment. So this returns
//! `Result<Policy, _>` and **every** problem is collected before returning:
//! a user fixing one typo should not have to re-run to find the second,
//! which is the same batch principle as the denial report
//! (`00-PRODUCT.md` §3.3).
//!
//! # Unknown keys are an error, not ignored
//!
//! A misspelled `netwrk.allow` that parsed as "no network grants" would
//! silently *narrow* a policy — and the user would see a confusing denial
//! rather than a config error. The module system catches this at evaluation
//! (`22` §2.2) and this is the second line of defence, for the case where a
//! key is well-formed JSON that no option declared.

use crate::decide::{Capabilities, Policy};
use crate::decision::Access;
use crate::grant::{Endpoint, Grant, ToolKind};
use crate::policy::{Profile, Tier};
use crate::resources::Resources;
use core::fmt;
use std::path::PathBuf;

/// One problem found while parsing a config.
///
/// Carries the JSON path so the message can name where to look. There is no
/// `Other(String)`: each variant is a distinct thing to tell the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The document was not an object.
    NotAnObject,
    /// A value had the wrong JSON type.
    WrongType {
        at: String,
        expected: &'static str,
        found: &'static str,
    },
    /// A string was not one of the accepted words.
    ///
    /// Carries the alternatives, because a config error that does not say
    /// what *would* work is half an error (`22` §4.2).
    NotOneOf {
        at: String,
        found: String,
        allowed: &'static [&'static str],
    },
    /// A key no option declared.
    UnknownKey { at: String },
    /// A required field was absent.
    Missing { at: String },
    /// A network endpoint could not be parsed.
    MalformedEndpoint { at: String, found: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnObject => f.write_str("rachna.nix must evaluate to an attribute set"),
            Self::WrongType {
                at,
                expected,
                found,
            } => write!(f, "{at}: expected {expected}, found {found}"),
            Self::NotOneOf { at, found, allowed } => {
                write!(f, "{at}: {found:?} is not one of {}", allowed.join(", "))
            }
            Self::UnknownKey { at } => write!(f, "{at}: no such option"),
            Self::Missing { at } => write!(f, "{at}: required"),
            Self::MalformedEndpoint { at, found } => write!(
                f,
                "{at}: {found:?} is not a host:port — try \"example.com:443\""
            ),
        }
    }
}

impl core::error::Error for ConfigError {}

/// Every problem found, in the order found.
///
/// A list rather than a single error because partial application is forbidden
/// and one-at-a-time reporting is hostile: `19` §2's config has seven keys,
/// and three typos should produce three lines, not three runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigErrors(Vec<ConfigError>);

impl ConfigErrors {
    /// Every problem.
    #[must_use]
    pub fn all(&self) -> &[ConfigError] {
        &self.0
    }
}

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for error in &self.0 {
            writeln!(f, "  {error}")?;
        }
        Ok(())
    }
}

impl core::error::Error for ConfigErrors {}

/// The keys `rachna.nix` may contain at the top level.
///
/// Listed so an unknown key is an error rather than silence, and so the
/// suggestion machinery has something to compare against.
const TOP_LEVEL_KEYS: &[&str] = &[
    "tier",
    "profile",
    "network",
    "filesystem",
    "ports",
    "tools",
    "secrets",
    // `19` §2.1 documents this and the parser rejected it: a rachna.nix
    // copied from the document failed with `resources: no such option`.
    // Same defect as `kind = "command"` (`21` §2.5).
    "resources",
];

/// Parses evaluated config JSON into a [`Policy`].
///
/// `capabilities` comes from the backend, not the config: what the host can
/// enforce is not a project's choice (`08-POLICY-AND-STORE.md` §1.2 step 5).
///
/// # Errors
///
/// Returns every problem found. A config with any problem yields no policy at
/// all — never a partially-applied one.
pub fn parse(json: &str, capabilities: Capabilities) -> Result<Policy, ConfigErrors> {
    let value: serde_json::Value = match serde_json::from_str(json) {
        Ok(value) => value,
        // A parse failure here is our bug or a Nix change, not a user error:
        // `nix eval --json` emits valid JSON or fails. Reported as
        // `NotAnObject` rather than leaking a serde message that names byte
        // offsets in output the user never saw.
        Err(_) => return Err(ConfigErrors(vec![ConfigError::NotAnObject])),
    };

    let Some(root) = value.as_object() else {
        return Err(ConfigErrors(vec![ConfigError::NotAnObject]));
    };

    let mut errors = Vec::new();

    for key in root.keys() {
        if !TOP_LEVEL_KEYS.contains(&key.as_str()) {
            errors.push(ConfigError::UnknownKey { at: key.clone() });
        }
    }

    let tier = enum_field(root, "tier", TIERS, &mut errors).unwrap_or(Tier::None);
    let profile = enum_field(root, "profile", PROFILES, &mut errors).unwrap_or(Profile::Sealed);
    let resources = resources(root, &mut errors);

    let mut grants = Vec::new();
    network_grants(root, &mut grants, &mut errors);
    mount_grants(root, &mut grants, &mut errors);
    port_grants(root, &mut grants, &mut errors);
    tool_grants(root, &mut grants, &mut errors);
    secret_grants(root, &mut grants, &mut errors);

    if errors.is_empty() {
        Ok(Policy {
            tier,
            profile,
            grants,
            resources,
            capabilities,
        })
    } else {
        Err(ConfigErrors(errors))
    }
}

/// The words accepted for `tier`, paired with their value.
const TIERS: &[(&str, Tier)] = &[
    ("open", Tier::Open),
    ("internet", Tier::Internet),
    ("allowlist", Tier::Allowlist),
    ("none", Tier::None),
];

/// The words accepted for `profile`.
const PROFILES: &[(&str, Profile)] = &[
    ("sealed", Profile::Sealed),
    ("development", Profile::Development),
    ("online", Profile::Online),
];

/// The JSON type name, for an error message that names what was found.
fn type_of(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "a list",
        serde_json::Value::Object(_) => "an attribute set",
    }
}

type Object = serde_json::Map<String, serde_json::Value>;

/// Reads a required enum-valued string field.
fn enum_field<T: Copy>(
    root: &Object,
    key: &str,
    allowed: &'static [(&'static str, T)],
    errors: &mut Vec<ConfigError>,
) -> Option<T> {
    let words: &'static [&'static str] = match key {
        "tier" => &["open", "internet", "allowlist", "none"],
        _ => &["sealed", "development", "online"],
    };

    let Some(value) = root.get(key) else {
        errors.push(ConfigError::Missing { at: key.to_owned() });
        return None;
    };
    let Some(text) = value.as_str() else {
        errors.push(ConfigError::WrongType {
            at: key.to_owned(),
            expected: "a string",
            found: type_of(value),
        });
        return None;
    };
    match allowed.iter().find(|(word, _)| *word == text) {
        Some((_, parsed)) => Some(*parsed),
        None => {
            errors.push(ConfigError::NotOneOf {
                at: key.to_owned(),
                found: text.to_owned(),
                allowed: words,
            });
            None
        }
    }
}

/// Reads a list of objects at `outer.inner`, calling `each` per element.
fn each_in_list(
    root: &Object,
    outer: &str,
    inner: Option<&str>,
    errors: &mut Vec<ConfigError>,
    mut each: impl FnMut(&serde_json::Value, &str, &mut Vec<ConfigError>),
) {
    let (path, value) = match inner {
        None => (outer.to_owned(), root.get(outer)),
        Some(inner) => (
            format!("{outer}.{inner}"),
            root.get(outer).and_then(|v| v.as_object()?.get(inner)),
        ),
    };
    // Absent is legitimate: a config granting no network is valid and common.
    let Some(value) = value else { return };
    let Some(list) = value.as_array() else {
        errors.push(ConfigError::WrongType {
            at: path,
            expected: "a list",
            found: type_of(value),
        });
        return;
    };
    for (index, element) in list.iter().enumerate() {
        each(element, &format!("{path}[{index}]"), errors);
    }
}

fn network_grants(root: &Object, grants: &mut Vec<Grant>, errors: &mut Vec<ConfigError>) {
    each_in_list(
        root,
        "network",
        Some("allow"),
        errors,
        |element, at, errors| {
            let Some(text) = element.as_str() else {
                errors.push(ConfigError::WrongType {
                    at: at.to_owned(),
                    expected: "a string",
                    found: type_of(element),
                });
                return;
            };
            match parse_endpoint(text) {
                Some(endpoint) => grants.push(Grant::Network { endpoint }),
                None => errors.push(ConfigError::MalformedEndpoint {
                    at: at.to_owned(),
                    found: text.to_owned(),
                }),
            }
        },
    );
}

/// Splits `host:port`.
///
/// Rejects a missing port rather than defaulting to 443: a grant for
/// `github.com` that silently meant `:443` would be a grant the user did not
/// write, and `00-PRODUCT.md` §3.2 is explicit that the file is the only
/// authority. Splits on the LAST colon so an IPv6 literal is not mangled.
fn parse_endpoint(text: &str) -> Option<Endpoint> {
    let (host, port) = text.rsplit_once(':')?;
    Endpoint::new(host, port.parse().ok()?).ok()
}

fn mount_grants(root: &Object, grants: &mut Vec<Grant>, errors: &mut Vec<ConfigError>) {
    each_in_list(
        root,
        "filesystem",
        Some("mounts"),
        errors,
        |element, at, errors| {
            let Some(mount) = element.as_object() else {
                errors.push(ConfigError::WrongType {
                    at: at.to_owned(),
                    expected: "an attribute set",
                    found: type_of(element),
                });
                return;
            };
            let source = string_field(mount, at, "source", errors);
            // READ, not discarded. This field was documented in this file's
            // own header, asserted in its tests, and thrown away — so
            // `target` was a documented feature that did nothing. Optional:
            // a mount with no target gets the guest's default, which is the
            // workspace.
            let target = mount
                .get("target")
                .and_then(|value| value.as_str())
                .map(PathBuf::from);
            let access = match mount.get("access").and_then(|v| v.as_str()) {
                // Through `Access::parse`, not a match here: these two words
                // had four separate spellings in this file, which is the
                // shape that let `ToolKind` drift from the spec.
                Some(word) if Access::parse(word).is_some() => Access::parse(word),
                Some(other) => {
                    errors.push(ConfigError::NotOneOf {
                        at: format!("{at}.access"),
                        found: other.to_owned(),
                        allowed: &Access::ALLOWED_WORDS,
                    });
                    None
                }
                // Absent means read-only: the safe default, so a forgotten
                // field cannot silently grant writes.
                None => Some(Access::ReadOnly),
            };
            if let (Some(source), Some(access)) = (source, access) {
                grants.push(Grant::Filesystem {
                    path: PathBuf::from(source),
                    target,
                    access,
                });
            }
        },
    );
}

fn port_grants(root: &Object, grants: &mut Vec<Grant>, errors: &mut Vec<ConfigError>) {
    each_in_list(root, "ports", None, errors, |element, at, errors| {
        let Some(port) = element.as_object() else {
            errors.push(ConfigError::WrongType {
                at: at.to_owned(),
                expected: "an attribute set",
                found: type_of(element),
            });
            return;
        };
        let guest = port_number(port, at, "guest", errors);
        // Absent means "the same as the guest port", which is what every real
        // config writes anyway (`20` §2).
        let host = match port.get("host") {
            None => guest,
            Some(_) => port_number(port, at, "host", errors),
        };
        if let (Some(guest), Some(host)) = (guest, host) {
            grants.push(Grant::Port { guest, host });
        }
    });
}

fn tool_grants(root: &Object, grants: &mut Vec<Grant>, errors: &mut Vec<ConfigError>) {
    each_in_list(
        root,
        "tools",
        Some("expose"),
        errors,
        |element, at, errors| {
            let Some(tool) = element.as_object() else {
                errors.push(ConfigError::WrongType {
                    at: at.to_owned(),
                    expected: "an attribute set",
                    found: type_of(element),
                });
                return;
            };
            let name = string_field(tool, at, "name", errors);
            // Parsed through `ToolKind::parse`, not a match written here.
            // The hand-written version was MISSING `command`, which `00` §6.4
            // declares for cargo — so a rachna.nix using the documented
            // spelling was rejected. One list, derived from `ALL`.
            let kind = match tool.get("kind").and_then(|v| v.as_str()) {
                Some(word) if ToolKind::parse(word).is_some() => ToolKind::parse(word),
                Some(other) => {
                    errors.push(ConfigError::NotOneOf {
                        at: format!("{at}.kind"),
                        found: other.to_owned(),
                        allowed: &ToolKind::ALLOWED_WORDS,
                    });
                    None
                }
                None => {
                    errors.push(ConfigError::Missing {
                        at: format!("{at}.kind"),
                    });
                    None
                }
            };
            // Absent means no network: a tool is a distinct principal
            // (`00` §11.2), and defaulting to network access would grant
            // something nobody wrote.
            let network = tool.get("network").and_then(serde_json::Value::as_bool);
            if let (Some(name), Some(kind)) = (name, kind) {
                grants.push(Grant::Tool {
                    name,
                    kind,
                    network: network.unwrap_or(false),
                });
            }
        },
    );
}

/// `resources = { cpus = 4; memory = "2GB"; disk = "20GB"; processes = 512; }`
///
/// Every field defaults, because `19` §4.5's property is that an empty
/// `rachna.nix` is valid — the Nix module supplies these before this parser
/// runs, so a missing field here means a caller passed partial JSON rather
/// than a user omitting something.
///
/// A **present but wrong** field is an error rather than a fallback to the
/// default. `00` §5.3 rule 4's reasoning applies: a value that silently means
/// something other than what it says is the same failure class as a limit
/// that is declared and never enforced.
fn resources(root: &Object, errors: &mut Vec<ConfigError>) -> Resources {
    let defaults = Resources::default();
    let Some(value) = root.get("resources") else {
        return defaults;
    };
    let Some(table) = value.as_object() else {
        errors.push(ConfigError::WrongType {
            at: "resources".to_owned(),
            expected: "an attribute set",
            found: type_of(value),
        });
        return defaults;
    };

    Resources {
        cpus: count_field(table, "resources.cpus", defaults.cpus, errors),
        memory_mib: size_field(table, "resources.memory", defaults.memory_mib, errors),
        disk_mib: size_field(table, "resources.disk", defaults.disk_mib, errors),
        processes: count_field(table, "resources.processes", defaults.processes, errors),
    }
}

/// A positive count, or `fallback` with an error recorded.
fn count_field(table: &Object, at: &str, fallback: u32, errors: &mut Vec<ConfigError>) -> u32 {
    let key = at.rsplit('.').next().unwrap_or(at);
    let Some(value) = table.get(key) else {
        return fallback;
    };
    match value.as_u64() {
        // Zero is refused for the same reason a zero size is: a VM with no
        // vCPUs does not start, and the failure would name neither.
        Some(0) | None => {
            errors.push(ConfigError::WrongType {
                at: at.to_owned(),
                expected: "a positive whole number",
                found: type_of(value),
            });
            fallback
        }
        Some(count) => u32::try_from(count).unwrap_or(u32::MAX),
    }
}

/// A size string like `"2GB"`, or `fallback` with an error recorded.
fn size_field(table: &Object, at: &str, fallback: u64, errors: &mut Vec<ConfigError>) -> u64 {
    let key = at.rsplit('.').next().unwrap_or(at);
    let Some(value) = table.get(key) else {
        return fallback;
    };
    // A bare number is accepted as mebibytes, matching Cloud Hypervisor's
    // own `size=2048M`, so `memory = 2048` is not a type error.
    if let Some(number) = value.as_u64() {
        if number == 0 {
            errors.push(ConfigError::NotOneOf {
                at: at.to_owned(),
                found: "0".to_owned(),
                allowed: &["a size such as 2GB"],
            });
            return fallback;
        }
        return number;
    }
    let Some(text) = value.as_str() else {
        errors.push(ConfigError::WrongType {
            at: at.to_owned(),
            expected: "a size such as \"2GB\"",
            found: type_of(value),
        });
        return fallback;
    };
    match crate::resources::parse_size(text) {
        Ok(mib) => mib,
        Err(error) => {
            // The size parser's own message, so the user sees what shape
            // works rather than a generic type complaint.
            errors.push(ConfigError::NotOneOf {
                at: at.to_owned(),
                found: text.to_owned(),
                allowed: &["MB", "MiB", "GB", "GiB"],
            });
            let _ = error;
            fallback
        }
    }
}

fn secret_grants(root: &Object, grants: &mut Vec<Grant>, errors: &mut Vec<ConfigError>) {
    each_in_list(
        root,
        "secrets",
        None,
        errors,
        |element, at, errors| match element.as_str() {
            Some(name) => grants.push(Grant::Secret {
                name: name.to_owned(),
            }),
            None => errors.push(ConfigError::WrongType {
                at: at.to_owned(),
                expected: "a string",
                found: type_of(element),
            }),
        },
    );
}

fn string_field(
    object: &Object,
    at: &str,
    key: &str,
    errors: &mut Vec<ConfigError>,
) -> Option<String> {
    match object.get(key) {
        Some(serde_json::Value::String(text)) => Some(text.clone()),
        Some(other) => {
            errors.push(ConfigError::WrongType {
                at: format!("{at}.{key}"),
                expected: "a string",
                found: type_of(other),
            });
            None
        }
        None => {
            errors.push(ConfigError::Missing {
                at: format!("{at}.{key}"),
            });
            None
        }
    }
}

fn port_number(object: &Object, at: &str, key: &str, errors: &mut Vec<ConfigError>) -> Option<u16> {
    let value = object.get(key)?;
    match value.as_u64().and_then(|n| u16::try_from(n).ok()) {
        Some(port) => Some(port),
        None => {
            errors.push(ConfigError::WrongType {
                at: format!("{at}.{key}"),
                expected: "a port number from 0 to 65535",
                found: type_of(value),
            });
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::Category;

    /// Exactly what `nix eval --json` emitted for a realistic config,
    /// captured from a real evaluation rather than hand-written.
    const REAL: &str = r#"{
      "filesystem": { "mounts": [
        { "access": "read-write", "source": "/Users/you/proj",
          "target": "/workspace" } ] },
      "network": { "allow": [ "registry.npmjs.org:443", "github.com:443" ] },
      "ports": [ { "guest": 3000, "host": 3000 } ],
      "profile": "development",
      "secrets": [ "aws" ],
      "tier": "allowlist",
      "tools": { "expose": [
        { "kind": "lsp", "name": "rust-analyzer", "network": false } ] }
    }"#;

    fn parsed(json: &str) -> Policy {
        parse(json, Capabilities::all()).expect("fixture must parse")
    }

    fn errors(json: &str) -> Vec<ConfigError> {
        parse(json, Capabilities::all())
            .expect_err("fixture must fail")
            .all()
            .to_vec()
    }

    #[test]
    fn a_mount_carries_where_the_guest_sees_it() {
        // THE generic host-to-guest mapping, and it was documented without
        // being implemented: this file's own header showed `"target":
        // "/workspace"`, a test asserted a config containing it parsed, and
        // the parser read `source` and `access` and dropped `target` on the
        // floor. `Grant::Filesystem` had nowhere to put it.
        //
        // Dotfiles are the case that made the gap obvious — a `.zshrc` is
        // only a shell config if it lands at `~/.zshrc`, and the same file
        // anywhere else is inert — but the mechanism is general: editor
        // config, a shared cache, a scratch volume.
        let policy = parse(
            r#"{ "tier": "allowlist", "profile": "development",
                  "filesystem": { "mounts": [
                    { "source": "/Users/you/.zshrc",
                      "target": "/home/dev/.zshrc" } ] } }"#,
            Capabilities::all(),
        )
        .expect("a mount with a target must parse");

        let Some(crate::grant::Grant::Filesystem {
            path,
            target,
            access,
        }) = policy.grants.first()
        else {
            panic!("no filesystem grant: {:?}", policy.grants)
        };
        assert_eq!(path, &PathBuf::from("/Users/you/.zshrc"));
        assert_eq!(
            target.as_deref(),
            Some(std::path::Path::new("/home/dev/.zshrc")),
            "the target was parsed and discarded"
        );
        // And read-only by default: a dotfile the guest can rewrite is a
        // dotfile the guest can use to change what runs on your host next
        // time you open a shell.
        assert_eq!(*access, Access::ReadOnly);
    }

    #[test]
    fn a_mount_without_a_target_is_still_valid() {
        // The target is OPTIONAL: the common case is the workspace, and
        // requiring a destination for it would be ceremony.
        let policy = parse(
            r#"{ "tier": "allowlist", "profile": "development",
                  "filesystem": { "mounts": [ { "source": "." } ] } }"#,
            Capabilities::all(),
        )
        .expect("a mount with no target must parse");
        let Some(crate::grant::Grant::Filesystem { target, .. }) = policy.grants.first() else {
            panic!("no filesystem grant")
        };
        assert_eq!(*target, None);
    }

    #[test]
    fn the_real_evaluation_output_parses_into_every_grant() {
        let policy = parsed(REAL);
        assert_eq!(policy.tier, Tier::Allowlist);
        assert_eq!(policy.profile, Profile::Development);

        let mut categories: Vec<Category> = policy.grants.iter().map(Grant::category).collect();
        categories.sort_unstable();
        categories.dedup();
        assert_eq!(
            categories,
            Category::ALL.to_vec(),
            "a realistic config should exercise every category"
        );
        assert_eq!(policy.grants.len(), 6, "two hosts plus one of each other");
    }

    #[test]
    fn capabilities_come_from_the_backend_not_the_config() {
        // What the host can enforce is not a project's choice
        // (08 §1.2 step 5). A config cannot widen it by declaring anything.
        let policy = parse(REAL, Capabilities::lacking([Category::Port])).expect("parses");
        assert!(!policy.capabilities.enforces(Category::Port));
    }

    // ---- refuse, never partially apply ----------------------------------

    #[test]
    fn a_config_with_any_error_yields_no_policy_at_all() {
        // 18 §2: a broken config must keep the last-good policy rather than
        // disturb a running environment. One bad field must not produce a
        // policy missing one grant.
        let json = r#"{ "tier": "allowlist", "profile": "development",
                        "network": { "allow": [ "no-port-here" ] } }"#;
        assert!(parse(json, Capabilities::all()).is_err());
    }

    #[test]
    fn every_problem_is_reported_not_just_the_first() {
        // Three typos should produce three lines, not three runs — the same
        // batch principle as the denial report (00 §3.3).
        let json = r#"{ "tier": "allowist", "profile": "developmnt",
                        "network": { "allow": [ "bad" ] } }"#;
        let found = errors(json);
        assert_eq!(found.len(), 3, "got {found:#?}");
    }

    // ---- unknown keys ----------------------------------------------------

    #[test]
    fn a_misspelled_top_level_key_is_an_error_not_silence() {
        // `netwrk.allow` parsing as "no network grants" would silently NARROW
        // the policy, and the user would see a confusing denial rather than a
        // config error.
        let json = r#"{ "tier": "allowlist", "profile": "development",
                        "netwrk": { "allow": [ "a:1" ] } }"#;
        assert_eq!(
            errors(json),
            [ConfigError::UnknownKey {
                at: "netwrk".to_owned()
            }]
        );
    }

    // ---- the enum fields -------------------------------------------------

    #[test]
    fn an_unrecognised_tier_lists_the_alternatives() {
        // A config error that does not say what WOULD work is half an error
        // (22 §4.2).
        let json = r#"{ "tier": "allowist", "profile": "development" }"#;
        let found = errors(json);
        assert_eq!(
            found,
            [ConfigError::NotOneOf {
                at: "tier".to_owned(),
                found: "allowist".to_owned(),
                allowed: &["open", "internet", "allowlist", "none"],
            }]
        );
        let message = found[0].to_string();
        assert!(message.contains("allowlist"), "{message}");
    }

    #[test]
    fn every_tier_and_profile_word_round_trips() {
        for (word, expected) in TIERS {
            let json = format!(r#"{{ "tier": "{word}", "profile": "development" }}"#);
            assert_eq!(parsed(&json).tier, *expected, "tier {word}");
        }
        for (word, expected) in PROFILES {
            let json = format!(r#"{{ "tier": "none", "profile": "{word}" }}"#);
            assert_eq!(parsed(&json).profile, *expected, "profile {word}");
        }
    }

    #[test]
    fn a_missing_axis_is_required_rather_than_defaulted() {
        // Defaulting a missing `tier` would mean a config that says nothing
        // about network gets a network posture nobody wrote.
        let found = errors(r#"{ "profile": "development" }"#);
        assert!(found.contains(&ConfigError::Missing {
            at: "tier".to_owned()
        }));
    }

    #[test]
    fn a_wrong_typed_axis_names_what_was_found() {
        let found = errors(r#"{ "tier": 3, "profile": "development" }"#);
        assert_eq!(
            found,
            [ConfigError::WrongType {
                at: "tier".to_owned(),
                expected: "a string",
                found: "a number",
            }]
        );
    }

    // ---- endpoints -------------------------------------------------------

    #[test]
    fn a_host_without_a_port_is_refused_rather_than_defaulted() {
        // A grant for `github.com` silently meaning `:443` would be a grant
        // the user did not write, and §3.2 makes the file the only authority.
        let json = r#"{ "tier": "allowlist", "profile": "development",
                        "network": { "allow": [ "github.com" ] } }"#;
        assert_eq!(
            errors(json),
            [ConfigError::MalformedEndpoint {
                at: "network.allow[0]".to_owned(),
                found: "github.com".to_owned(),
            }]
        );
    }

    #[test]
    fn an_ipv6_literal_is_not_mangled_by_the_port_split() {
        // Splitting on the FIRST colon would turn `[::1]:8080` into host
        // `[` — so the split is on the last.
        let json = r#"{ "tier": "allowlist", "profile": "development",
                        "network": { "allow": [ "[::1]:8080" ] } }"#;
        let policy = parsed(json);
        match &policy.grants[0] {
            Grant::Network { endpoint } => {
                assert_eq!(endpoint.host(), "[::1]");
                assert_eq!(endpoint.port(), 8080);
            }
            other => panic!("expected a network grant, got {other:?}"),
        }
    }

    #[test]
    fn a_port_out_of_range_is_refused() {
        let json = r#"{ "tier": "allowlist", "profile": "development",
                        "network": { "allow": [ "a.com:70000" ] } }"#;
        assert!(!errors(json).is_empty());
    }

    #[test]
    fn the_error_message_suggests_the_right_shape() {
        let json = r#"{ "tier": "allowlist", "profile": "development",
                        "network": { "allow": [ "github.com" ] } }"#;
        let message = errors(json)[0].to_string();
        assert!(message.contains("host:port"), "{message}");
        assert!(message.contains("example.com:443"), "{message}");
    }

    // ---- mounts ----------------------------------------------------------

    #[test]
    fn a_mount_with_no_access_defaults_to_read_only() {
        // The safe direction: a forgotten field must not silently grant
        // writes, which is the broadest filesystem permission there is.
        let json = r#"{ "tier": "none", "profile": "development",
                        "filesystem": { "mounts": [ { "source": "/p" } ] } }"#;
        assert_eq!(
            parsed(json).grants,
            [Grant::Filesystem {
                path: PathBuf::from("/p"),
                target: None,
                access: Access::ReadOnly,
            }]
        );
    }

    #[test]
    fn a_mount_with_an_unrecognised_access_lists_the_alternatives() {
        let json = r#"{ "tier": "none", "profile": "development",
                        "filesystem": { "mounts": [
                          { "source": "/p", "access": "rw" } ] } }"#;
        assert_eq!(
            errors(json),
            [ConfigError::NotOneOf {
                at: "filesystem.mounts[0].access".to_owned(),
                found: "rw".to_owned(),
                allowed: &Access::ALLOWED_WORDS,
            }]
        );
    }

    #[test]
    fn a_mount_without_a_source_is_an_error() {
        let json = r#"{ "tier": "none", "profile": "development",
                        "filesystem": { "mounts": [ { "target": "/w" } ] } }"#;
        assert!(errors(json).contains(&ConfigError::Missing {
            at: "filesystem.mounts[0].source".to_owned()
        }));
    }

    // ---- ports -----------------------------------------------------------

    #[test]
    fn a_port_with_no_host_side_mirrors_the_guest() {
        // What every real config writes anyway (20 §2).
        let json = r#"{ "tier": "none", "profile": "development",
                        "ports": [ { "guest": 3000 } ] }"#;
        assert_eq!(
            parsed(json).grants,
            [Grant::Port {
                guest: 3000,
                host: 3000
            }]
        );
    }

    #[test]
    fn a_non_numeric_port_is_refused() {
        let json = r#"{ "tier": "none", "profile": "development",
                        "ports": [ { "guest": "3000" } ] }"#;
        assert!(!errors(json).is_empty());
    }

    // ---- tools -----------------------------------------------------------

    #[test]
    fn a_tool_without_an_explicit_network_field_gets_none() {
        // A tool is a distinct principal (00 §11.2); defaulting to network
        // access would grant something nobody wrote.
        let json = r#"{ "tier": "none", "profile": "development",
                        "tools": { "expose": [
                          { "name": "gopls", "kind": "lsp" } ] } }"#;
        assert_eq!(
            parsed(json).grants,
            [Grant::Tool {
                name: "gopls".to_owned(),
                kind: ToolKind::Lsp,
                network: false,
            }]
        );
    }

    #[test]
    fn every_enumerated_option_accepts_exactly_the_words_the_spec_documents() {
        // The general version of the `kind = "command"` bug: four options in
        // `rachna.nix` take a word from a fixed set, and each set exists in
        // two places — the document and the code. `ToolKind` drifted; these
        // pin the other three before they do.
        //
        // The literals come from `19` §2.1 and §2.2's own comments:
        //
        //   tier    = "allowlist";   # open | internet | allowlist | none
        //   profile = "development"; # sealed | development | online
        //   access  = "read-write";  # read-only | read-write
        //   kind    = "lsp";         # lsp | formatter | debugger | command
        //
        // Deliberately NOT derived from `Tier::ALL` and friends: a test
        // driven by the code's own enumeration only checks the code against
        // itself, which is exactly why the first version of the tool-kind
        // test passed while the bug was present.
        let documented: [(&str, &[&str]); 4] = [
            ("tier", &["open", "internet", "allowlist", "none"]),
            ("profile", &["sealed", "development", "online"]),
            ("access", &["read-only", "read-write"]),
            ("kind", &["lsp", "formatter", "debugger", "command"]),
        ];
        for (option, words) in documented {
            let accepted: Vec<&str> = match option {
                "tier" => Tier::ALL.iter().map(|t| t.as_str()).collect(),
                "profile" => Profile::ALL.iter().map(|p| p.as_str()).collect(),
                "access" => Access::ALL.iter().map(|a| a.as_str()).collect(),
                "kind" => ToolKind::ALL.iter().map(|k| k.as_str()).collect(),
                other => panic!("unhandled option `{other}`"),
            };
            let mut expected: Vec<&str> = words.to_vec();
            expected.sort_unstable();
            let mut actual = accepted;
            actual.sort_unstable();
            assert_eq!(
                actual, expected,
                "`{option}` accepts {actual:?} but the spec documents {expected:?}"
            );
        }
    }

    #[test]
    fn the_resources_block_19_section_2_1_documents_parses() {
        // THE bug this closes. `19` §2.1 documents
        //   resources = { cpus = 4; memory = "2GB"; disk = "20GB";
        //                 processes = 512; };
        // and the parser rejected the whole config with `resources: no such
        // option` — a documented option the code refuses, exactly the
        // `kind = "command"` defect (`21` §2.5).
        let policy = parsed(
            r#"{ "tier": "allowlist", "profile": "development",
                 "resources": { "cpus": 8, "memory": "4GB",
                                "disk": "40GB", "processes": 1024 } }"#,
        );
        assert_eq!(policy.resources.cpus, 8);
        assert_eq!(policy.resources.memory_mib, 4096);
        assert_eq!(policy.resources.disk_mib, 40960);
        assert_eq!(policy.resources.processes, 1024);
        // And the quota comes with the count, per `15` §3.2.
        assert_eq!(policy.resources.host_cpu_quota_percent(), 800);
    }

    #[test]
    fn an_omitted_resources_block_gets_the_declared_defaults() {
        // What happens when a user writes no limits — `19` §4.5's property
        // that an empty config is valid. The Nix module supplies these
        // before this parser runs, so a missing block here means partial
        // JSON rather than a user omission; either way the answer must be
        // the documented defaults, not zeroes.
        let policy = parsed(r#"{ "tier": "allowlist", "profile": "development" }"#);
        assert_eq!(policy.resources, Resources::default());
        assert_eq!(policy.resources.cpus, 4);
        assert_eq!(policy.resources.memory_mib, 2048);
    }

    #[test]
    fn a_partial_resources_block_defaults_only_what_is_missing() {
        // A user tuning one field must not silently lose the others.
        let policy = parsed(
            r#"{ "tier": "allowlist", "profile": "development",
                 "resources": { "memory": "8GB" } }"#,
        );
        assert_eq!(policy.resources.memory_mib, 8192);
        assert_eq!(policy.resources.cpus, Resources::default().cpus);
        assert_eq!(policy.resources.disk_mib, Resources::default().disk_mib);
    }

    #[test]
    fn a_present_but_wrong_resource_is_an_error_not_a_silent_default() {
        // `00` §5.3 rule 4's reasoning: a value that silently means
        // something other than what it says is the same failure class as a
        // limit declared and never enforced. Falling back to the default
        // here would give a user 2 GB when they asked for "lots" and told
        // them nothing.
        for (json, at) in [
            (r#"{"cpus": 0}"#, "resources.cpus"),
            (r#"{"cpus": "four"}"#, "resources.cpus"),
            (r#"{"memory": "lots"}"#, "resources.memory"),
            (r#"{"memory": 0}"#, "resources.memory"),
            (r#"{"disk": "20TB"}"#, "resources.disk"),
            (r#"{"processes": 0}"#, "resources.processes"),
        ] {
            let config = format!(
                r#"{{ "tier": "allowlist", "profile": "development",
                      "resources": {json} }}"#
            );
            let found = errors(&config);
            assert!(
                found.iter().any(|error| error.to_string().contains(at)),
                "{json} did not produce an error naming {at}: {found:?}"
            );
        }
    }

    #[test]
    fn a_resources_value_that_is_not_an_attribute_set_says_so() {
        let found = errors(r#"{ "tier": "allowlist", "profile": "development", "resources": 4 }"#);
        assert!(found.contains(&ConfigError::WrongType {
            at: "resources".to_owned(),
            expected: "an attribute set",
            found: "a number",
        }));
    }

    #[test]
    fn a_bare_number_is_mebibytes_matching_cloud_hypervisor() {
        // CH's own `--memory size=2048M`, so `memory = 2048` is not a type
        // error — it is the same unit the hypervisor uses.
        let policy = parsed(
            r#"{ "tier": "allowlist", "profile": "development",
                 "resources": { "memory": 2048 } }"#,
        );
        assert_eq!(policy.resources.memory_mib, 2048);
    }

    #[test]
    fn every_tool_kind_the_spec_documents_parses() {
        // THE test that was missing, and the reason the bug existed: the
        // parser had a hand-written match listing three kinds while `00`
        // §6.4's own example declares four — `{ name = "cargo"; kind =
        // "command"; }`. So a rachna.nix written from the documentation was
        // REJECTED, and nothing noticed.
        //
        // PINNED AGAINST THE SPEC'S LITERAL WORDS, not against
        // `ToolKind::ALL`. A first version of this test iterated `ALL`, and
        // that version does not catch the bug: dropping `Command` from `ALL`
        // also drops it from the test, so the test and the defect move
        // together. Verified by doing exactly that — every test still passed.
        //
        // These four strings are `00` §6.4's `kind =` values, copied from the
        // document. A spec-conformance test has to be anchored to the
        // document, or it only checks the code against itself.
        for word in ["lsp", "formatter", "debugger", "command"] {
            let kind = ToolKind::parse(word)
                .unwrap_or_else(|| panic!("`00` §6.4 declares `kind = \"{word}\"`, unparseable"));
            let json = format!(
                r#"{{ "tier": "none", "profile": "development",
                      "tools": {{ "expose": [ {{ "name": "t", "kind": "{word}" }} ] }} }}"#
            );
            // `parsed`, not `errors`: the latter EXPECTS a failure and
            // panics on a clean parse, which is what my first version of
            // this test hit. The policy that comes back is also checked, so
            // "it parsed" cannot mean "it parsed into something else".
            let policy = parsed(&json);
            assert_eq!(
                policy.grants,
                vec![Grant::Tool {
                    name: "t".to_owned(),
                    kind,
                    network: false,
                }],
                "`kind = \"{word}\"` did not round-trip"
            );
        }

        // And an undocumented kind is still refused — so the loop above is
        // not passing because the parser accepts everything.
        let json = r#"{ "tier": "none", "profile": "development",
                        "tools": { "expose": [ { "name": "t", "kind": "linter" } ] } }"#;
        let found = errors(json);
        assert!(
            found.iter().any(|error| matches!(
                error,
                ConfigError::NotOneOf { found, .. } if found == "linter"
            )),
            "an unknown kind was accepted: {found:?}"
        );
        // The error must name every kind the parser accepts, which is what
        // `ALLOWED_WORDS` being tied to `ALL`'s length enforces.
        let message = found
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        for word in ["lsp", "formatter", "debugger", "command"] {
            assert!(
                message.contains(word),
                "the error omits `{word}`, which `00` §6.4 declares: {message}"
            );
        }
    }

    #[test]
    fn a_tool_without_a_kind_is_an_error() {
        // The kind decides how Rachna proxies it, so guessing would mean
        // proxying an LSP as a formatter.
        let json = r#"{ "tier": "none", "profile": "development",
                        "tools": { "expose": [ { "name": "x" } ] } }"#;
        assert!(errors(json).contains(&ConfigError::Missing {
            at: "tools.expose[0].kind".to_owned()
        }));
    }

    #[test]
    fn every_tool_kind_word_parses() {
        for (word, expected) in [
            ("lsp", ToolKind::Lsp),
            ("formatter", ToolKind::Formatter),
            ("debugger", ToolKind::Debugger),
        ] {
            let json = format!(
                r#"{{ "tier": "none", "profile": "development",
                      "tools": {{ "expose": [
                        {{ "name": "t", "kind": "{word}" }} ] }} }}"#
            );
            match &parsed(&json).grants[0] {
                Grant::Tool { kind, .. } => assert_eq!(*kind, expected),
                other => panic!("expected a tool grant, got {other:?}"),
            }
        }
    }

    // ---- absence is legitimate ------------------------------------------

    #[test]
    fn a_config_granting_nothing_is_valid() {
        // Deny-by-default means the minimal config is the two axes and
        // nothing else. It must not be an error.
        let json = r#"{ "tier": "none", "profile": "sealed" }"#;
        let policy = parsed(json);
        assert!(policy.grants.is_empty());
    }

    #[test]
    fn a_grant_list_that_is_not_a_list_names_the_type() {
        let json = r#"{ "tier": "none", "profile": "development",
                        "network": { "allow": "github.com:443" } }"#;
        assert_eq!(
            errors(json),
            [ConfigError::WrongType {
                at: "network.allow".to_owned(),
                expected: "a list",
                found: "a string",
            }]
        );
    }

    #[test]
    fn a_non_object_document_is_refused() {
        assert_eq!(errors("[1,2,3]"), [ConfigError::NotAnObject]);
        assert_eq!(errors("null"), [ConfigError::NotAnObject]);
        // Invalid JSON is our bug or a Nix change, not a user error, so it
        // does not leak a serde message about byte offsets in output the user
        // never saw.
        assert_eq!(errors("{not json"), [ConfigError::NotAnObject]);
    }

    #[test]
    fn errors_render_one_per_line() {
        let json = r#"{ "tier": "nope", "profile": "nope" }"#;
        let rendered = parse(json, Capabilities::all())
            .expect_err("fails")
            .to_string();
        assert_eq!(rendered.lines().count(), 2, "{rendered}");
    }
}
