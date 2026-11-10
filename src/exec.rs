//! What to build and run: the second artifact `rachna.nix` evaluates into.
//!
//! `01-ARCHITECTURE.md` §2.3 specifies exactly two artifacts, and nothing
//! downstream reads the Nix file again:
//!
//! - **[`ExecSpec`]** — what to build and run: packages, services,
//!   entrypoints, environment, volumes.
//! - **`Policy`** (`decide.rs`) — what is permitted.
//!
//! That split is not tidiness. `reload.rs` classifies a config change by
//! diffing these two, so "packages changed, therefore rebuild" is a
//! consequence of the type split rather than a special case someone
//! remembered to write.
//!
//! # Why this module existed only as a comment until now
//!
//! `decide.rs:88` referred to `ExecSpec` and no definition followed. The
//! visible cost was that the demo guest had Node and Postgres **baked into
//! the image**, with their store paths substituted into the init script as
//! `@NODE@` and `@POSTGRES@` — because there was no struct to carry a
//! project's packages and no build step keyed on them. That is the stand-in
//! this module removes.
//!
//! # Packages are strings, deliberately
//!
//! A package is a nixpkgs attribute path (`nodejs_22`, `postgresql_16`) and
//! Rachna does **not** check that it exists. Nix does, when it evaluates —
//! and it gives a better answer than we could, because it knows the pinned
//! nixpkgs. Validating here would mean either shipping an attribute list
//! that rots, or evaluating twice.
//!
//! What we *do* check is the shape: a list of strings, non-empty strings, no
//! duplicates. Those are errors Nix would report confusingly or not at all.
//!
//! # The guest is a NixOS VM and this is the user's half of it
//!
//! `00-PRODUCT.md` §1: you get an isolated Linux computer, and `rachna.nix`
//! is how you say what is in it. Rachna owns the base system — which NixOS
//! release, the kernel, the init, the agent (`19` §3, enforced with
//! `lib.mkForce`) — and the project owns what runs on top. This struct is
//! the project's half.

use crate::config::{type_of as json_type, ConfigError};

/// A package set, services, and how to run the project.
///
/// Everything defaults, because `19` §4.5's property is that an **empty**
/// `rachna.nix` is valid: you get the base guest with no extra packages and
/// no services, which is a useful environment rather than an error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecSpec {
    /// nixpkgs attribute paths, in the order written.
    ///
    /// Order is preserved rather than sorted, so `rachna config inspect`
    /// shows the user their own list back. [`ExecSpec::closure_key`] sorts
    /// for hashing, so order does not change the image identity.
    pub packages: Vec<String>,
    /// Environment variables for the project's processes.
    ///
    /// Sorted by name, so two configs differing only in writing order
    /// produce one image rather than two.
    pub variables: Vec<(String, String)>,
    /// Services to start, in the order written.
    pub services: Vec<Service>,
    /// Named commands: `rachna run dev`.
    pub entrypoints: Vec<(String, String)>,
}

/// A service the guest should start.
///
/// # Why a narrow shape rather than NixOS's own options
///
/// This is the one place `19` §4's "re-expose" rule has a mechanical reason
/// behind it rather than a preference. `services.postgresql` has hundreds of
/// options and several name paths — `dataDir` above all. A project pointing
/// `dataDir` at `/workspace` would put the database on the virtiofs share,
/// where a snapshot would **not** capture it: the whole suspend-and-resume
/// promise (`00` §2.3, "come back to a warm Postgres") depends on service
/// state living on the snapshot-participating volume.
///
/// So Rachna owns the data directory and the project chooses the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// The service name, as the project wrote it.
    pub name: String,
    /// Whether to start it.
    pub enable: bool,
    /// The port it listens on, when it takes one.
    pub port: Option<u16>,
}

impl ExecSpec {
    /// Whether this spec asks for anything beyond the base guest.
    ///
    /// An empty spec can reuse the shipped image; a non-empty one needs a
    /// project-specific build.
    #[must_use]
    pub fn is_bare(&self) -> bool {
        self.packages.is_empty() && self.services.is_empty()
    }

    /// The identity of the guest image this spec requires.
    ///
    /// Two projects declaring the same packages share one built image, so
    /// the second `rachna start` is a cache hit. That is what keeps a
    /// per-project build invisible: `06` §27's closures are **fetched from a
    /// binary cache, never compiled**, so the cost of a hit is a lookup.
    ///
    /// # What goes in, and what deliberately does not
    ///
    /// Packages and services go in: they change the closure. Entrypoints and
    /// variables do **not** — they are read at run time, so changing
    /// `NODE_ENV` must not invalidate a built image. `reload.rs` classifies
    /// those as live changes, and this function has to agree with that or a
    /// live change would trigger a rebuild anyway.
    ///
    /// Sorted before hashing, so declaration order does not fork the cache.
    /// # Why packages and services are hashed as separate fields
    ///
    /// A first version put both in one flat list, with services spelled
    /// `service:<name>:<enable>:<port>`. A test asserting that a package
    /// cannot be confused with a service **failed**: a package literally
    /// named `service:redis:true:-` produced the same key as the service
    /// `redis`, because nothing stopped a package name from spelling a
    /// service record. That is a cache collision between two different
    /// specs — the wrong guest image, silently.
    ///
    /// Prefix conventions do not fix it, because a package name is an
    /// arbitrary string and any prefix is a string a package could have.
    /// So the two sets are hashed as **length-prefixed fields**: the digest
    /// absorbs each set's element count before its contents, and no
    /// arrangement of one set can imitate the other.
    #[must_use]
    pub fn closure_key(&self) -> String {
        let mut packages = self.packages.clone();
        packages.sort();
        packages.dedup();

        // Disabled services are still part of the key: `enable = false` and
        // absent are the same closure today, but saying so explicitly means
        // a toggle cannot silently reuse the wrong image if the guest build
        // ever makes them differ.
        let mut services: Vec<String> = self
            .services
            .iter()
            .map(|service| {
                format!(
                    "{}{UNIT}{}{UNIT}{}",
                    service.name,
                    service.enable,
                    service
                        .port
                        .map_or_else(|| "-".to_owned(), |p| p.to_string())
                )
            })
            .collect();
        services.sort();
        services.dedup();

        let mut canonical = String::new();
        for set in [&packages, &services] {
            // The COUNT, then each element with its own length. A field
            // whose contents cannot be mistaken for a field boundary is
            // what makes the two sets unambiguous regardless of what a
            // package is called.
            canonical.push_str(&format!("{}{RECORD}", set.len()));
            for element in set {
                canonical.push_str(&format!("{}:{element}{RECORD}", element.len()));
            }
        }
        format!("{:016x}", fnv1a(&canonical))
    }
}

/// ASCII unit separator: between a service's own fields.
const UNIT: char = '\u{1f}';
/// ASCII record separator: between elements of a hashed set.
const RECORD: char = '\u{1e}';

/// FNV-1a over the spec's canonical form.
///
/// Not a cryptographic hash and not required to be: this names a cache
/// entry, and the inputs come from a config the user wrote. A collision
/// would mean reusing another project's image, so the width matters —
/// 64 bits over a handful of package names is far past birthday-collision
/// range for one machine's cache.
///
/// Matches `main.rs`'s `path_hash` rather than introducing a second hash
/// with different constants.
fn fnv1a(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// The keys an [`ExecSpec`] is built from.
///
/// Separate from `config.rs`'s policy keys so each list stays readable, and
/// so a key moving between the two is one edit rather than a merge.
pub const EXEC_KEYS: &[&str] = &["environment", "services", "entrypoints"];

/// Parses the exec half of an evaluated config.
///
/// Errors accumulate into `errors` rather than returning early, because
/// `config.rs`'s contract is that a user fixing one typo should not have to
/// re-run to find the second (`00` §3.3's batch principle).
pub(crate) fn exec_spec(
    root: &serde_json::Map<String, serde_json::Value>,
    errors: &mut Vec<ConfigError>,
) -> ExecSpec {
    let environment = root.get("environment").and_then(|v| v.as_object());
    ExecSpec {
        packages: packages(environment, errors),
        variables: variables(environment, errors),
        services: services(root, errors),
        entrypoints: entrypoints(root, errors),
    }
}

/// `environment.packages = with pkgs; [ nodejs_22 postgresql_16 ];`
///
/// # Why a duplicate is an error rather than deduplicated
///
/// Nix would accept `[ nodejs_22 nodejs_22 ]` silently — a list, two
/// elements, one closure. But a user who wrote a package twice either meant
/// two different versions and mistyped one, or is reading a merged config
/// they do not realise is merged. Both are worth saying out loud, and
/// neither is visible once we dedupe for the closure key.
fn packages(
    environment: Option<&serde_json::Map<String, serde_json::Value>>,
    errors: &mut Vec<ConfigError>,
) -> Vec<String> {
    let Some(value) = environment.and_then(|table| table.get("packages")) else {
        return Vec::new();
    };
    let Some(list) = value.as_array() else {
        errors.push(ConfigError::WrongType {
            at: "environment.packages".to_owned(),
            expected: "a list of package names",
            found: json_type(value),
        });
        return Vec::new();
    };
    let mut packages: Vec<String> = Vec::new();
    for (index, element) in list.iter().enumerate() {
        let at = format!("environment.packages[{index}]");
        // A derivation evaluates to an attribute set, so `--json` emits an
        // object here unless the module coerces it to its attribute name.
        // Saying "a package name" rather than "a string" is the difference
        // between a user reading the message and a user guessing.
        let Some(name) = element.as_str() else {
            errors.push(ConfigError::WrongType {
                at,
                expected: "a package name",
                found: json_type(element),
            });
            continue;
        };
        if name.trim().is_empty() {
            errors.push(ConfigError::WrongType {
                at,
                expected: "a package name",
                found: "an empty string",
            });
            continue;
        }
        if packages.iter().any(|existing| existing == name) {
            errors.push(ConfigError::Duplicate {
                at,
                found: name.to_owned(),
            });
            continue;
        }
        packages.push(name.to_owned());
    }
    packages
}

/// `environment.variables = { NODE_ENV = "development"; };`
///
/// Sorted by name so declaration order does not fork the image cache, and
/// so `config inspect` has a stable order to print.
fn variables(
    environment: Option<&serde_json::Map<String, serde_json::Value>>,
    errors: &mut Vec<ConfigError>,
) -> Vec<(String, String)> {
    let Some(value) = environment.and_then(|table| table.get("variables")) else {
        return Vec::new();
    };
    let Some(table) = value.as_object() else {
        errors.push(ConfigError::WrongType {
            at: "environment.variables".to_owned(),
            expected: "a set of name/value pairs",
            found: json_type(value),
        });
        return Vec::new();
    };
    let mut variables = Vec::new();
    for (name, value) in table {
        let at = format!("environment.variables.{name}");
        // NUL cannot pass through `execve`'s environment, and `=` in a name
        // makes the pair unparseable at the other end. Caught here because
        // the guest would otherwise fail with something unrelated-looking.
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            errors.push(ConfigError::WrongType {
                at,
                expected: "a variable name without `=` or NUL",
                found: "an unusable name",
            });
            continue;
        }
        match value.as_str() {
            Some(text) if text.contains('\0') => errors.push(ConfigError::WrongType {
                at,
                expected: "a value without NUL",
                found: "a string containing NUL",
            }),
            Some(text) => variables.push((name.clone(), text.to_owned())),
            // Numbers and booleans are rejected rather than stringified: Nix
            // writes `PORT = 3000` happily, and silently turning that into
            // `"3000"` would mean the config says one thing and the guest
            // sees another. `PORT = "3000"` is one character away.
            None => errors.push(ConfigError::WrongType {
                at,
                expected: "a string (quote it: `\"3000\"`)",
                found: json_type(value),
            }),
        }
    }
    variables.sort();
    variables
}

/// `services.postgres = { enable = true; port = 5432; };`
fn services(
    root: &serde_json::Map<String, serde_json::Value>,
    errors: &mut Vec<ConfigError>,
) -> Vec<Service> {
    let Some(value) = root.get("services") else {
        return Vec::new();
    };
    let Some(table) = value.as_object() else {
        errors.push(ConfigError::WrongType {
            at: "services".to_owned(),
            expected: "a set of services",
            found: json_type(value),
        });
        return Vec::new();
    };
    let mut services = Vec::new();
    for (name, body) in table {
        let at = format!("services.{name}");
        let Some(body) = body.as_object() else {
            errors.push(ConfigError::WrongType {
                at,
                expected: "a set with `enable`",
                found: json_type(body),
            });
            continue;
        };
        for key in body.keys() {
            if !["enable", "port"].contains(&key.as_str()) {
                errors.push(ConfigError::UnknownKey {
                    at: format!("{at}.{key}"),
                });
            }
        }
        // `services.postgres = {}` means enabled: writing the service at all
        // is the request. `enable = false` is how you keep the declaration
        // and turn it off, which is what a commented-out block is for
        // otherwise.
        let enable = match body.get("enable") {
            None => true,
            Some(serde_json::Value::Bool(flag)) => *flag,
            Some(other) => {
                errors.push(ConfigError::WrongType {
                    at: format!("{at}.enable"),
                    expected: "true or false",
                    found: json_type(other),
                });
                continue;
            }
        };
        let port = match body.get("port") {
            None => None,
            Some(value) => match value.as_u64().and_then(|n| u16::try_from(n).ok()) {
                Some(port) => Some(port),
                None => {
                    errors.push(ConfigError::WrongType {
                        at: format!("{at}.port"),
                        expected: "a port number from 0 to 65535",
                        found: json_type(value),
                    });
                    continue;
                }
            },
        };
        services.push(Service {
            name: name.clone(),
            enable,
            port,
        });
    }
    services
}

/// `entrypoints = { dev = "npm run dev"; };`
fn entrypoints(
    root: &serde_json::Map<String, serde_json::Value>,
    errors: &mut Vec<ConfigError>,
) -> Vec<(String, String)> {
    let Some(value) = root.get("entrypoints") else {
        return Vec::new();
    };
    let Some(table) = value.as_object() else {
        errors.push(ConfigError::WrongType {
            at: "entrypoints".to_owned(),
            expected: "a set of name/command pairs",
            found: json_type(value),
        });
        return Vec::new();
    };
    let mut entrypoints = Vec::new();
    for (name, command) in table {
        let at = format!("entrypoints.{name}");
        match command.as_str() {
            Some(text) if text.trim().is_empty() => errors.push(ConfigError::WrongType {
                at,
                expected: "a command",
                found: "an empty string",
            }),
            Some(text) => entrypoints.push((name.clone(), text.to_owned())),
            None => errors.push(ConfigError::WrongType {
                at,
                expected: "a command string",
                found: json_type(command),
            }),
        }
    }
    entrypoints.sort();
    entrypoints
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decide::Capabilities;

    /// Parses the exec half, asserting the config was valid.
    fn spec(json: &str) -> ExecSpec {
        let (_, exec) = crate::config::parse_both(json, Capabilities::all())
            .unwrap_or_else(|errors| panic!("{json} should parse: {errors}"));
        exec
    }

    /// The errors a config produces, as rendered strings.
    fn errors(json: &str) -> Vec<String> {
        crate::config::parse_both(json, Capabilities::all())
            .expect_err("should not parse")
            .all()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    const BASE: &str = r#""tier": "none", "profile": "sealed""#;

    fn with(body: &str) -> String {
        format!("{{ {BASE}, {body} }}")
    }

    // ---- the thing this module exists for -------------------------------

    #[test]
    fn a_project_declares_node_and_postgres_and_gets_both() {
        // THE case. Before this module these two packages were baked into
        // the guest image with their store paths substituted into the init
        // script as `@NODE@` and `@POSTGRES@` — because no struct carried a
        // project's packages. `00` §1 promises an isolated Linux computer
        // that `rachna.nix` configures, so this is the product working.
        let exec = spec(&with(
            r#""environment": { "packages": ["nodejs_22", "postgresql_16"],
                                "variables": { "NODE_ENV": "development" } },
               "services": { "postgres": { "enable": true, "port": 5432 } },
               "entrypoints": { "dev": "npm run dev" }"#,
        ));
        assert_eq!(exec.packages, ["nodejs_22", "postgresql_16"]);
        assert_eq!(
            exec.variables,
            [("NODE_ENV".to_owned(), "development".to_owned())]
        );
        assert_eq!(
            exec.services,
            [Service {
                name: "postgres".to_owned(),
                enable: true,
                port: Some(5432),
            }]
        );
        assert_eq!(
            exec.entrypoints,
            [("dev".to_owned(), "npm run dev".to_owned())]
        );
        assert!(!exec.is_bare(), "a spec with packages needs its own image");
    }

    #[test]
    fn an_empty_config_is_valid_and_asks_for_the_shipped_image() {
        // `19` §4.5's property: an empty `rachna.nix` is valid. You get the
        // base guest, which is a useful environment rather than an error —
        // and `is_bare` is what lets `start` skip a build entirely.
        let exec = spec(&format!("{{ {BASE} }}"));
        assert_eq!(exec, ExecSpec::default());
        assert!(exec.is_bare());
    }

    #[test]
    fn declaring_packages_is_not_an_unknown_option() {
        // The `resources` defect, which `19` §2.1 documented and the parser
        // rejected: a rachna.nix copied out of the document failed with
        // `no such option`. The key list is split in two now, so this
        // asserts the unknown-key check sees BOTH halves.
        for key in EXEC_KEYS {
            let json = match *key {
                "environment" => with(r#""environment": { "packages": ["jq"] }"#),
                "services" => with(r#""services": { "redis": { "enable": true } }"#),
                "entrypoints" => with(r#""entrypoints": { "dev": "true" }"#),
                other => panic!("no fixture for {other}"),
            };
            crate::config::parse_both(&json, Capabilities::all())
                .unwrap_or_else(|e| panic!("{key} must be a known option: {e}"));
        }
    }

    #[test]
    fn a_misspelled_exec_key_still_fails_loudly() {
        // Opening the surface must not open it to typos: `19` §3's property
        // is that every key either does something or fails.
        let found = errors(&with(r#""enviroment": { "packages": ["jq"] }"#));
        assert!(
            found.iter().any(|e| e.contains("enviroment")),
            "a misspelled key must be reported: {found:?}"
        );
    }

    // ---- packages -------------------------------------------------------

    #[test]
    fn packages_keep_the_order_they_were_written_in() {
        // So `config inspect` shows the user their own list back.
        let exec = spec(&with(
            r#""environment": { "packages": ["zlib", "nodejs_22", "atuin"] }"#,
        ));
        assert_eq!(exec.packages, ["zlib", "nodejs_22", "atuin"]);
    }

    #[test]
    fn a_package_declared_twice_is_an_error_not_a_silent_dedupe() {
        let found = errors(&with(
            r#""environment": { "packages": ["nodejs_22", "nodejs_22"] }"#,
        ));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("more than once"), "{found:?}");
        assert!(found[0].contains("nodejs_22"), "{found:?}");
    }

    #[test]
    fn a_package_that_is_not_a_name_says_so_in_those_words() {
        // A derivation evaluates to an attribute set, so `--json` emits an
        // object unless the module coerced it. "expected a package name"
        // is the difference between reading the message and guessing.
        let found = errors(&with(r#""environment": { "packages": [{ "drv": 1 }] }"#));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("a package name"), "{found:?}");
        assert!(found[0].contains("environment.packages[0]"), "{found:?}");
    }

    #[test]
    fn an_empty_package_name_is_rejected() {
        let found = errors(&with(r#""environment": { "packages": ["", "jq"] }"#));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("an empty string"), "{found:?}");
    }

    #[test]
    fn packages_must_be_a_list() {
        let found = errors(&with(r#""environment": { "packages": "nodejs_22" }"#));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("a list of package names"), "{found:?}");
    }

    #[test]
    fn a_bad_element_does_not_discard_the_good_ones() {
        // Errors accumulate (`00` §3.3): both problems are reported, and
        // the valid packages still parse so `config inspect` can show what
        // it understood.
        let found = errors(&with(
            r#""environment": { "packages": ["jq", 7, "ripgrep", 8] }"#,
        ));
        assert_eq!(
            found.len(),
            2,
            "both bad elements, not just the first: {found:?}"
        );
    }

    // ---- variables ------------------------------------------------------

    #[test]
    fn variables_are_sorted_so_writing_order_does_not_fork_the_cache() {
        let one = spec(&with(
            r#""environment": { "variables": { "B": "2", "A": "1" } }"#,
        ));
        let other = spec(&with(
            r#""environment": { "variables": { "A": "1", "B": "2" } }"#,
        ));
        assert_eq!(one.variables, other.variables);
        assert_eq!(
            one.variables,
            [
                ("A".to_owned(), "1".to_owned()),
                ("B".to_owned(), "2".to_owned())
            ]
        );
    }

    #[test]
    fn a_number_is_not_silently_stringified() {
        // Nix writes `PORT = 3000` happily. Turning that into `"3000"` would
        // mean the config says one thing and the guest sees another, and
        // `PORT = "3000"` is one character away — so the error says that.
        let found = errors(&with(r#""environment": { "variables": { "PORT": 3000 } }"#));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("quote it"), "{found:?}");
        assert!(found[0].contains("environment.variables.PORT"), "{found:?}");
    }

    #[test]
    fn a_variable_name_with_an_equals_sign_is_refused() {
        // `=` makes the pair unparseable at the other end, and NUL cannot
        // pass through execve's environment at all. Caught here because the
        // guest would otherwise fail with something unrelated-looking.
        let found = errors(&with(r#""environment": { "variables": { "A=B": "x" } }"#));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("without `=` or NUL"), "{found:?}");
    }

    #[test]
    fn a_nul_in_a_value_is_refused() {
        let found = errors(&with(
            "\"environment\": { \"variables\": { \"A\": \"x\\u0000y\" } }",
        ));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("NUL"), "{found:?}");
    }

    #[test]
    fn variables_must_be_a_set() {
        let found = errors(&with(r#""environment": { "variables": ["A=1"] }"#));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("name/value pairs"), "{found:?}");
    }

    // ---- services -------------------------------------------------------

    #[test]
    fn a_service_written_at_all_is_enabled() {
        // `services.postgres = {}` means enabled: writing it is the request.
        // `enable = false` is how you keep the declaration and turn it off.
        let exec = spec(&with(r#""services": { "postgres": {} }"#));
        assert!(exec.services[0].enable);
        assert_eq!(exec.services[0].port, None);
        assert!(!exec.is_bare(), "a service needs a built image too");
    }

    #[test]
    fn a_disabled_service_is_kept_rather_than_dropped() {
        // Kept so `config inspect` can show it and so the closure key
        // distinguishes it — dropping it would make `enable = false`
        // indistinguishable from deleting the block, which is not what the
        // user wrote.
        let exec = spec(&with(r#""services": { "redis": { "enable": false } }"#));
        assert_eq!(exec.services.len(), 1);
        assert!(!exec.services[0].enable);
    }

    #[test]
    fn an_unknown_service_option_is_an_error() {
        // The narrow shape is the point (`19` §4): `dataDir` is owned by
        // Rachna because a project pointing it at `/workspace` would put the
        // database on the virtiofs share, where a snapshot would not capture
        // it — breaking "come back to a warm Postgres" (`00` §2.3).
        let found = errors(&with(
            r#""services": { "postgres": { "enable": true, "dataDir": "/workspace/db" } }"#,
        ));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("services.postgres.dataDir"), "{found:?}");
        assert!(found[0].contains("no such option"), "{found:?}");
    }

    #[test]
    fn a_service_port_out_of_range_is_refused() {
        let found = errors(&with(r#""services": { "postgres": { "port": 70000 } }"#));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("0 to 65535"), "{found:?}");
    }

    #[test]
    fn enable_must_be_a_boolean() {
        let found = errors(&with(r#""services": { "postgres": { "enable": "yes" } }"#));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("true or false"), "{found:?}");
    }

    #[test]
    fn a_service_must_be_a_set() {
        let found = errors(&with(r#""services": { "postgres": true }"#));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("a set with `enable`"), "{found:?}");
    }

    // ---- entrypoints ----------------------------------------------------

    #[test]
    fn entrypoints_are_named_commands() {
        let exec = spec(&with(
            r#""entrypoints": { "test": "npm test", "dev": "npm run dev" }"#,
        ));
        assert_eq!(
            exec.entrypoints,
            [
                ("dev".to_owned(), "npm run dev".to_owned()),
                ("test".to_owned(), "npm test".to_owned())
            ],
            "sorted, so the order is stable"
        );
    }

    #[test]
    fn an_empty_entrypoint_command_is_refused() {
        let found = errors(&with(r#""entrypoints": { "dev": "   " }"#));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("an empty string"), "{found:?}");
    }

    #[test]
    fn an_entrypoint_must_be_a_string() {
        let found = errors(&with(r#""entrypoints": { "dev": ["npm", "test"] }"#));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("a command string"), "{found:?}");
    }

    #[test]
    fn entrypoints_must_be_a_set() {
        let found = errors(&with(r#""entrypoints": ["npm test"]"#));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("name/command pairs"), "{found:?}");
    }

    // ---- the closure key: what names a built image ----------------------

    #[test]
    fn the_same_packages_in_a_different_order_are_one_image() {
        // The cache-hit property. Two projects declaring the same packages
        // share one built image, which is what keeps a per-project build
        // invisible: `06` §27's closures are FETCHED, never compiled, so a
        // hit costs a lookup.
        let one = spec(&with(
            r#""environment": { "packages": ["nodejs_22", "postgresql_16"] }"#,
        ));
        let other = spec(&with(
            r#""environment": { "packages": ["postgresql_16", "nodejs_22"] }"#,
        ));
        assert_ne!(one.packages, other.packages, "order IS preserved");
        assert_eq!(
            one.closure_key(),
            other.closure_key(),
            "but it must not fork the image cache"
        );
    }

    #[test]
    fn different_packages_are_different_images() {
        let one = spec(&with(r#""environment": { "packages": ["nodejs_22"] }"#));
        let other = spec(&with(r#""environment": { "packages": ["nodejs_20"] }"#));
        assert_ne!(one.closure_key(), other.closure_key());
    }

    #[test]
    fn adding_a_package_changes_the_image() {
        let one = spec(&with(r#""environment": { "packages": ["nodejs_22"] }"#));
        let other = spec(&with(
            r#""environment": { "packages": ["nodejs_22", "postgresql_16"] }"#,
        ));
        assert_ne!(one.closure_key(), other.closure_key());
    }

    #[test]
    fn changing_an_environment_variable_does_not_rebuild() {
        // THE property that makes this key agree with `reload.rs`: variables
        // are read at run time, so `NODE_ENV` is a LIVE change. A key that
        // included them would force a rebuild for an edit the reload
        // classifier calls live, and the two would disagree.
        let one = spec(&with(
            r#""environment": { "packages": ["nodejs_22"],
                                "variables": { "NODE_ENV": "development" } }"#,
        ));
        let other = spec(&with(
            r#""environment": { "packages": ["nodejs_22"],
                                "variables": { "NODE_ENV": "production" } }"#,
        ));
        assert_ne!(one.variables, other.variables);
        assert_eq!(one.closure_key(), other.closure_key());
    }

    #[test]
    fn changing_an_entrypoint_does_not_rebuild() {
        let one = spec(&with(r#""entrypoints": { "dev": "npm run dev" }"#));
        let other = spec(&with(r#""entrypoints": { "dev": "npm start" }"#));
        assert_ne!(one.entrypoints, other.entrypoints);
        assert_eq!(one.closure_key(), other.closure_key());
    }

    #[test]
    fn a_service_is_part_of_the_image_identity() {
        let bare = spec(&format!("{{ {BASE} }}"));
        let with_redis = spec(&with(r#""services": { "redis": { "enable": true } }"#));
        assert_ne!(bare.closure_key(), with_redis.closure_key());
    }

    #[test]
    fn toggling_a_service_changes_the_image_identity() {
        let on = spec(&with(r#""services": { "redis": { "enable": true } }"#));
        let off = spec(&with(r#""services": { "redis": { "enable": false } }"#));
        assert_ne!(
            on.closure_key(),
            off.closure_key(),
            "an enable toggle must not silently reuse the other image"
        );
    }

    #[test]
    fn a_service_port_changes_the_image_identity() {
        let one = spec(&with(r#""services": { "postgres": { "port": 5432 } }"#));
        let other = spec(&with(r#""services": { "postgres": { "port": 5433 } }"#));
        assert_ne!(one.closure_key(), other.closure_key());
    }

    #[test]
    fn a_package_cannot_be_confused_with_a_service_of_the_same_name() {
        // The key joins its parts, so a separator that could appear in a
        // package name would let two different specs collide. `service:`
        // prefixing plus a unit separator is what prevents it; this asserts
        // the property rather than the spelling.
        let as_package = spec(&with(
            r#""environment": { "packages": ["service:redis:true:-"] }"#,
        ));
        let as_service = spec(&with(r#""services": { "redis": { "enable": true } }"#));
        assert_ne!(as_package.closure_key(), as_service.closure_key());
    }

    #[test]
    fn the_closure_key_is_stable_across_runs() {
        // A key that changed between invocations would miss the cache every
        // time, which is the whole cost this is meant to avoid. Pinned to a
        // literal so a change to the hash function is a deliberate edit —
        // it invalidates every cached image on every machine.
        let exec = spec(&with(
            r#""environment": { "packages": ["nodejs_22", "postgresql_16"] }"#,
        ));
        assert_eq!(exec.closure_key(), exec.closure_key());
        assert_eq!(exec.closure_key().len(), 16, "a fixed-width hex name");
        assert_eq!(exec.closure_key(), "116ba4d9fa0cb05e");
    }

    #[test]
    fn an_empty_spec_still_has_a_key() {
        // `is_bare` decides whether to build; the key must not panic or
        // collide with a real spec if something asks anyway.
        let bare = ExecSpec::default();
        assert_eq!(bare.closure_key().len(), 16);
        let one = spec(&with(r#""environment": { "packages": ["jq"] }"#));
        assert_ne!(bare.closure_key(), one.closure_key());
    }

    // ---- both halves come back together ---------------------------------

    #[test]
    fn a_config_yields_both_artifacts_or_neither() {
        // `01` §2.3: exactly two artifacts, and `config.rs`'s contract is
        // refuse-never-partially-apply. So a config broken in its POLICY
        // half must not hand back a usable exec half either — otherwise a
        // rebuild could start for a config that was rejected.
        let json = with(r#""environment": { "packages": ["jq"] }, "tier": "nope""#);
        crate::config::parse_both(&json, Capabilities::all())
            .expect_err("a bad tier must reject the whole config");
    }

    #[test]
    fn problems_in_both_halves_are_reported_together() {
        // One run, every problem — the batch principle. A user fixing the
        // tier should not then discover the package error.
        let found = errors(
            r#"{ "tier": "nope", "profile": "sealed",
                  "environment": { "packages": [7] } }"#,
        );
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.iter().any(|e| e.contains("nope")), "{found:?}");
        assert!(
            found.iter().any(|e| e.contains("a package name")),
            "{found:?}"
        );
    }
}
