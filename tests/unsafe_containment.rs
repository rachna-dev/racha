//! `unsafe` lives in exactly one module, and this is what keeps that true.
//!
//! `Cargo.toml` denied `unsafe_code` outright, and `17`'s VZ-binding
//! decision rested on that being free: the binding was believed to be safe
//! Rust. It is not — all 502 of its functions are `unsafe fn`, so calling
//! any of them means allowing `unsafe` somewhere.
//!
//! The project owner's decision was to **contain** it rather than ban it or
//! move it into a Swift shim. A ban would mean no macOS backend at all; a
//! shim would put the same `unsafe` behind a C ABI where neither clippy nor
//! `cargo-mutants` can see it, which is less auditable rather than more.
//!
//! So the ban is replaced by an auditable property: **exactly one
//! `allow(unsafe_code)` in the tree, in a named file.** `unsafe_code` is a
//! `deny` rather than a `forbid` precisely so one module can override it —
//! which means nothing but this test stops a second module from doing the
//! same quietly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

/// The ONE file permitted to allow `unsafe`.
const CONTAINMENT: &str = "src/backend/macos_vm.rs";

/// Whether this source lifts the crate-level `deny(unsafe_code)`.
///
/// Collapses whitespace first, so an attribute `rustfmt` has wrapped over
/// several lines reads the same as a one-line one.
fn lifts_the_deny(text: &str) -> bool {
    let collapsed: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    // Both spellings: `allow` and `expect` each lift a `deny`.
    [
        "allow( unsafe_code",
        "allow(unsafe_code",
        "expect( unsafe_code",
        "expect(unsafe_code",
    ]
    .iter()
    .any(|needle| collapsed.contains(needle))
}

fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|e| e == "rs") {
            found.push(path);
        }
    }
}

#[test]
fn only_one_module_allows_unsafe() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    assert!(!files.is_empty(), "found no Rust sources to audit");

    let mut allowed = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a readable source file");
        // Whitespace-insensitive, because `rustfmt` splits a long attribute
        // across lines: the real module writes
        //
        //     #![allow(
        //         unsafe_code,
        //         reason = "…"
        //     )]
        //
        // which a single-line `contains("allow(unsafe_code)")` misses. The
        // first version of this test did exactly that and reported ZERO
        // allowing modules — a guard that passes by finding nothing is
        // worse than no guard, and only the vacuity check below caught it.
        if lifts_the_deny(&text) {
            allowed.push(
                file.strip_prefix(root)
                    .unwrap_or(file)
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    allowed.sort();

    assert_eq!(
        allowed,
        vec![CONTAINMENT.to_owned()],
        "`unsafe` must be allowed in exactly one module. If a new one needs \
         it, that is a decision to take deliberately — not by editing this \
         list to match the code"
    );
}

#[test]
fn the_containment_module_is_the_only_place_unsafe_appears() {
    // The stronger half. A module could write `unsafe` without an `allow`
    // and simply fail to compile — but a `deny` can also be lifted from the
    // command line or a profile, so the keyword's location is worth
    // asserting on its own rather than trusting the lint to hold.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);

    for file in &files {
        let relative = file
            .strip_prefix(root)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        if relative == CONTAINMENT {
            continue;
        }
        let text = std::fs::read_to_string(file).expect("a readable source file");
        for (number, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            assert!(
                !code.contains("unsafe "),
                "{relative}:{} uses `unsafe` outside {CONTAINMENT}: {}",
                number + 1,
                line.trim()
            );
        }
    }
}

#[test]
fn the_containment_module_actually_contains_the_unsafe() {
    // First assert the thing under attack EXISTS. Without this, both tests
    // above pass trivially the moment the VZ backend is deleted — a green
    // suite proving only that nothing uses unsafe because nothing is there.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let module = root.join(CONTAINMENT);
    let text = std::fs::read_to_string(&module)
        .unwrap_or_else(|error| panic!("{CONTAINMENT} must exist: {error}"));
    assert!(
        lifts_the_deny(&text),
        "{CONTAINMENT} does not allow unsafe, so the containment tests are vacuous"
    );
    assert!(
        text.contains("unsafe {") || text.contains("unsafe fn"),
        "{CONTAINMENT} allows unsafe but uses none, so nothing is contained"
    );
}
