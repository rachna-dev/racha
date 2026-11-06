{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

{
  # Rachna — a declarative, isolated development environment manager.
  # See design-docs/00-PRODUCT.md for the product model,
  #     design-docs/01-ARCHITECTURE.md for the crate layout.

  # https://devenv.sh/languages/
  languages.rust = {
    enable = true;
    channel = "stable";
    components = [
      "rustc"
      "cargo"
      "clippy"
      "rustfmt"
      "rust-analyzer"
      "rust-src" # rust-analyzer needs this to resolve std
    ];
  };

  # https://devenv.sh/packages/
  packages = with pkgs; [
    git

    # Nix evaluation is a first-class dependency: rachna-config shells out to
    # `nix eval --json` rather than linking libnixexpr. See 01-ARCHITECTURE.md §11.1.
    nix

    # rusqlite is built with the `bundled` feature, so no host libsqlite is
    # required at link time — but the CLI is handy for inspecting .rachna/rachna.db.
    sqlite

    # Tooling the build order (01-ARCHITECTURE.md §8) leans on.
    cargo-nextest # faster test runs, better output than `cargo test`
    cargo-deny # license + advisory audit
    cargo-machete # find unused dependencies in a growing workspace
    nixfmt-rfc-style # format our own .nix files
  ];

  env = {
    # Keep build artifacts out of the source tree's way and shared across crates.
    CARGO_TERM_COLOR = "always";

    # `tracing` defaults — overridable per-shell.
    RUST_LOG = "rachna=debug,warn";

    # Backtraces on by default while the workspace is young.
    RUST_BACKTRACE = "1";
  };

  # https://devenv.sh/scripts/
  scripts = {
    # One command to check everything CI would check.
    check.exec = ''
      set -euo pipefail
      echo "▸ fmt"      && cargo fmt --all --check
      echo "▸ clippy"   && cargo clippy --workspace --all-targets -- -D warnings
      echo "▸ test"     && cargo nextest run --workspace
      echo "▸ nix fmt"  && nixfmt --check devenv.nix
      echo "✓ all checks passed"
    '';

    fix.exec = ''
      set -euo pipefail
      cargo fmt --all
      nixfmt devenv.nix
      cargo clippy --workspace --all-targets --fix --allow-dirty -- -D warnings
    '';

    # Unused-dependency sweep; the workspace will accrete these fast.
    deps.exec = ''
      cargo machete && cargo deny check
    '';
  };

  # https://devenv.sh/basics/
  enterShell = ''
    echo "rachna · $(cargo --version)"
    echo "  check   run fmt + clippy + tests"
    echo "  fix     format and auto-fix lints"
    echo "  deps    audit dependencies"
  '';

  # https://devenv.sh/tests/
  enterTest = ''
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo nextest run --workspace
  '';

  # https://devenv.sh/git-hooks/
  git-hooks.hooks = {
    rustfmt.enable = true;
    clippy = {
      enable = true;
      settings.allFeatures = true;
    };
    nixfmt.enable = true;
  };

  # See full reference at https://devenv.sh/reference/options/
}
