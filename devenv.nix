{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

{
  # Rachna — a declarative, isolated development environment manager.
  #
  # The gate below is the contract: fmt, clippy, tests, and mutation testing
  # as the real bar for policy and path code.

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
      "llvm-tools-preview" # cargo-llvm-cov needs this
    ];
  };

  # https://devenv.sh/packages/
  packages =
    with pkgs;
    [
      git

      # Nix evaluation is a first-class dependency: rachna.nix is evaluated by
      # shelling out to `nix eval --json` rather than linking libnixexpr.
      nix

      # ── the testing bar (AGENTS.md) ──────────────────────────────────────
      cargo-nextest # faster runs, better output than `cargo test`
      cargo-mutants # THE bar for a security boundary: does the suite FAIL
      # when behaviour changes? A surviving mutant in policy
      # or path code is a bug in the test suite.
      cargo-deny # licence + advisory audit
      cargo-machete # unused dependencies

      # ci/gate.sh runs on bare Ubuntu and Arch containers without the devenv
      # shell, so it must stay portable.
      shellcheck
    ]
    ++ lib.optionals pkgs.stdenv.isLinux [
      # The chosen Linux backend, with virtiofsd for the
      # workspace mount. On macOS the backend is Virtualization.framework,
      # which needs no package — but a macOS build MUST be ad-hoc codesigned
      # with com.apple.security.virtualization or it CRASHES rather than
      # failing gracefully.
      cloud-hypervisor
      virtiofsd
    ];

  env = {
    CARGO_TERM_COLOR = "always";
    RUST_LOG = "rachna=debug,warn";
    RUST_BACKTRACE = "1";
  };

  # https://devenv.sh/scripts/
  scripts = {
    # THE GATE from AGENTS.md: before starting a task and before calling it
    # done. A gate already failing when you start gets fixed first.
    #
    # Defined in ci/gate.sh so the shell, GitHub and Forgejo all run exactly
    # the same checks — they cannot drift on what "passing" means.
    check.exec = "exec ./ci/gate.sh gate";

    # BUILD AND SIGN, together, because the two cannot be separated on
    # macOS and separating them is a trap I fell into repeatedly.
    #
    # `02` §4 measured that without `com.apple.security.virtualization`
    # `VZVirtualMachine.init` THROWS — so an unsigned `rachna` does not
    # degrade, it dies. And every `cargo build`, `cargo clippy --fix` and
    # `cargo mutants` run relinks the binary and discards the signature,
    # leaving a `rachna start` that fails with
    #
    #   this host cannot run that configuration: … doesn't have the
    #   "com.apple.security.virtualization" entitlement
    #
    # which reads as a host or entitlement problem and is neither.
    #
    # Signing is ad-hoc (`codesign --sign -`): no certificate, no Apple
    # account, nothing to configure. There was never a reason for it to be
    # a separate step the caller has to remember.
    build.exec = ''
      set -euo pipefail
      cargo build "$@"
      ./ci/sign-macos.sh target/debug/rachna
    '';

    fix.exec = ''
      set -euo pipefail
      cargo fmt --all
      cargo clippy --workspace --all-targets --fix --allow-dirty -- -D warnings
      # Relinks, so it strips the signature. See `build` above.
      ./ci/sign-macos.sh target/debug/rachna
    '';

    # Mutation testing is the honest measure for a security boundary: 100%
    # line coverage with assertion-free tests proves nothing. A surviving
    # mutant means the suite does not actually check that behaviour.
    # Not `exec`: mutation testing rebuilds the binary many times and
    # leaves it unsigned, so the shell re-signs afterwards. A `mutants` run
    # that leaves you unable to start a VM is a trap, and it caught me
    # twice in one session.
    mutants.exec = ''
      set -euo pipefail
      ./ci/gate.sh mutants
      ./ci/sign-macos.sh target/debug/rachna
    '';

    # Coverage is deliberately NOT in this shell.
    #
    # cargo-llvm-cov 0.9.0 fails its own test suite in this nixpkgs revision on
    # both aarch64-darwin and x86_64-linux, so it cannot be built here. That is
    # an acceptable loss rather than a workaround to carry: coverage is a floor
    # and `mutants` is the actual bar (AGENTS.md). Revisit when nixpkgs fixes
    # the package; until then CI reports coverage via rustup instead.
    cov.exec = ''
      echo "coverage is not available in this shell — cargo-llvm-cov is broken" >&2
      echo "in this nixpkgs revision. Mutation testing (\`mutants\`) is the bar;" >&2
      echo "see AGENTS.md. CI reports coverage separately." >&2
      exit 1
    '';

    deps.exec = "exec ./ci/gate.sh deps";
  };

  # https://devenv.sh/basics/
  enterShell = ''
    echo "rachna"
    echo "  check     the gate: fmt + clippy + tests  (run before and after every task)"
    echo "  mutants   mutation testing — the real bar for policy and path code"
    echo "  cov       coverage summary (a floor, not the goal)"
    echo "  deps      unused deps + advisories"
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
    clippy.enable = true;
    nixfmt.enable = true;
    shellcheck.enable = true;

    # Refuse to commit a cargo-mutants artifact.
    #
    # `cargo mutants --in-place` edits the real source tree, so an interrupted
    # run leaves deliberately-broken code behind. This happened once in
    # development: a mutated `is_met_by` (the audit evidence threshold) and a
    # gutted `network_grants` were staged by a commit that ran while mutation
    # testing was still going. `ci/gate.sh` no longer passes --in-place, and
    # this is the backstop for a run started by hand.
    #
    # Committing a mutant is not a cosmetic mistake: every mutant is a
    # security-relevant behaviour change that the test suite is known to
    # detect, so it would land as code whose tests are guaranteed to fail.
    no-mutation-artifacts = {
      enable = true;
      name = "no cargo-mutants artifacts";
      entry = "${pkgs.writeShellScript "no-mutation-artifacts" ''
        if grep -rln 'changed by cargo-mutants' "$@" 2>/dev/null; then
          echo "refusing to commit: the files above hold cargo-mutants edits." >&2
          echo "restore them with: git checkout HEAD -- <file>" >&2
          exit 1
        fi
      ''}";
      files = "\\.rs$";
      pass_filenames = true;
    };
  };

  # See full reference at https://devenv.sh/reference/options/
}
