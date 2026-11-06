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
  # The feasibility spike is complete (design-docs/02 through 05); the
  # implementation has not started. This shell carries the toolchain the spike
  # established we need, so it is ready when code lands.

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
  packages =
    with pkgs;
    [
      git

      # Nix evaluation is a first-class dependency: rachna.nix is evaluated by
      # shelling out to `nix eval --json` rather than linking libnixexpr.
      nix

      # Cloud Hypervisor is the chosen Linux backend (design-docs/03 §1), with
      # virtiofsd for the workspace mount. Linux only — on macOS the backend is
      # Virtualization.framework, which needs no package.
      #
      # NOTE: a macOS build must be ad-hoc codesigned with the
      # com.apple.security.virtualization entitlement or it CRASHES rather than
      # failing gracefully (design-docs/02 §5).
    ]
    ++ lib.optionals pkgs.stdenv.isLinux [
      cloud-hypervisor
      virtiofsd
    ];

  env = {
    CARGO_TERM_COLOR = "always";
    RUST_LOG = "rachna=debug,warn";
    RUST_BACKTRACE = "1";
  };

  # https://devenv.sh/basics/
  enterShell = ''
    echo "rachna · spike complete, implementation not started"
    echo "  design-docs/00-PRODUCT.md       what we are building"
    echo "  design-docs/02..05              measured findings"
  '';

  # https://devenv.sh/git-hooks/
  git-hooks.hooks = {
    nixfmt.enable = true;
  };

  # See full reference at https://devenv.sh/reference/options/
}
