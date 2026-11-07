#!/usr/bin/env bash
# The gate, as one script both CI providers call.
#
# AGENTS.md defines this as: fmt + clippy -D warnings + the full test run,
# before starting a task and before calling it done. Keeping it in a script
# rather than duplicating it in each workflow means GitHub and Forgejo cannot
# drift apart on what "passing" means.
#
# Usage: ci/gate.sh [gate|mutants|deps|all]
set -euo pipefail

step() { printf '\n\033[1m▸ %s\033[0m\n' "$1"; }

gate() {
  step "fmt"
  cargo fmt --all --check
  step "clippy"
  cargo clippy --workspace --all-targets -- -D warnings
  step "tests"
  cargo nextest run --workspace
}

# Mutation testing is THE bar for this project, not coverage: for a security
# boundary, "does the suite fail when behaviour changes" is the only honest
# measure. cargo-mutants exits non-zero when a mutant survives, which is
# exactly the gate we want — a surviving mutant in policy or path code is a bug
# in the test suite, not an acceptable gap.
mutants() {
  step "mutants"
  # cargo-mutants' own summary reads as a failure count at a glance —
  # "1 missed, 119 caught" invites "why are 119 failing?". They are not:
  # CAUGHT means the suite detected deliberately broken code, which is the
  # goal, and MISSED is the number to worry about. Spelled out here because
  # this line is read in CI logs by whoever is least in context.
  echo "  caught   = the suite detected broken code  -> want this HIGH"
  echo "  missed   = broken code went unnoticed      -> want this ZERO"
  echo "  unviable = did not compile, nothing tested -> neutral"
  echo
  cargo mutants --colors=never --in-place
}

deps() {
  step "unused dependencies"
  cargo machete
  step "advisories and licences"
  cargo deny check
}

case "${1:-all}" in
  gate) gate ;;
  mutants) mutants ;;
  deps) deps ;;
  all)
    gate
    mutants
    deps
    ;;
  *)
    echo "usage: $0 [gate|mutants|deps|all]" >&2
    exit 2
    ;;
esac

printf '\n\033[1;32m✓ %s passed\033[0m\n' "${1:-all}"
