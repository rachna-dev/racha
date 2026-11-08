#!/usr/bin/env bash
# Sign a built binary with the Virtualization.framework entitlement.
#
# NOT a packaging nicety. 02-SPIKE-MACOS-VZ.md §4 measured that without
# `com.apple.security.virtualization`, VZVirtualMachine.init throws
# NSInvalidArgumentException — a crash rather than an error return. So an
# unsigned `rachna` on macOS does not fail gracefully, it dies, and the build
# must sign rather than leave it to a README.
#
# A no-op on anything but macOS, so the gate can call it unconditionally.
set -euo pipefail

binary="${1:-target/debug/rachna}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "  not macOS — nothing to sign"
  exit 0
fi

if [[ ! -f "$binary" ]]; then
  echo "  $binary does not exist yet — nothing to sign" >&2
  exit 0
fi

entitlements="$(dirname "$0")/../build/vz.entitlements"
codesign --force --sign - --entitlements "$entitlements" "$binary"

# Verify rather than assume: a signature that did not take the entitlement
# produces exactly the crash this script exists to prevent, and `codesign`
# exits 0 either way.
if ! codesign -d --entitlements - "$binary" 2>&1 |
     grep -q "com.apple.security.virtualization"; then
  echo "  SIGNED BUT THE ENTITLEMENT IS ABSENT — this binary would crash" >&2
  exit 1
fi
echo "  signed with com.apple.security.virtualization"
