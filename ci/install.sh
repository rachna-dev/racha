#!/usr/bin/env bash
# The one-line installer:
#
#   curl -fsSL https://raw.githubusercontent.com/rachna-dev/racha/main/ci/install.sh | sh
#
# Fetches the `rachna` binary and the guest image for this machine, verifies
# both against published checksums, and puts the binary on PATH.
#
# WHY CURL AND NOT A BROWSER DOWNLOAD. Measured: `curl` sets only
# `com.apple.provenance`, never `com.apple.quarantine` — so a curl-installed
# `rachna` runs with no further steps, while the same file downloaded in a
# browser is killed with "Apple could not verify 'rachna' is free of malware"
# and a button offering to Trash it.
#
# That dialog is not about packaging. Most CLI tools never see it (`lsd` is
# ad-hoc signed like `rachna` and downloads fine); `rachna` links
# Virtualization.framework and claims `com.apple.security.virtualization`,
# which is what Gatekeeper's malware check exists to scrutinise when no
# Developer ID vouches for it.
#
# The quarantine attribute is cleared anyway, below. It costs one command and
# covers the case where someone pipes this script from a tool that does set
# it — a defensive line is cheaper than a support thread.
set -eu

REPO="${RACHNA_REPO:-rachna-dev/racha}"
VERSION="${RACHNA_VERSION:-latest}"
PREFIX="${RACHNA_PREFIX:-$HOME/.local/bin}"
GUEST_VERSION="26.11-3181085"

# WHICH GUEST: the stand-in by default, the real NixOS one on request.
#
# Two images are published per architecture and they are genuinely
# different things:
#
#   rachna-guest-…       a busybox root assembled by substitution. ~143 MB.
#                        What `rachna start` has been booting and the only
#                        one proven on real hardware. It runs a fixed demo
#                        (a Node app on Postgres) rather than a declared
#                        service set.
#
#   rachna-real-guest-…  `guest/guest.nix` built for real: a NixOS system
#                        with systemd, `services.postgresql` as a DECLARED
#                        service, and `devenv` in the image. ~637 MB. This
#                        is the guest Rachna is designed around — and it has
#                        never been booted, only built and verified
#                        structurally.
#
# So the default stays the proven one. `RACHNA_GUEST=real` opts in, because
# the alternative — shipping an unbooted image as the default — is how a
# user's first `rachna start` becomes the thing that discovers it does not
# work.
GUEST_KIND="${RACHNA_GUEST:-standin}"
case "$GUEST_KIND" in
  standin) GUEST_ARCHIVE_PREFIX="rachna-guest" ;;
  real)    GUEST_ARCHIVE_PREFIX="rachna-real-guest" ;;
  *) printf '\nrachna: RACHNA_GUEST must be standin or real, got %s\n' \
       "$GUEST_KIND" >&2; exit 1 ;;
esac

say() { printf '\n▸ %s\n' "$*"; }
die() { printf '\nrachna: %s\n' "$*" >&2; exit 1; }

# ---- what machine is this -------------------------------------------------

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux)  os=linux ;;
  *) die "unsupported system: $(uname -s). rachna needs macOS or Linux." ;;
esac

case "$(uname -m)" in
  arm64|aarch64) arch=aarch64 ;;
  x86_64|amd64)  arch=x86_64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

if [ "$os" = darwin ] && [ "$arch" != aarch64 ]; then
  # Stated rather than attempted: Virtualization.framework needs Apple
  # Silicon, so an Intel Mac would install a binary that cannot start a VM.
  die "rachna needs Apple Silicon on macOS — Virtualization.framework is not
     available on Intel Macs."
fi

case "$os-$arch" in
  darwin-aarch64) target=aarch64-apple-darwin ;;
  linux-x86_64)   target=x86_64-unknown-linux-gnu ;;
  linux-aarch64)  target=aarch64-unknown-linux-gnu ;;
esac

for tool in curl tar shasum; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required and not on PATH"
done

say "installing rachna for $target"

# ---- fetch ---------------------------------------------------------------

if [ "$VERSION" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

work=$(mktemp -d)
# `$?` is preserved so a failure here is not masked by the cleanup's own
# exit status — a trap ending in `rm` hands the script `rm`'s status.
cleanup() { status=$?; rm -rf "$work"; exit $status; }
trap cleanup EXIT

say "downloading the binary"
curl -fsSL -o "$work/rachna.tar.gz" "$base/rachna-$target.tar.gz" \
  || die "could not download rachna-$target.tar.gz from $base.
     There may be no release published yet. Build from source instead:
     https://github.com/$REPO#building-from-source"

# VERIFIED, not trusted. The checksum is published beside the archive, so
# this catches a truncated download and a mirror that serves something else.
# It is not a defence against a compromised release — that needs signing,
# which is tracked separately.
# The archive keeps its PUBLISHED name here, because the `.sha256` file
# names the file it describes — downloading to `rachna.tar.gz` while the
# checksum says `rachna-aarch64-apple-darwin.tar.gz` made `shasum -c` look
# for a file that did not exist, and the installer reported a checksum
# MISMATCH on a perfectly good download. Found by running it.
archive="rachna-$target.tar.gz"
mv "$work/rachna.tar.gz" "$work/$archive"

if curl -fsSL -o "$work/$archive.sha256" \
     "$base/$archive.sha256" 2>/dev/null; then
  ( cd "$work" && shasum -a 256 -c "$archive.sha256" >/dev/null ) \
    || die "the downloaded archive does not match its published checksum.
     Delete it and try again; if it persists, open an issue."
  say "checksum verified"
else
  printf '  no checksum published for this release — skipping verification\n'
fi

tar -C "$work" -xzf "$work/$archive"
test -f "$work/rachna" || die "the archive did not contain a rachna binary"

# ---- install -------------------------------------------------------------

mkdir -p "$PREFIX"
install -m 0755 "$work/rachna" "$PREFIX/rachna"

if [ "$os" = darwin ]; then
  # Defensive: curl does not set this, but a browser or some GUI tools do,
  # and the failure it produces is a malware dialog rather than an error.
  xattr -d com.apple.quarantine "$PREFIX/rachna" 2>/dev/null || true

  # The entitlement is NOT optional: `VZVirtualMachine.init` throws without
  # it, so a binary missing it does not degrade — it dies on the first
  # `rachna start`. Checked here because a release that lost it would
  # otherwise be discovered by the user.
  if ! codesign -d --entitlements - "$PREFIX/rachna" 2>&1 \
       | grep -q 'com.apple.security.virtualization'; then
    die "this build is missing the virtualization entitlement, so it cannot
     create a VM. That is a packaging bug — please open an issue."
  fi
fi

"$PREFIX/rachna" --version >/dev/null 2>&1 \
  || die "the installed binary does not run. Please open an issue."

say "installed $("$PREFIX/rachna" --version) to $PREFIX/rachna"

# ---- the guest image -----------------------------------------------------

guest_dir="$HOME/.rachna/guests/$GUEST_VERSION-$arch"
if [ -f "$guest_dir/root.img" ]; then
  say "guest image already present"
else
  if [ "$GUEST_KIND" = real ]; then
    say "downloading the REAL NixOS guest image (~637 MB)"
    printf '  this image is built and verified but has not been booted;\n'
    # shellcheck disable=SC2016  # literal backticks, naming a variable
    printf '  `RACHNA_GUEST=standin` installs the proven one instead.\n'
  else
    say "downloading the guest image (~143 MB)"
  fi
  # The VERSIONED name, matching what `guest.yml` publishes. An unversioned
  # one would hand this binary whatever image the latest release carries —
  # and the binary only looks in `guests/$GUEST_VERSION-$arch`, so a newer
  # image would be downloaded, unpacked, and never found.
  if curl -fsSL -o "$work/guest.tar.gz" \
       "$base/$GUEST_ARCHIVE_PREFIX-$GUEST_VERSION-$arch.tar.gz" 2>/dev/null; then
    mkdir -p "$guest_dir"
    tar -C "$guest_dir" -xzf "$work/guest.tar.gz"
    # The image ships its own SHA256SUMS, generated at build time.
    if [ -f "$guest_dir/SHA256SUMS" ]; then
      ( cd "$guest_dir" && shasum -a 256 -c SHA256SUMS >/dev/null ) \
        || die "the guest image does not match its checksums. Remove
     $guest_dir and try again."
      say "guest image verified"
    fi
  else
    printf '  no %s guest image published for %s yet.\n' \
      "$GUEST_KIND" "$arch"
    if [ "$GUEST_KIND" = real ]; then
      printf '  build one:  nix build ./guest#packages.%s-linux.vz-image\n' \
        "$arch"
    else
      printf '  build one locally:  bash ci/build-guest.sh\n'
    fi
  fi
fi

# ---- tell them what to do next -------------------------------------------

case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *)
    printf '\n  %s is not on your PATH. Add it:\n\n' "$PREFIX"
    # shellcheck disable=SC2016  # $PATH stays literal: the user pastes this
    printf '    export PATH="%s:$PATH"\n' "$PREFIX"
    ;;
esac

cat <<'NEXT'

  Start a project:

    cd ~/my-project
    rachna init        # writes rachna.nix, which grants nothing by default
    rachna start       # shows what it may do, then waits for you to accept

NEXT
