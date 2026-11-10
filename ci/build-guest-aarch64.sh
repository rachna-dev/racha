#!/usr/bin/env bash
# Builds a guest root image with Node and Postgres, for aarch64 VZ hosts.
#
# WHY THIS EXISTS, and what it is not: `guest/flake.nix` is the real guest,
# and it needs 240 derivations BUILT for aarch64-linux (02 §6.9) — which an
# aarch64-darwin host with no Linux builder cannot do. This assembles an
# equivalent root by SUBSTITUTION only: every package is fetched prebuilt
# and signed from cache.nixos.org, so 21 §2.1a's integrity chain holds.
#
# Use it to run a real guest on a Mac today. Prefer the flake wherever a
# Linux builder exists.
set -euo pipefail

# Must match `layout::GUEST_VERSION`: `08` §4.1.1 names the guest by
# version AND arch so an upgrade cannot overwrite an image that existing
# snapshots still reference.
GUEST_VERSION="${GUEST_VERSION:-26.11-3181085}"
OUT="${1:-$HOME/.rachna/guests/$GUEST_VERSION-aarch64}"
PINNED="nixpkgs/3181085bfd08663b6b9e60bc7a8395c2aaa741bd"
# Node comes from a different pin DELIBERATELY: at the pinned rev, nodejs_22
# needs building and nodejs_20 fails an end-of-life assertion (02 §6.9).
NODE_PIN="nixpkgs/nixos-25.05"

say() { printf '\n▸ %s\n' "$*"; }

say "fetching the guest kernel (aarch64-linux)"
KERNEL_DIR=$(nix build --no-link --print-out-paths \
  "$PINNED#legacyPackages.aarch64-linux.linuxPackages.kernel")
KERNEL="$KERNEL_DIR/Image"
# VZLinuxBootLoader takes the uncompressed Image; the vmlinux extraction in
# guest/flake.nix is a Cloud Hypervisor/x86 concern (02 §6.5).
test -f "$KERNEL" || { echo "no Image in $KERNEL_DIR" >&2; exit 1; }

# The kernel's MODULES, as a separate output. `CONFIG_VIRTIO_FS=m` on this
# nixpkgs — virtiofs is a module, not built in — and the kernel's `out`
# ships only Image/System.map/dtbs. Without these the guest cannot mount
# the workspace at all: measured as `no virtiofs share tagged 'workspace'`
# with only two virtio devices in the guest, which looked host-side and
# was not.
say "fetching the kernel modules (virtiofs is CONFIG_VIRTIO_FS=m)"
MODULES=$(nix build --no-link --print-out-paths \
  "$PINNED#legacyPackages.aarch64-linux.linuxPackages.kernel.modules")
test -d "$MODULES/lib/modules" || { echo "no modules in $MODULES" >&2; exit 1; }

say "fetching busybox, node, postgres, e2fsprogs"
BUSYBOX=$(nix build --no-link --print-out-paths \
  "$PINNED#legacyPackages.aarch64-linux.pkgsStatic.busybox")
POSTGRES=$(nix build --no-link --print-out-paths \
  "$PINNED#legacyPackages.aarch64-linux.postgresql_16" | grep -v -- '-man$' | head -1)
NODE=$(nix build --no-link --print-out-paths \
  "$NODE_PIN#legacyPackages.aarch64-linux.nodejs_22" | head -1)
E2FS=$(nix build --no-link --print-out-paths "nixpkgs#e2fsprogs" | grep -- '-bin$' | head -1)

# Everything must be a Linux binary, or it fetched the host's build by
# mistake — which would fail at boot with no useful message.
for binary in "$NODE/bin/node" "$POSTGRES/bin/postgres"; do
  file "$binary" | grep -q 'ELF.*aarch64' || {
    echo "$binary is not an aarch64 Linux ELF — wrong system fetched" >&2
    exit 1
  }
done

WORK=$(mktemp -d)
# `chmod -R u+w` before the delete: `cp -a` preserves the nix store's
# read-only permissions, and `rm -rf` then fails on every single path.
# Found by running this script — the image built and the cleanup failed,
# which would have left ~400 MiB in TMPDIR on every invocation.
# The trap PRESERVES the exit status explicitly.
#
# **Not because the implicit form was broken** — measured both ways in
# isolation and a trap ending in `rm -rf` also exits 1, because bash
# restores `$?` around an EXIT trap. The reported `exit 0` came from the
# CALLER: `build-guest.sh | tail -6` takes the pipeline's status, which is
# `tail`'s. My own command masked it, and I blamed the script.
#
# Kept anyway, for one reason that is not cosmetic: `rm -rf` on a tree
# containing read-only nix store paths CAN fail, and then the implicit
# status really is `rm`'s. Making it explicit costs four lines and removes
# the question.
cleanup() {
  status=$?
  # `chmod -R` over the copied nix store paths took MINUTES on a tree of
  # 55 closures and made the build look hung long after the image was
  # written — I killed one mid-`install`, which left a root.img whose ext4
  # superblock was valid and whose journal was not (`Could not load
  # journal inode`). That is `24` §6's trap exactly: a partial artefact
  # that inspects as complete.
  #
  # `find -exec chmod` on DIRECTORIES only is what `rm -rf` actually needs
  # — a read-only file in a writable directory deletes fine.
  find "$WORK" -type d -exec chmod u+w {} + 2>/dev/null || true
  rm -rf "$WORK" 2>/dev/null || true
  exit $status
}
trap cleanup EXIT
ROOT="$WORK/root"
#  holds the shipped demo app;  is a MOUNT
# POINT for the user's project, so it stays empty in the image.
mkdir -p "$ROOT"/{bin,sbin,dev,proc,sys,tmp,etc,var,run,workspace,data,opt/rachna,nix/store}

# ONLY THE TWO MODULES THE GUEST LOADS. `cp -a` of the whole tree copied
# **139 MB** so that `insmod` could use two files — and then the image had
# to be large enough to hold all of it. Measured: that step alone was the
# longest in the build and it ran out of disk twice on a machine with a
# few hundred MB spare.
#
# The guest loads `fuse` and `virtiofs` by path and has no `modprobe`, so
# nothing else in that tree is reachable. Copying it was not caution, it
# was waste.
say "copying the two kernel modules the guest loads"
MODVER=$(basename "$MODULES/lib/modules"/*)
FUSEDIR="lib/modules/$MODVER/kernel/fs/fuse"
mkdir -p "$ROOT/$FUSEDIR"
for module in fuse virtiofs; do
  cp "$MODULES/$FUSEDIR/$module.ko.xz" "$ROOT/$FUSEDIR/" 2>/dev/null \
    || cp "$MODULES/$FUSEDIR/$module.ko" "$ROOT/$FUSEDIR/"
done
chmod -R u+w "$ROOT/lib/modules"
# Decompressed: busybox's `insmod` does not handle .xz, and the guest has
# no `modprobe` to do it for us.
#
# `xz` comes from the store rather than PATH. The first version used a
# bare `xz` and the shell reported "command not found" — which the `||
# true` swallowed, so the script reported success while shipping modules
# the guest could not load. A tool that is not on PATH is exactly what
# `|| true` must not hide.
XZ=$(nix build --no-link --print-out-paths "nixpkgs#xz" | grep -- '-bin$' | head -1)
test -x "$XZ/bin/xz" || { echo "no xz in $XZ" >&2; exit 1; }
find "$ROOT/lib/modules" -name '*.ko.xz' -exec "$XZ/bin/xz" -d {} \;
# And ASSERT the result, because a silent no-op here ships a guest that
# cannot mount its workspace.
test -f "$ROOT/lib/modules/$(basename "$MODULES/lib/modules"/*)/kernel/fs/fuse/virtiofs.ko" || {
  echo "virtiofs.ko was not decompressed — the guest cannot mount virtiofs" >&2
  exit 1
}

say "copying closures ($(nix path-info -r "$NODE" "$POSTGRES" | wc -l | tr -d ' ') paths)"
for path in $(nix path-info -r "$NODE" "$POSTGRES"); do
  cp -a "$path" "$ROOT/nix/store/" 2>/dev/null || true
done

cp "$BUSYBOX/bin/busybox" "$ROOT/bin/busybox"
chmod +w "$ROOT/bin/busybox"
( cd "$ROOT"
  # `mke2fs` included: the guest FORMATS its own state volume on first
  # use, because the host handing over a pre-formatted image would put the
  # host's e2fsprogs in the guest's boot path.
  for c in sh mount umount echo cat ls sleep poweroff mkdir chown su id ps \
           grep env ln date head tail cut printf touch ip ifconfig hostname \
           mke2fs mkfs.ext2 blkid sync halt reboot insmod lsmod find uname stat df; do
    ln -sf busybox "bin/$c"
  done )

printf 'root:x:0:0:root:/root:/bin/sh\npostgres:x:1000:1000:postgres:/data:/bin/sh\n' > "$ROOT/etc/passwd"
printf 'root:x:0:\npostgres:x:1000:\n' > "$ROOT/etc/group"
echo rachna > "$ROOT/etc/hostname"

# The guest's init. Store paths are substituted in, because Postgres
# resolves share/ and lib/ from argv[0] and a /bin symlink breaks it
# (02 §6.9).
sed -e "s|@POSTGRES@|$POSTGRES|g" -e "s|@NODE@|$NODE|g" \
  "$(dirname "$0")/../guest/aarch64-init.sh" > "$ROOT/init"
# CHECKED HERE, because a syntax error in the guest's init is a kernel
# panic three minutes into a boot ("Attempted to kill init"), with the
# reason nowhere in the output. Measured: an editing slip left a
# duplicated `else`/`fi` and cost a full build-and-boot cycle to find.
sh -n "$ROOT/init" || { echo "the guest init has a syntax error" >&2; exit 1; }
chmod +x "$ROOT/init"
cp "$(dirname "$0")/../guest/todos.js" "$ROOT/opt/rachna/todos.js"

say "building the initramfs"
INITRAMFS="$WORK/initramfs"
mkdir -p "$INITRAMFS"/{bin,dev,proc,sys,mnt}
cp "$BUSYBOX/bin/busybox" "$INITRAMFS/bin/busybox"
chmod +w "$INITRAMFS/bin/busybox"
# The same two modules, copied directly rather than copy-then-delete: the
# initramfs is loaded into GUEST MEMORY, so every byte is RAM the guest
# does not get, and the host does not need to touch 139 MB to place 2 MB.
mkdir -p "$INITRAMFS/$FUSEDIR"
for module in fuse virtiofs; do
  cp "$MODULES/$FUSEDIR/$module.ko.xz" "$INITRAMFS/$FUSEDIR/" 2>/dev/null \
    || cp "$MODULES/$FUSEDIR/$module.ko" "$INITRAMFS/$FUSEDIR/"
done
chmod -R u+w "$INITRAMFS/lib/modules"
find "$INITRAMFS/lib/modules" -name '*.ko.xz' -exec "$XZ/bin/xz" -d {} \;

( cd "$INITRAMFS"
  # `cat` is NOT optional: the declared-mount loop reads
  # `/proc/cmdline`, and without it `$(cat /proc/cmdline)` expands to
  # nothing with the error swallowed by command substitution. That cost a
  # long detour — the guest looked like it was receiving no command line
  # while demonstrably acting on `root=/dev/vda`, and I was about to write
  # up a VZ device-tree theory to explain the contradiction.
  #
  # `02` §6.12 is the same lesson: check the measuring tool before
  # blaming the mechanism.
  for c in sh mount echo cat switch_root sleep ls mkdir insmod tr; do
    ln -sf busybox "bin/$c"
  done
  cat > init <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
i=0
while [ $i -lt 20 ]; do [ -b /dev/vda ] && break; sleep 0.25; i=$((i+1)); done
mount -t ext4 /dev/vda /mnt || { echo "RACHNA-INITRAMFS-FAILED"; exec sh; }

# THE WORKSPACE IS MOUNTED HERE, before switch_root — and that is the
# finding, not a preference. Mounting it after switch_root produced a live
# virtiofs mount serving an EMPTY tree: `/proc/mounts` showed it, `ls -a`
# listed nothing, and a standalone probe doing the same mount from an
# initramfs saw the host's files. `switch_root` was the difference.
#
# `switch_root` moves /proc, /sys and /dev for us but not arbitrary
# mounts, so the share is mounted into the NEW root's /workspace before
# pivoting — after which it is simply part of the filesystem the guest
# boots into.
#
# The modules are loaded here too, so the root init does not need
# `insmod` itself. `CONFIG_VIRTIO_FS=m` on this kernel, and the kernel
# package ships no modules directory — they come from a separate
# `modules` output.
MODDIR=$(echo /lib/modules/*/kernel/fs/fuse)
insmod "$MODDIR/fuse.ko" 2>/dev/null
insmod "$MODDIR/virtiofs.ko" 2>/dev/null

mkdir -p /mnt/workspace
if mount -t virtiofs workspace /mnt/workspace 2>/dev/null; then
  echo "RACHNA-INITRAMFS-WORKSPACE: $(ls /mnt/workspace | tr '\n' ' ')"
else
  echo "RACHNA-INITRAMFS-WORKSPACE-FAILED"
fi

echo "RACHNA-CMDLINE: $(cat /proc/cmdline)"

# DECLARED MOUNTS, from `rachna.mount=tag:/path` on the kernel command
# line. The host cannot tell VZ where a share belongs — a share is
# identified by tag and the guest decides — so the command line carries
# the map. It is also the only channel that reaches a guest before
# anything is mounted, which is when this is needed.
#
# Mounted into `/mnt`, which `switch_root` is about to make `/`, so each
# lands at its final path and a dotfile is in place before any shell
# starts.
for param in $(cat /proc/cmdline); do
  case "$param" in
    rachna.mount=*)
      spec=${param#rachna.mount=}
      tag=${spec%%:*}
      dest=${spec#*:}
      # The parent is created because a declared destination may be
      # somewhere the image has nothing — a home directory, say.
      mkdir -p "/mnt$dest" 2>/dev/null
      if mount -t virtiofs "$tag" "/mnt$dest" 2>/dev/null; then
        echo "RACHNA-MOUNT: $tag -> $dest"
        # READ THROUGH IT, not just "mounted". `02` §6.12: this mount
        # reports success while `find`/`ls` return nothing, so "mounted" is
        # the mechanism's verdict on itself and the file list is the
        # evidence a user cares about. The shell's own glob is what works.
        echo "RACHNA-MOUNT-FILES: $tag -> $(cd "/mnt$dest" && echo *)"
      else
        echo "RACHNA-MOUNT-FAILED: $tag -> $dest"
      fi
      ;;
  esac
done

exec switch_root /mnt /init
INIT
  chmod +x init
  find . | cpio -o -H newc 2>/dev/null | gzip -9 > "$WORK/initramfs.gz" )

say "building the root image"
mkdir -p "$OUT"
# SIZED FROM THE CONTENT, with headroom, rather than a flat 2 GiB. The
# guest writes its data to a separate state volume (`08` §4.1.3), so the
# root only ever holds what this script puts in it — and a 2 GiB
# declaration meant the build needed 2 GiB of free disk to assemble ~700
# MB of files. It failed on exactly that, twice.
CONTENT_MB=$(du -sm "$ROOT" | cut -f1)
IMAGE_MB=$(( CONTENT_MB + CONTENT_MB / 5 + 128 ))
say "root image: ${CONTENT_MB}MB of content -> ${IMAGE_MB}MB image"
# BUILT AT ITS DESTINATION, not built in $WORK and copied. The copy
# needed the image's size TWICE — 1.2 GB of free disk for a 615 MB
# artefact — and that is what ran out, three times on this machine.
#
# The trade is that a failed build leaves a partial file where the good
# one belongs, so it is removed first and verified after: `$OUT/root.img`
# existing is never by itself evidence that it is usable.
mkdir -p "$OUT"
rm -f "$OUT/root.img"
python3 -c "
f = open('$OUT/root.img', 'wb')
f.truncate($IMAGE_MB * 1024 * 1024)
f.close()"
"$E2FS/bin/mke2fs" -t ext4 -d "$ROOT" -F -L rachna-root -q "$OUT/root.img"

install -m 0644 "$KERNEL" "$OUT/Image"
install -m 0644 "$WORK/initramfs.gz" "$OUT/initramfs.gz"
chmod 0644 "$OUT/root.img"

# VERIFY WHAT WAS INSTALLED, not what was built. A truncated copy leaves a
# root.img whose ext4 superblock is intact and whose journal is not — the
# guest then fails with `EXT4-fs (vda): Could not load journal inode` and
# drops to an initramfs shell. Measured, after a build was interrupted
# mid-`install`.
#
# That is `24` §6's finding again: a partial artefact that inspects as
# complete. The superblock alone is not evidence, so the sizes are
# compared and `e2fsck` is asked.
for artefact in Image initramfs.gz root.img; do
  test -s "$OUT/$artefact" || {
    echo "$OUT/$artefact is missing or empty" >&2
    exit 1
  }
done
# `-n` is read-only, so this answers rather than repairs: a filesystem we
# would have to repair is one we should rebuild.
"$E2FS/bin/e2fsck" -n -f "$OUT/root.img" >/dev/null 2>&1 || {
  echo "the installed root.img does not pass e2fsck — rebuild rather than ship it" >&2
  exit 1
}

# A caller that pipes this script's output gets the PIPELINE's status, not
# the script's — `… | tail -6` reports `tail`'s 0 over a failed build. That
# cost a wrong diagnosis, so the final line is unambiguous: its absence
# means the build did not finish, whatever the exit status looked like.
say "done"
printf '  kernel:    %s\n' "$OUT/Image"
printf '  initramfs: %s\n' "$OUT/initramfs.gz"
printf '  root:      %s (%s)\n' "$OUT/root.img" "$(du -h "$OUT/root.img" | cut -f1)"
