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

OUT="${1:-$HOME/.rachna/guests/aarch64}"
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
trap 'chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT
ROOT="$WORK/root"
#  holds the shipped demo app;  is a MOUNT
# POINT for the user's project, so it stays empty in the image.
mkdir -p "$ROOT"/{bin,sbin,dev,proc,sys,tmp,etc,var,run,workspace,data,opt/rachna,nix/store}

say "copying the kernel modules"
mkdir -p "$ROOT/lib/modules"
cp -a "$MODULES/lib/modules/." "$ROOT/lib/modules/"
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
           mke2fs mkfs.ext2 blkid sync halt reboot insmod lsmod find uname; do
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
mkdir -p "$INITRAMFS/lib/modules"
cp -a "$MODULES/lib/modules/." "$INITRAMFS/lib/modules/"
chmod -R u+w "$INITRAMFS/lib/modules"
# Only the two modules the share needs: copying every module would add
# ~200 MiB to an initramfs the kernel must load into memory.
find "$INITRAMFS/lib/modules" -type f \
  ! -name 'fuse.ko*' ! -name 'virtiofs.ko*' -delete
find "$INITRAMFS/lib/modules" -name '*.ko.xz' -exec "$XZ/bin/xz" -d {} \;

( cd "$INITRAMFS"
  for c in sh mount echo switch_root sleep ls mkdir insmod tr; do
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
MODDIR=$(echo /lib/modules/*/kernel/fs/fuse)
insmod "$MODDIR/fuse.ko" 2>/dev/null
insmod "$MODDIR/virtiofs.ko" 2>/dev/null
# Mounted DIRECTLY into the new root, so `switch_root` inherits it as an
# ordinary part of the filesystem rather than having to carry it across.
#
# MEASURED (`02` §6.12): mounting into the initramfs and letting
# `switch_root` move it gave `/proc/mounts` showing the share and `ls -a`
# listing nothing — the mount survived the pivot and its CONTENTS did
# not. Mounting at the final path is what works, and the proof is the
# file list printed on both sides of the pivot.
# MOUNTED HERE, and the workspace is the one thing in this guest that
# does not work (`02` §6.12). Recorded rather than hidden:
#
#   RACHNA-INITRAMFS-WORKSPACE: my-source-file.txt rachna.nix src
#   RACHNA-WORKSPACE-FILES:                          <- after switch_root
#
# Same mount, same path, contents gone. `/proc/mounts` still shows it, so
# the kernel believes the filesystem is mounted while serving nothing.
# `mount --move` was tried and PANICKED the guest ("Attempted to kill
# init"), so it is not a safe workaround either.
#
# Left mounting at the final path because that is the simplest form that
# boots, and the file list on both sides of the pivot is what makes the
# failure visible instead of looking like an empty project.
MODDIR=$(echo /lib/modules/*/kernel/fs/fuse)
insmod "$MODDIR/fuse.ko" 2>/dev/null
insmod "$MODDIR/virtiofs.ko" 2>/dev/null
mkdir -p /mnt/workspace
if mount -t virtiofs workspace /mnt/workspace 2>/dev/null; then
  echo "RACHNA-INITRAMFS-WORKSPACE: $(ls /mnt/workspace | tr '\n' ' ')"
else
  echo "RACHNA-INITRAMFS-WORKSPACE-FAILED"
fi

exec switch_root /mnt /init
INIT
  chmod +x init
  find . | cpio -o -H newc 2>/dev/null | gzip -9 > "$WORK/initramfs.gz" )

say "building the root image"
mkdir -p "$OUT"
python3 -c "f=open('$WORK/root.img','wb'); f.truncate(2*1024*1024*1024); f.close()"
"$E2FS/bin/mke2fs" -t ext4 -d "$ROOT" -F -L rachna-root -q "$WORK/root.img"

install -m 0644 "$KERNEL" "$OUT/Image"
install -m 0644 "$WORK/initramfs.gz" "$OUT/initramfs.gz"
install -m 0644 "$WORK/root.img" "$OUT/root.img"

say "done"
printf '  kernel:    %s\n' "$OUT/Image"
printf '  initramfs: %s\n' "$OUT/initramfs.gz"
printf '  root:      %s (%s)\n' "$OUT/root.img" "$(du -h "$OUT/root.img" | cut -f1)"
