# Collects everything a VMM needs to boot the guest into one directory with a
# manifest, so `rachna` reads one path instead of knowing NixOS internals.
#
# The manifest is also the honest place to record what the backend must supply:
# the virtiofs tags this guest expects, and the kernel command line it was
# built with.
{
  lib,
  runCommand,
  jq,
  system,
  kernel,
  initrd,
  kernelParams,
  toplevel,
}:

runCommand "rachna-guest-boot"
  {
    nativeBuildInputs = [ jq ];
    passthru = { inherit kernel initrd toplevel; };
  }
  ''
    mkdir -p $out

    # Kernel. On x86_64 NixOS installs bzImage, but Cloud Hypervisor needs a
    # PVH-capable ELF vmlinux (design-docs/04-SPIKE-LINUX-CH.md §4.2), so link
    # whichever images exist and let the manifest say which is which.
    for img in bzImage Image vmlinux; do
      if [ -e ${kernel}/$img ]; then
        ln -s ${kernel}/$img $out/$img
      fi
    done

    ln -s ${initrd}/initrd $out/initrd
    ln -s ${toplevel} $out/system

    # The init the kernel must run. NixOS's stage-2 lives in the closure.
    initPath=${toplevel}/init

    jq -n \
      --arg system '${system}' \
      --arg init "$initPath" \
      --arg cmdline '${lib.concatStringsSep " " kernelParams}' \
      --arg toplevel '${toplevel}' \
      '{
         system: $system,
         # Appended to the guest cmdline by the backend; `init=` tells the
         # kernel where NixOS stage-2 is.
         cmdline: ($cmdline + " init=" + $init),
         toplevel: $toplevel,
         # virtiofs tags this guest mounts. The backend MUST provide every
         # required tag or boot will hang waiting for a filesystem.
         # Matches fileSystems in configuration.nix.
         shares: [
           { tag: "nix-store", mount: "/nix/store", access: "read-only",  required: true  },
           { tag: "workspace", mount: "/workspace", access: "read-write", required: true  },
           { tag: "state",     mount: "/var/lib/rachna", access: "read-write", required: true,  snapshot: true  },
           { tag: "cache",     mount: "/home/dev/.cache", access: "read-write", required: false, snapshot: false }
         ],
         # Console wiring that actually works on Cloud Hypervisor; hvc0
         # silently produces no output.
         console: { device: "ttyS0", backend: "serial" }
       }' > $out/manifest.json
  ''
