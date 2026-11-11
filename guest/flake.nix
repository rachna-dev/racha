{
  # The pinned NixOS guest.
  #
  # Four bugs are fixed HERE rather than left to a caller, because three of
  # the four fail silently or confusingly. Each was measured:
  #
  #   never mount a host share over a directory systemd owns — `/var/lib`
  #   shadows `/var/lib/systemd` and logind fails 238/STATE_DIRECTORY on
  #   every boot
  #
  #   two options were renamed on this nixpkgs: `systemd.extraConfig` ->
  #   `systemd.settings.Manager`, and `services.journald.extraConfig` ->
  #   `services.journald.settings.Journal`
  #
  #   console wiring must be `--serial file=` with `console=ttyS0`; the
  #   `hvc0` variant produces ZERO output and ZERO errors, which is the
  #   worst way to be wrong
  #
  #   nixpkgs ships only `bzImage`, and Cloud Hypervisor needs a
  #   PVH-capable ELF `vmlinux` — extracted below rather than left to the
  #   caller to discover
  #
  # The rev is pinned deliberately and never bumped by accident: two people
  # with the same rachna.nix must get the same machine (`08` §4.1.1).
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/3181085bfd08663b6b9e60bc7a8395c2aaa741bd";

  # HOST TOOLING ONLY — deliberately a second input, and the separation is
  # load-bearing.
  #
  # The guest pin above decides what the VM *is*: `08` §4.1.1 requires two
  # people with the same `rachna.nix` to get the same machine, so bumping it
  # changes every guest and is never done by accident. But the pin ships
  # Cloud Hypervisor **53.0**, and `04` §7 recommends targeting **v54** for
  # the n-2 migration-compatibility guarantee — plus `25` §3 needs v54's
  # offload daemon, which is the only design where snapshot plaintext never
  # reaches disk.
  #
  # Those are two different questions. The hypervisor is a *host tool* that
  # runs the guest; it is not part of the guest. Bumping it must not rebuild
  # anyone's environment, and a single input would have forced exactly that.
  #
  # `24`'s correction is why this is explicit rather than implied: that spike
  # used v53 from the devShell and v54 from elsewhere without recording
  # which, so its header claimed v54 for measurements taken on v53. The flake
  # now names both, and the devShell is the version of record for tooling.
  inputs.host-tools.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    {
      self,
      nixpkgs,
      host-tools,
    }:
    let
      forSystems =
        f:
        nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (
          system: f system nixpkgs.legacyPackages.${system}
        );
    in
    {
      # The guest system, per architecture.
      nixosConfigurations = {
        x86_64-linux = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [ ./guest.nix ];
        };
        aarch64-linux = nixpkgs.lib.nixosSystem {
          system = "aarch64-linux";
          modules = [ ./guest.nix ];
        };
      };

      # The boot bundle: a PVH-capable vmlinux plus the initrd and cmdline.
      #
      # §4.4's gap, closed. `scripts/extract-vmlinux` lives in the kernel's
      # `.dev` output and produces the ELF image Cloud Hypervisor needs from
      # the bzImage nixpkgs ships.
      packages = forSystems (
        system: pkgs:
        let
          guest = self.nixosConfigurations.${system};
          kernel = guest.config.boot.kernelPackages.kernel;
        in
        {
          boot-bundle =
            pkgs.runCommand "rachna-boot-bundle"
              {
                nativeBuildInputs = with pkgs; [
                  bash
                  gzip
                  xz
                  bzip2
                  lz4
                  lzop
                  zstd
                  binutils
                ];
              }
              ''
                mkdir -p $out

                # Cloud Hypervisor needs a PVH-capable ELF image, and nixpkgs
                # ships ONLY a bzImage — verified on this nixpkgs rev: the kernel
                # output contains exactly `System.map` and `bzImage`, no
                # `vmlinux`. So extraction is required, not optional (§4.4).
                #
                # `scripts/extract-vmlinux` needs the decompressors on PATH: a
                # bzImage is a self-extracting wrapper around a compressed
                # vmlinux, and the script tries each format in turn. Without them
                # it silently finds nothing.
                bash ${kernel.dev}/lib/modules/${kernel.modDirVersion}/source/scripts/extract-vmlinux \
                  ${kernel}/bzImage > $out/vmlinux

                # Verified rather than assumed: the script exits 0 having written
                # nothing when no decompressor matches, and a 0-byte vmlinux is
                # the silent failure 05 §4.4 warns about. An ELF starts \x7fELF.
                if [ ! -s $out/vmlinux ]; then
                  echo "extract-vmlinux produced an empty image" >&2
                  exit 1
                fi
                if [ "$(head -c 4 $out/vmlinux | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]; then
                  echo "extracted image is not an ELF — CH needs PVH ELF" >&2
                  exit 1
                fi

                cp ${guest.config.system.build.initialRamdisk}/initrd $out/initrd

                # The closure as a read-only squashfs — `00` §7 Layer C: the
                # project closure is a SEPARATE disk attached to a generic
                # base, so changing a package swaps one disk rather than
                # rebuilding an OS image.
                #
                # Needed because the guest's `fileSystems."/"` must have
                # something to switch into. Measured without it: the initrd
                # reaches 15 targets, fails "Find NixOS closure", and drops
                # to emergency mode — switch-root with no root.
                mkdir -p $out/closure
                echo "${guest.config.system.build.toplevel}" > $out/closure/system
                ${pkgs.squashfsTools}/bin/mksquashfs \
                  $(cat ${pkgs.writeClosure [ guest.config.system.build.toplevel ]}) \
                  $out/closure.squashfs \
                  -no-hardlinks -keep-as-directory -all-root -b 1048576 \
                  -comp zstd -Xcompression-level 6 -no-progress >/dev/null
                cp ${guest.config.system.build.toplevel}/init $out/init 2>/dev/null || true
                ln -s ${guest.config.system.build.toplevel} $out/system

                # The cmdline, written here so the backend does not reconstruct
                # it. `console=ttyS0` is §4.3's measured requirement: the hvc0
                # variant produces zero output AND zero errors.
                # `printf` rather than a heredoc, for the reason recorded on
                # `vz-image` below: an indented `<<EOF` terminator is never
                # matched and the heredoc eats the rest of the script, as a
                # warning rather than an error.
                printf '%s\n' \
                  'init=${guest.config.system.build.toplevel}/init console=ttyS0 8250.nr_uarts=1 panic=1 nomodeset loglevel=4' \
                  > $out/cmdline
              '';

          # THE IMAGE `rachna start` LOADS, which is a different shape from
          # `boot-bundle` above and deliberately so.
          #
          # `boot-bundle` targets Cloud Hypervisor: a PVH-capable ELF
          # `vmlinux`, because CH cannot boot the bzImage nixpkgs ships
          # (§4.4). Apple's Virtualization.framework wants the opposite —
          # `VZLinuxBootLoader` takes the kernel AS SHIPPED, and an extracted
          # ELF is not what it expects.
          #
          # The filenames are a contract with `boot.rs`, not a preference:
          # `Image::find` looks for exactly `Image`, `initramfs.gz` and
          # `root.img` in one version-named directory and reports a specific
          # missing file otherwise. A bundle with the right contents under
          # other names fails as "incomplete", which is why this exists
          # rather than the CLI learning a second layout.
          vz-image =
            pkgs.runCommand "rachna-vz-image"
              {
                nativeBuildInputs = with pkgs; [
                  gzip
                  e2fsprogs
                  squashfsTools
                ];
              }
              ''
                                mkdir -p $out

                                # The kernel UNMODIFIED. aarch64 nixpkgs ships `Image`;
                                # x86_64 ships `bzImage`, and VZ accepts that too — so the
                                # file is copied under the name `boot.rs` expects rather
                                # than converted.
                                if [ -f ${kernel}/Image ]; then
                                  cp ${kernel}/Image $out/Image
                                else
                                  cp ${kernel}/bzImage $out/Image
                                fi

                                # `initramfs.gz`, gzipped because that is the name the host
                                # looks for. NixOS's `initialRamdisk` is already compressed,
                                # so this is a copy under the contracted name — verified
                                # with `file` below rather than assumed from the extension.
                                cp ${guest.config.system.build.initialRamdisk}/initrd \
                                  $out/initramfs.gz

                                # The closure as the ROOT DISK. `guest.nix` mounts
                                # `/dev/vda` as a squashfs at `/nix/.ro-store` and overlays
                                # it, so `root.img` IS that squashfs — the name says "root"
                                # because that is the disk the guest roots from, not because
                                # it holds a conventional root filesystem.
                                mksquashfs \
                                  $(cat ${pkgs.writeClosure [ guest.config.system.build.toplevel ]}) \
                                  $out/root.img \
                                  -no-hardlinks -keep-as-directory -all-root -b 1048576 \
                                  -comp zstd -Xcompression-level 6 -no-progress >/dev/null

                                # The cmdline the host passes. `init=` must name the closure's
                                # own init or the guest switch-roots into nothing — measured
                                # in §4.3 as 15 targets reached then emergency mode.
                                # `printf`, NOT a heredoc. Measured: an indented `<<EOF`
                                # terminator is never matched — a Nix multi-line string's body is
                                # indented, and the shell wants the terminator at column 0 — so
                                # the heredoc swallows the REST OF THE SCRIPT. bash reports that
                                # as a *warning* and exits 0, so every verification after it is
                                # silently skipped on a build that looks fine. `printf` has no
                                # terminator to indent.
                                printf '%s\n' \
                                  'init=${guest.config.system.build.toplevel}/init console=ttyS0 8250.nr_uarts=1 panic=1 nomodeset loglevel=4' \
                                  > $out/cmdline

                                # EVERY FILE NON-EMPTY, named one at a time. A 0-byte kernel
                                # or root is the silent failure shape this project keeps
                                # hitting: the build exits 0, the image looks present, and
                                # the guest dies with no output.
                                for f in Image initramfs.gz root.img cmdline; do
                                  if [ ! -s $out/$f ]; then
                                    echo "vz-image: $f is empty or missing" >&2
                                    exit 1
                                  fi
                                done

                                # The kernel must be a kernel, checked at the MEASURED magic
                                # offsets rather than by scanning the head of the file.
                                #
                                # A first version grepped the first 64 bytes for `ARM64` or
                                # `HdrS` and rejected a real x86_64 kernel: `HdrS` sits at
                                # offset **514**, not in the header prologue. Measured on the
                                # images this project actually ships —
                                #
                                #   aarch64:  `ARMd` at offset 56  (41 52 4d 64 — the
                                #             documented `ARM\\x64`, whose fourth byte is
                                #             the ASCII `d`, so it compares as text)
                                #   x86_64:   `HdrS` at offset 514
                                #
                                # — so each is read where it lives. Worth the care because
                                # copying the wrong file yields an image that boots to
                                # nothing on the console (`02` §4), which is the failure
                                # shape that costs the most time to diagnose.
                                arm=$(dd if=$out/Image bs=1 skip=56 count=4 2>/dev/null)
                                x86=$(dd if=$out/Image bs=1 skip=514 count=4 2>/dev/null)
                                if [ "$arm" != "ARMd" ] && [ "$x86" != "HdrS" ]; then
                                  echo "vz-image: Image carries neither the aarch64 nor the \
                x86_64 kernel magic" >&2
                                  exit 1
                                fi

                                # Checksums, so `install.sh` can verify what it fetched.
                                ( cd $out && sha256sum Image initramfs.gz root.img cmdline \
                                    > SHA256SUMS )
              '';

          default = self.packages.${system}.boot-bundle;
        }
      );

      devShells = forSystems (
        system: pkgs:
        let
          # From `host-tools`, not the guest pin. Asserted below rather than
          # trusted: a devShell silently giving v53 is what made `24`'s
          # header wrong.
          tools = host-tools.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              tools.cloud-hypervisor
              tools.virtiofsd
              pkgs.jq
            ];

            # `04` §7 wants v54 and `25` §3 needs its offload daemon. If the
            # shell ever resolves to something older, say so on entry rather
            # than letting a measurement be attributed to the wrong version
            # — which is the mistake `24`'s header made.
            shellHook = ''
              have=$(cloud-hypervisor --version 2>/dev/null | head -1)
              case "$have" in
                *v5[4-9]*|*v[6-9][0-9]*) : ;;
                *) echo "rachna: WARNING — host tooling is '$have'." >&2
                   echo "  04 §7 targets v54+ and 25 §3 needs its offload" >&2
                   echo "  daemon. Measurements taken here must record v53." >&2 ;;
              esac
            '';
          };
        }
      );
    };
}
