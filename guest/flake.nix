{
  description = "Rachna's pinned NixOS guest — a reproducible Linux development machine.";

  inputs = {
    # PINNED, never floating. The guest is the reproducibility boundary: two
    # people with the same rachna.nix must get the same machine, so this rev is
    # bumped deliberately and never by accident.
    nixpkgs.url = "github:NixOS/nixpkgs/3181085";
  };

  outputs =
    { self, nixpkgs }:
    let
      # The guest is always Linux; only the architecture follows the host.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forEach = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      # One guest per architecture. `rachna` selects by host arch.
      nixosConfigurations = nixpkgs.lib.genAttrs systems (
        system:
        nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [ ./configuration.nix ];
        }
      );

      # What the VMM actually boots: a kernel + initrd + the system closure.
      packages = forEach (
        system:
        let
          cfg = self.nixosConfigurations.${system}.config;
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          # The system closure, as a store path the guest mounts read-only.
          system = cfg.system.build.toplevel;

          # Kernel image. Cloud Hypervisor wants a PVH-capable ELF vmlinux on
          # x86_64, NOT the bzImage nixpkgs installs by default — see
          # design-docs/04-SPIKE-LINUX-CH.md §4.2.
          kernel = cfg.system.build.kernel;

          initrd = cfg.system.build.initialRamdisk;

          # Everything a VMM needs, in one directory with a manifest.
          boot = pkgs.callPackage ./boot.nix {
            system = cfg.system.build.toplevel;
            kernel = cfg.system.build.kernel;
            initrd = cfg.system.build.initialRamdisk;
            kernelParams = cfg.boot.kernelParams;
            inherit (cfg.system.build) toplevel;
          };
        }
      );

      devShells = forEach (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.cloud-hypervisor
              pkgs.virtiofsd
            ];
          };
        }
      );
    };
}
