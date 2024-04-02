{
  description = "Virtio over fabrics";

  nixConfig.bash-prompt = "virtio-of";
  nixConfig.bash-prompt-prefix = "[\\033[1;33m";
  nixConfig.bash-prompt-suffix = "\\033[0m \\w]$ ";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nix-vscode-extensions = {
      url = "github:nix-community/nix-vscode-extensions";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    nix-vscode-extensions,
  }: let
    system = "x86_64-linux";

    overlay = self: super: {
      # linuxPackages = super.linuxPackages_6_1;
      # linuxPackages = super.linuxPackages_6_6;
      # see https://nixos.wiki/wiki/Linux_kernel "Booting a kernel from a custom source"
      linuxPackages = let
        my_linux_pkg = {
          fetchurl,
          buildLinux,
          ...
        } @ args:
          buildLinux (args
            // rec {
              version = "6.3";
              modDirVersion = "6.3.0";

              src = fetchurl {
                url = "mirror://kernel/linux/kernel/v6.x/linux-${version}.tar.xz";
                sha256 = "sha256-ujSR9e1r0nCjcMRAQ049aQhfzdUoki+gHnPXZX23Ox4=";
              };
              kernelPatches = [];

              # extraConfig = ''
              #   INTEL_SGX y
              # '';

              # extraMeta.branch = "5.4";
            }
            // (args.argsOverride or {}));

        my_linux = self.callPackage my_linux_pkg {};
      in
        self.recurseIntoAttrs (self.linuxPackagesFor my_linux);

      linuxKernel =
        super.linuxKernel
        // {
          packagesFor = kernel_: ((super.linuxKernel.packagesFor kernel_).extend (lpself: lpsuper: {
            virtio-of = lpsuper.callPackage ./kernel {};
          }));
        };
      virtio-target = super.callPackage ./. {};
    };

    pkgs = nixpkgs.legacyPackages.${system}.extend overlay;

    extensions = nix-vscode-extensions.extensions.${system};

    inherit (pkgs) vscode-with-extensions vscodium;

    vscode = vscode-with-extensions.override {
      vscode = vscodium;
      vscodeExtensions = [
        extensions.vscode-marketplace.ms-vscode.cpptools
        extensions.vscode-marketplace.github.vscode-github-actions
        extensions.vscode-marketplace.bbenoist.nix
      ];
    };

    nixos = pkgs.nixos (import ./configuration.nix);

    start_qemu_sh = pkgs.writeShellScript "start_qemu.sh" ''
      ${pkgs.coreutils}/bin/mkdir -p ./xchg

      TMPDIR=''$(pwd)
      USE_TMPDIR=1
      export TMPDIR USE_TMPDIR

      TTY_FILE="./xchg/tty.sh"
      read -r rows cols <<< "''$(${pkgs.coreutils}/bin/stty size)"

      cat << EOF > "''${TTY_FILE}"
      export TERM=xterm-256color
      stty rows ''$rows cols ''$cols
      reset
      EOF

      ${pkgs.coreutils}/bin/stty intr ^] # send INTR with Control-]
      ${nixos.vm}/bin/run-nixos-vm
      ${pkgs.coreutils}/bin/stty intr ^c
    '';

    vtgt_config = pkgs.writeText "vtgt.conf" ''
      [target]
      transport = tcp
      #transport = rdma
      address = 0.0.0.0
      # address = 192.168.122.1
      port = 15771
      threads = 4
      targets = 128

      [block0]
      tvqn = virtio-target/block/block0.service
      model = block
      features = 0
      backend = driver=block-posix,path=/tmp/block0.img,queues=4,serial=vtgt-000001

      [crypto0]
      tvqn = virtio-target/crypto/crypto0.service
      model = crypto
      features = 0
      backend = driver=crypto-gcrypt

      [rng0]
      tvqn = virtio-target/rng/rng0.service
      model = rng
      features = 0
      backend = driver=rng-simulator
    '';

    start_vtgt_sh = pkgs.writeShellScript "start_vtgt.sh" ''
      if [ ! -f /tmp/block0.img ] ; then
        truncate -s 1G /tmp/block0.img
      fi
      exec ${pkgs.virtio-target}/bin/vtgt ${vtgt_config};
    '';
  in {
    overlays = {
      default = overlay;
    };

    packages.${system} = rec {
      virtio-target = pkgs.virtio-target;
      virtio-of = pkgs.linuxPackages.virtio-of;
      default = virtio-target;
    };

    devShells.${system} = rec {
      virtio-target = with pkgs;
        mkShell {
          packages = [vscode];
          inputsFrom = [pkgs.virtio-target];
          shellHook = ''
            export KCFLAGS=-I$(pwd)/kernel
            export KERNELRELEASE=${pkgs.linuxPackages.kernel.modDirVersion}
            export KDIR=${pkgs.linuxPackages.kernel.dev}/lib/modules/${pkgs.linuxPackages.kernel.modDirVersion}/build
          '';
        };
      default = virtio-target;
    };

    apps.${system} = rec {
      codium = {
        type = "app";
        program = "${vscode}/bin/codium";
      };
      vtgt = {
        type = "app";
        program = "${start_vtgt_sh}";
      };
      qemu = {
        type = "app";
        program = "${start_qemu_sh}";
      };
      default = vtgt;
    };
  };
}
