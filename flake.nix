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
      linuxPackages = super.linuxPackages_6_6;
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
    # start_gtk_test_sh = pkgs.writeShellScript "start_gtk_test.sh" ''
    #   export LOCALE_ARCHIVE="${pkgs.glibcLocales}/lib/locale/locale-archive";
    #   export GDK_GL=gles
    #   exec ${pkgs.nixgl.nixGLMesa}/bin/nixGLMesa ${pkgs.libvirtiolo-debug}/bin/gtk_test
    # '';
    #    startvm_sh = pkgs.writeShellScript "startvm.sh" ''
    #      ${pkgs.coreutils}/bin/mkdir -p ./xchg
    #
    #      TMPDIR=''$(pwd)
    #      USE_TMPDIR=1
    #      export TMPDIR USE_TMPDIR
    #
    #      TTY_FILE="./xchg/tty.sh"
    #      read -r rows cols <<< "''$(${pkgs.coreutils}/bin/stty size)"
    #
    #      cat << EOF > "''${TTY_FILE}"
    #      export TERM=xterm-256color
    #      stty rows ''$rows cols ''$cols
    #      reset
    #      EOF
    #
    #      ${pkgs.coreutils}/bin/stty intr ^] # send INTR with Control-]
    #      ${pkgs.nixgl.nixGLMesa}/bin/nixGLMesa ${nixos.vm}/bin/run-nixos-vm
    #      ${pkgs.coreutils}/bin/stty intr ^c
    #    '';
  in {
    overlays.${system} = {
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
            echo "Hello world"
          '';
        };
      default = virtio-target;
    };

    apps.${system} = rec {
      # codium = {
      #   type = "app";
      #   program = "${vscode}/bin/codium";
      # };
      # startvm = {
      #   type = "app";
      #   program = "${startvm_sh}";
      # };
      # test_virglrenderer = {
      #   type = "app";
      #   program = "${startvm_sh}";
      # };
      # default = startvm;
      virtio-target = {
      };
      default = virtio-target;
    };
  };
}
