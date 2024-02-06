{
  pkgs,
  lib,
  config,
  modulesPath,
  ...
}:
with lib; {
  imports = [
    (modulesPath + "/profiles/qemu-guest.nix")
    (modulesPath + "/virtualisation/qemu-vm.nix")
  ];

  config = {
    system.stateVersion = "23.05";
    hardware.opengl.enable = true;

    boot = {
      # see https://nixos.wiki/wiki/Linux_kernel "Booting a kernel from a custom source"
      kernelPackages = let
        my_linux_pkg = {
          fetchurl,
          buildLinux,
          ...
        } @ args:
          buildLinux (args
            // rec {
              version = "6.3";
              modDirVersion = "6.3.0";

              # src = fetchurl {
              #   url = "https://github.com/jsakkine-intel/linux-sgx/archive/v23.tar.gz";
              #   # After the first build attempt, look for "hash mismatch" and then 2 lines below at the "got:" line.
              #   # Use "sha256-....." value here.
              #   hash = "";
              # };
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

        my_linux = pkgs.callPackage my_linux_pkg {};
      in
        pkgs.recurseIntoAttrs (pkgs.linuxPackagesFor my_linux);
    };

    # from profiles/minimal.nix
    documentation.enable = false;
    documentation.doc.enable = false;
    documentation.man.enable = false;
    documentation.nixos.enable = false;
    documentation.info.enable = false;
    programs.bash.enableCompletion = false;
    programs.command-not-found.enable = false;

    programs.dconf.enable = true;

    services.getty.autologinUser = "root";

    virtualisation = {
      memorySize = 4 * 1024;
      cores = 4;
      forwardPorts = [
        {
          from = "host";
          host.port = 10022;
          guest.port = 22;
        }
      ];
      qemu = {
        options = [
          # "-device virtio-vga-gl"
          # "-display sdl,gl=on"

          # "-display sdl,gl=off"
          # "-vga none"
          "-nographic"
          # "-serial stdio"

          # "-chardev qemu-vdagent,id=ch1,name=vdagent,clipboard=on"
          # "-device virtio-serial-pci"
          # "-device virtserialport,chardev=ch1,id=ch1,name=com.redhat.spice.0"
        ];
      };
    };

    security.polkit.enable = true;

    networking.firewall.enable = false;

    services.openssh.enable = true;
    services.openssh.settings.PermitRootLogin = "yes";
    # services.openssh.passwordAuthentication = true;

    environment.systemPackages = with pkgs; [
      vim
      micro
      wget
      mc
      tree
      tmux
    ];

    users.mutableUsers = false;

    users.users.root = {
      password = "";
      openssh.authorizedKeys.keys = ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDYiMGe5zxNUAbYnJMRWrVfQrPxbPH77bpY3JvRTd2xM/Pdm+o6zbPYToJcDZWBUDO3XuQFCtrLuEGM5IBKlrf7JCsk/yeoCS8tcFjEJxMTE1FQVuwxOlrbNSDF2aeA9XpIPg2mL2JUBj6YOF141GWXNra1X/s6bOfAwmxgZw/RnPY7+6ZFFwTGgWniurc3oeCOdT09aX5RDIEUcnni8ye7fLNQJHv3egz62ORVswJ7CuLtVcdK6gMOVCeBC0DFPUkt0SXLUQUwU5HpWKB1Xx9EKWPmdlZk+0pXz14DgiGfseCbRDQGLqvHE7WxT/MxSHzLqicAlrXMAAdz3EsA2D1dTetb0d20PvViYkDYIa/phzdueM8RbzGaItPKffsMZx9aUMALnbEKeyNPUzfyLohrqT6yflZ1N3o6EWEGXTBpAnHEjYBgdWR4tcKyfBu6sjWzEYM0jnIXnbRPjdoPdg+JR4+S4MzoPDprB86Nr722Jg03xa+sQudS9IBgY8YvYwM= amakarov@NB-100862.open-synergy.com"];
    };

    users.users.guest = {
      isNormalUser = true;
      home = "/home/guest";
      description = "Guest";
      # group = "guest";
      extraGroups = ["wheel"];
      uid = 1001;
      password = "";
    };
  };
}
