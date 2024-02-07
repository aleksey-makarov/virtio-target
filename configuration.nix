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
      extraModulePackages = with config.boot.kernelPackages; [virtio-of];
      kernelModules = ["virtio-fabrics" "virtio-tcp" "virtio-rdma"];
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

      (writeShellScriptBin
        "start_block_device.sh"
        ''
          ADDR=10.0.2.2
          echo command=create,transport=tcp,taddr=''$ADDR,tport=15771,tvqn=virtio-target/block/block0.service,iaddr=''$ADDR,iport=0,ivqn=vqn.uuid:42761df9-4c3f-4b27-843d-c88d1dcdce32 > /dev/virtio-fabrics
        '')
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
