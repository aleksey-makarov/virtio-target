{
  stdenv,
  lib,
  kernel,
  writeText,
}: let
  makefile = writeText "Makefile" ''
    modules:
    ''\t$(MAKE) -C $(KDIR) M=$$PWD modules
    install:
    ''\t$(MAKE) -C $(KDIR) M=$$PWD modules_install
    .PHONY: modules install
  '';
in
  stdenv.mkDerivation rec {
    pname = "virtio-of";
    version = "0.1";
    name = "${pname}-${version}-${kernel.version}";

    src = ./.;

    hardeningDisable = ["pic" "format"];
    nativeBuildInputs = kernel.moduleBuildDependencies;

    outputs = ["out" "dev"];

    makeFlags = [
      "KERNELRELEASE=${kernel.modDirVersion}"
      "KDIR=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
      "INSTALL_MOD_PATH=$(out)"
    ];

    postPatch = ''
      ln -s ${makefile} Makefile
    '';

    postInstall = ''
      install -Dm444 virtio_of.h -t $out/include/linux
    '';

    meta = with lib; {
      description = "virtio-of kernel modules";
      homepage = "https://lists.oasis-open.org/archives/virtio-comment/202304/msg00442.html";
      license = licenses.gpl2;
      maintainers = [
        {
          email = "alm@opensynergy.com";
          name = "Aleksei Makarov";
          github = "aleksey.makarov";
          githubId = 19228987;
        }
      ];
      platforms = platforms.linux;
    };
  }
