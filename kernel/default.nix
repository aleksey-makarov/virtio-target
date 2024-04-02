{
  stdenv,
  lib,
  kernel,
  writeText,
}:
stdenv.mkDerivation rec {
  pname = "virtio-of";
  version = "0.1";
  name = "${pname}-${version}-${kernel.version}";

  src = ./.;

  hardeningDisable = ["pic" "format"];
  nativeBuildInputs = kernel.moduleBuildDependencies;

  outputs = ["out" "dev"];

  makeFlags = [
    "KCFLAGS=-I${src}"
    "KERNELRELEASE=${kernel.modDirVersion}"
    "KDIR=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
    "INSTALL_MOD_PATH=$(out)"
  ];

  postInstall = ''
    install -Dm444 linux/virtio_of.h -t $out/include/linux
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
