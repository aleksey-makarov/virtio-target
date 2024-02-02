{
  stdenv,
  lib,
  libgcrypt,
  # linuxHeaders,
}:
stdenv.mkDerivation rec {
  pname = "virtio-target";
  version = "0.1";

  src = ./.;

  outputs = ["out" "dev"];

  # buildInputs = [];

  nativeBuildInputs = [
    # linuxHeaders
    libgcrypt
  ];

  installPhase = ''
    set -x
    mkdir -p $out/bin
    cp ./vtgt ./initiator/vinitiator $out/bin
  '';

  meta = with lib; {
    description = "virtio-oF target";
    homepage = "https://www.opensynergy.com/";
    license = licenses.mit;
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
