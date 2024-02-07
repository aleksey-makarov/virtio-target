{
  stdenv,
  lib,
  libgcrypt,
}:
stdenv.mkDerivation rec {
  pname = "virtio-target";
  version = "0.1";

  src = ./.;

  outputs = ["out" "dev"];

  # buildInputs = [];

  nativeBuildInputs = [
    libgcrypt
  ];

  installPhase = ''
    mkdir -p $out/bin
    cp ./vtgt ./initiator/vinitiator $out/bin
  '';

  meta = with lib; {
    description = "virtio-of target";
    homepage = "https://lists.oasis-open.org/archives/virtio-comment/202304/msg00442.html";
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
