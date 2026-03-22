{
  lib,
  rustPlatform,
  pkg-config,
  openssl,
  protobuf,
}: let
  toml = (lib.importTOML ./Cargo.toml).workspace.package;
in rustPlatform.buildRustPackage {
  pname = "tranquil-pds";
  inherit (toml) version;

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.intersection (lib.fileset.fromSource (lib.sources.cleanSource ./.)) (
      lib.fileset.unions [
        ./Cargo.toml
        ./Cargo.lock
        ./crates
      	./.sqlx
      	./migrations
      ]
    );
  };

  nativeBuildInputs = [
    pkg-config
    protobuf
  ];

  buildInputs = [
    openssl
  ];

  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "curve25519-dalek-4.1.3" = "1013mg8xna6jjgq9kvpy0dlbhh5zv1wll9kw1fyplrhw91w7py3c";
      "libsignal-protocol-0.1.0" = "1dk71757dccvyknn106kkf19a5arlkyinrb6x8xh2ly6f717jick";
      "spqr-1.4.0" = "0hx2nmkscv7pn5qan86g8k9ljlvp7dshbspqivsqv0wgsydlcdns";
      "libsignal-service-0.1.0" = "0xxr0ipl0pl35m3518fa8sjnp8viwsni41xv6s0f3mar45h3wydf";
      "presage-0.8.0-dev" = "16hrnjikpz5dqwa9v74akn4l0xkb64ld7qkpq3rw067bn05cjxis";
    };
  };

  doCheck = false;

  meta = {
    license = lib.licenses.agpl3Plus;
    mainProgram = "tranquil-server";
  };
}
