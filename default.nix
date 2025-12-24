{
  lib,
  rustPlatform,
  pkg-config,
  openssl,
}: let
  toml = (lib.importTOML ./Cargo.toml).package;
in rustPlatform.buildRustPackage {
  pname = "tranquil-pds";
  inherit (toml) version;

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.intersection (lib.fileset.fromSource (lib.sources.cleanSource ./.)) (
      lib.fileset.unions [
        ./Cargo.toml
        ./Cargo.lock
        ./src
      	./.sqlx
      	./migrations
	      ./frontend
      ]
    );
  };

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    openssl
  ];

  cargoLock.lockFile = ./Cargo.lock;

  doCheck = false;
}
