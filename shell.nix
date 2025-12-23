{
  mkShell,
  callPackage,
  rustPlatform,

  # repo tooling
  just,
  podman,
  podman-compose,

  # rust tooling
  clippy,
  rustfmt,
  rust-analyzer,

  # frontend tooling
  deno,
}: let
  defaultPackage = callPackage ./default.nix { };
in mkShell {
  inputsFrom = [ defaultPackage ];

  env = {
    RUST_SRC_PATH = rustPlatform.rustLibSrc;
  };

  packages = [
    just
    podman
    podman-compose

    clippy
    rustfmt
    rust-analyzer

    deno
  ];
}