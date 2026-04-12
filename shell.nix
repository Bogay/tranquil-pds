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
  sqlx-cli,
  cargo-nextest,

  # frontend tooling
  svelte-language-server,
  typescript-language-server,
}:
let
  pds = callPackage ./default.nix { };
  frontend = callPackage ./frontend.nix { };
in
mkShell {
  inputsFrom = [
    pds
    frontend
  ];

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
    sqlx-cli
    cargo-nextest

    svelte-language-server
    typescript-language-server
  ];
}
