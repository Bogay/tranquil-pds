{
  lib,
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
  deno,
  svelte-language-server,
  typescript-language-server,
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
    sqlx-cli
    cargo-nextest
    
    deno
    svelte-language-server
    typescript-language-server
  ];
}

