{
  mkShell,
  callPackage,
  rustPlatform,

  # repo tooling
  just,

  # rust tooling
  clippy,
  rustfmt,
  rust-analyzer,
  sqlx-cli,
  cargo-nextest,

  # nix jemalloc for some tests that use jemalloc
  rust-jemalloc-sys,

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

    clippy
    rustfmt
    rust-analyzer
    sqlx-cli
    cargo-nextest

    rust-jemalloc-sys

    svelte-language-server
    typescript-language-server
  ];
}
