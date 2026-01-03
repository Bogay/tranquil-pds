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
  mold,

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
  }
  # isabel if this is like a horrible way to do this forgive me for my sins ig
  # if you can make this better go do it and tell me how or something :3
  // builtins.fromTOML (
    (s: if s == "" then s else s + "\"") (lib.replaceStrings [ "\n" "=" "\"" ] [ "\"\n" "=\"" "\\\"" ]
      (lib.concatStringsSep "\n"
        (lib.filter (line: !lib.hasPrefix "#" line && line != "")
          (lib.splitString "\n"
            (if lib.pathIsRegularFile ./.env
              then (lib.readFile ./.env)
              else ""
            )
          )
        )
      )
    )
  );

  packages = [
    just
    podman
    podman-compose

    clippy
    rustfmt
    rust-analyzer
    sqlx-cli
    mold
    
    deno
    svelte-language-server
    typescript-language-server
  ];
}

