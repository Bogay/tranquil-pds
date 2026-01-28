{
  lib,
  stdenvNoCC,
  
  fetchDenoDeps,
  fetchFromGitHub,
  
  buildGoModule,

  deno,
  esbuild,
}: let
  toml = (lib.importTOML ./Cargo.toml).workspace.package;
  deno-deps = fetchDenoDeps {
    pname = "tranquil-frontend-deno-deps";
    denoLock = ./frontend/deno.lock;
    hash = "sha256-UB+E00TjWX0fTUZ7XwcwRJ/OUOSSJpz6Ss04U5i8dGI=";
  };
  # the esbuild in upstream nixpkgs is too old.
  esbuild' = esbuild.override {
    buildGoModule = args: buildGoModule (
      args // (
        let
          version = "0.27.2";
        in {
          inherit version;
          src = fetchFromGitHub {
            owner = "evanw";
            repo = "esbuild";
            tag = "v${version}";
            hash = "sha256-JbJB3F1NQlmA5d0rdsLm4RVD24OPdV4QXpxW8VWbESA";
          };
          vendorHash = "sha256-+BfxCyg0KkDQpHt/wycy/8CTG6YBA/VJvJFhhzUnSiQ";
        }
      )
    );
  };
in stdenvNoCC.mkDerivation {
    pname = "tranquil-frontend";
    inherit (toml) version;
    
    src = ./frontend;

    nativeBuildInputs = [
      deno
    ];
    # tell vite (through the esbuild api) where the nix provided esbuild binary is
    env.ESBUILD_BINARY_PATH = lib.getExe esbuild';

    buildPhase = ''
      # copy the deps to the required location
      cp -r --no-preserve=mode ${deno-deps.denoDeps}/.deno ./
      cp -r --no-preserve=mode ${deno-deps.denoDeps}/vendor ./

      pwd
      ls /build/frontend/vendor

      # Now you can run the project using deps
      # you need to activate [deno's vendor feature](https://docs.deno.com/runtime/fundamentals/modules/#vendoring-remote-modules)
      # you need to use the `$DENO_DIR` env var, to point deno to the correct local cache
      DENO_DIR=./.deno deno run --frozen --cached-only build
    '';
    installPhase = ''
      cp -r ./dist $out
    '';
}
