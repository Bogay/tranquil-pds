{
  lib,
  stdenvNoCC,
  nodejs,
  pnpm_11,
  pnpmConfigHook,
  fetchPnpmDeps,
  nix-update-script,
}:
let
  toml = (lib.importTOML ./Cargo.toml).workspace.package;
  pnpm = pnpm_11;
in
stdenvNoCC.mkDerivation (finalAttrs: {
  pname = "tranquil-frontend";
  inherit (toml) version;

  src = ./frontend;

  pnpmDeps = fetchPnpmDeps {
    inherit (finalAttrs) pname version src;
    inherit pnpm;
    fetcherVersion = 4;
    hash = "sha256-+P4UUkZKQJVfGbDFKR0gRMU+wYK9K7NBYo1s/ebRK9I=";
  };

  nativeBuildInputs = [
    pnpm
    nodejs
    pnpmConfigHook
  ];

  buildPhase = ''
    runHook preBuild
    pnpm build
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    cp -r ./dist $out
    runHook postInstall
  '';

  passthru.updateScript = nix-update-script {
    extraArgs = [
      "--version"
      "SKIP"
    ];
  };
})
