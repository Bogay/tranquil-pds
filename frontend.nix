{
  lib,
  stdenvNoCC,
  pnpm,
  pnpmConfigHook,
  fetchPnpmDeps,
  nix-update-script,
}:
let
  toml = (lib.importTOML ./Cargo.toml).workspace.package;
in
stdenvNoCC.mkDerivation (finalAttrs: {
  pname = "tranquil-frontend";
  inherit (toml) version;

  src = ./frontend;

  pnpmDeps = fetchPnpmDeps {
    inherit (finalAttrs) pname version src;
    fetcherVersion = 3;
    hash = "sha256-E0S8dOaTOpY9m7Ft59tUQ6CLlLriWPE4WE1+S45vomY=";
  };

  nativeBuildInputs = [
    pnpm
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
