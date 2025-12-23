{
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  outputs = { self, nixpkgs, ... }: let
    forAllSystems =
      function:
      nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (
        system: function nixpkgs.legacyPackages.${system}
      );
  in {
    packages = forAllSystems (pkgs: {
      tranquil-pds = pkgs.callPackage ./default.nix { };
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.tranquil-pds;
    });

    devShells = forAllSystems (pkgs: {
      default = pkgs.callPackage ./shell.nix { };
    });
  };
}
