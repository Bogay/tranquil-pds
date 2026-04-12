{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      forAllSystems =
        function:
        nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (
          system: function nixpkgs.legacyPackages.${system}
        );
    in
    {
      packages = forAllSystems (pkgs: {
        tranquil-pds = pkgs.callPackage ./default.nix { };
        tranquil-frontend = pkgs.callPackage ./frontend.nix { };
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.tranquil-pds;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.callPackage ./shell.nix { };
      });

      nixosModules = {
        default = self.nixosModules.tranquil-pds;
        tranquil-pds =
          { lib, pkgs, ... }:
          {
            _file = "${self.outPath}/flake.nix#nixosModules.tranquil-pds";
            imports = [ (import ./module.nix self) ];
            config.services.tranquil-pds = {
              package = self.packages.${pkgs.stdenv.hostPlatform.system}.tranquil-pds;
              settings.frontend.package = self.packages.${pkgs.stdenv.hostPlatform.system}.tranquil-frontend;
            };
          };
      };

      checks.x86_64-linux.integration = import ./test.nix {
        pkgs = nixpkgs.legacyPackages.x86_64-linux;
        inherit self;
      };

      checks.aarch64-linux.integration = import ./test.nix {
        pkgs = nixpkgs.legacyPackages.aarch64-linux;
        inherit self;
      };
    };
}
