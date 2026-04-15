{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  };

  nixConfig = {
    extra-substituters = [
      "https://tranquil.cachix.org"
      "https://nix-community.cachix.org"
      "https://cache.garnix.io"
      "https://devenv.cachix.org"
    ];
    extra-trusted-public-keys = [
      "tranquil.cachix.org-1:PoO+mGL6a6LcJiPakMDHN4E218/ei/7v2sxeDtNkSRg="
      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
      "cache.garnix.io:CTFPyKSLcx5RMJKfLo5EEPUObbA78b0YQ2DTCJXqr9g="
      "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw="
    ];
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
        tranquil-pds-aarch64 = pkgs.pkgsCross.aarch64-multiplatform.callPackage ./default.nix { };
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
            imports = [ ./module.nix ];
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
