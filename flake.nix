{
  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixpkgs-unstable/nixexprs.tar.xz";
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
      lib.mkPackages = import ./pkgs.nix;

      packages = forAllSystems (pkgs: (self.lib.mkPackages pkgs) // {
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.tranquil-pds;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.callPackage ./shell.nix { };
        full = pkgs.callPackage ./shells/full.nix { };
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
              settings.frontend.dir = self.packages.${pkgs.stdenv.hostPlatform.system}.tranquil-frontend;
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
