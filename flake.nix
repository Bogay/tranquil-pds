{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";

    # tranquil frontend uses deno as its package manager and build time runtime.
    # nixpkgs does not have deno support yet but its being worked on in https://github.com/NixOS/nixpkgs/pull/419255
    # for now we important that PR as well purely for its fetchDenoDeps
    nixpkgs-fetch-deno.url = "github:aMOPel/nixpkgs/feat/fetchDenoDeps";
  };

  outputs = {
    self,
    nixpkgs,
    ...
  } @ inputs: let
    forAllSystems = function:
      nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (
        system: (function system nixpkgs.legacyPackages.${system})
      );
  in {
    packages = forAllSystems (system: pkgs: {
      tranquil-pds = pkgs.callPackage ./default.nix {};
      tranquil-frontend = pkgs.callPackage ./frontend.nix {
        inherit (inputs.nixpkgs-fetch-deno.legacyPackages.${system}) fetchDenoDeps;
      };
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.tranquil-pds;
    });

    devShells = forAllSystems (system: pkgs: {
      default = pkgs.callPackage ./shell.nix {};
    });

    nixosModules = {
      default = self.nixosModules.tranquil-pds;
      tranquil-pds = {
        _file = "${self.outPath}/flake.nix#nixosModules.tranquil-pds";
        imports = [(import ./module.nix self)];
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
