# Tranquil PDS production installation on NixOS

This guide covers installing Tranquil PDS on NixOS via the flake and the bundled NixOS module.

## Prerequisites

- A server :p
- Disk space enough for blobs (depends on usage; plan for ~1GB per active user as a baseline)
- A domain name pointing to your server's IP
- A wildcard TLS certificate for `*.pds.example.com` (user handles are served as subdomains)
- Flakes enabled (`experimental-features = nix-command flakes` in `nix.conf`)

## Add the flake as an input

In your system flake:

```nix
{
  inputs.tranquil.url = "git+https://tangled.org/tranquil.farm/tranquil-pds";

  outputs = { self, nixpkgs, tranquil, ... }: {
    nixosConfigurations.pds = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        tranquil.nixosModules.default
        ./configuration.nix
      ];
    };
  };
}
```

## Enable the service

In `configuration.nix`:

```nix
{
  services.tranquil-pds = {
    enable = true;
    database.createLocally = true;
    settings = {
      server.hostname = "pds.example.com";
      # see example.toml for all options
    };
  };
}
```

This will set up the local postgres database for you automatically. If you prefer to manage postgres yourself, leave `database.createLocally` at its default (`false`) and set `settings.database.url` manually.

See [example.toml](../example.toml) for the full set of configuration options.

## Binary cache

Pre-built artifacts from the flake — the package, frontend, and devshell — are published to [tranquil.cachix.org](https://tranquil.cachix.org). To pull from it instead of building locally, add to your NixOS config:

```nix
nix.settings = {
  substituters = [ "https://tranquil.cachix.org" ];
  trusted-public-keys = [ "tranquil.cachix.org-1:PoO+mGL6a6LcJiPakMDHN4E218/ei/7v2sxeDtNkSRg=" ];
};
```

> [!NOTE]
> Due to a current spindle limitation, the aarch64 package is cross-compiled on an x86_64 builder and published under a separate attribute. If you're running on aarch64, set the package manually:
>
> ```nix
> services.tranquil-pds.package = inputs.tranquil.packages.x86_64-linux.tranquil-pds-aarch64;
> ```
