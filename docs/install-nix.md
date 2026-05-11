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
    database.createLocally = true; # set to false if you prefer to manually manage postgres. You must then set settings.database.url.
    settings = {
      server.hostname = "pds.example.com";
      # database.url = "postgresql://user:postgres@example.com" -- Only if database.createLocally is set to false.
      # see example.toml for all options
    };
    # see Secrets section for more information.
    environmentFiles = [ "/etc/secrets/tranquil.env.production" ];
  };
}
```

You will also likely want to configure Caddy or nginx to actually serve traffic to the service. An example Caddy config is provided below.

See [example.toml](https://tangled.org/tranquil.farm/tranquil-pds/blob/main/example.toml) at the repository root for the full set of configuration options.

### Example Caddy config

```nix
{
  services.caddy = {
    enable = true;

    virtualHosts = {
      "pds.example.com" = {
        # by default, tranquil runs on port 3000.
        # You can change this with the tranquil-pds.settings.server.port option in the service config.
        extraConfig = ''
          reverse_proxy localhost:3000
        '';
      };
    };
  };

  networking.firewall.allowedTCPPorts = [
    80
    443
  ];
}
```

### Secrets

Additionally, you will need to provide the following environment variables.

```env
# use `openssl rand -base64 32` to generate these.
JWT_SECRET=<secret_here>
DPOP_SECRET=<secret_here>
MASTER_KEY=<secret_here>
```

The simplest (least secure and least reproducible) option is to provide these secrets in a `.env` file using the `environmentFiles` option as shown above.

It is recommended that you use something like [`agenix`](https://github.com/ryantm/agenix) or [`sops-nix`](https://github.com/Mic92/sops-nix) for proper secrets management on a NixOS machine instead.

Example `sops-nix` config:

```nix
let
  inherit (config.sops) secrets;
in
{
  services.tranquil-pds = {
    enable = true;
    database.createLocally = true;
    settings = {
      server.hostname = "pds.example.com";
    };
    environmentFiles = [ secrets.tranquils-secrets.path ];
  };
}
```

## Communications

To actually be able to receive communications from the PDS for things like verification codes, or PLC operations, you must set at least one of the following options.

### Email

```nix
let
  inherit (config.sops) secrets;
in
{
  services.tranquil-pds = {
    enable = true;
    database.createLocally = true;
    settings = {
      server.hostname = "pds.example.com";
      email.from_address = "tranquil_admin@pds.example.com";
      # email.from_name = "Tranquil PDS";
    };
    environmentFiles = [ secrets.tranquils-secrets.path ];
  };
}
```

For DKIM options, please consult the [example.toml](https://tangled.org/tranquil.farm/tranquil-pds/blob/main/example.toml) at the repository root.

### Discord

```nix
let
  inherit (config.sops) secrets;
in
{
  services.tranquil-pds = {
    enable = true;
    database.createLocally = true;
    settings = {
      server.hostname = "pds.example.com";
      # if you're using proper secrets management, you should provide DISCORD_BOT_TOKEN in the environment file instead.
      discord.bot_token = "whatever";
    };
    environmentFiles = [ secrets.tranquils-secrets.path ];
  };
}
```

### Telegram

```nix
let
  inherit (config.sops) secrets;
in
{
  services.tranquil-pds = {
    enable = true;
    database.createLocally = true;
    settings = {
      server.hostname = "pds.example.com";
      telegram = {
        # if you're using proper secrets management, you should provide TELEGRAM_BOT_TOKEN in the environment file instead.
        bot_token = "whatever";
        # if you're using proper secrets management, you should provide TELEGRAM_WEBHOOK_SECRET in the environment file instead.
        webhook_secret = "whatever2";
      };
    };
    environmentFiles = [ secrets.tranquils-secrets.path ];
  };
}
```

### Signal

```nix
let
  inherit (config.sops) secrets;
in
{
  services.tranquil-pds = {
    enable = true;
    database.createLocally = true;
    settings = {
      server.hostname = "pds.example.com";
      # you must link a device using the admin API before enabling this option.
      signal.enabled = true;
    };
    environmentFiles = [ secrets.tranquils-secrets.path ];
  };
}
```

### No comms channel

If you have not set up any of these, you can technically still access any relevant information by querying the database directly.

Please keep in mind this is a last-ditch attempt and it is highly recommended that you do in fact specify some channel for communications.

Running `sudo -u tranquil-pds psql` will give you command line access to the PostgreSQL database.

From there, you can run `SELECT * FROM comms_queue;` which will return all communications sent from the PDS. From there, you can extract any relevant information.

## Bootstrap

When the PDS service is able to properly run for the first time, you will be given a bootstrap invite code to migrate your repository to this PDS.

The simplest way to find this invite code is to check the service logs by doing `journalctl -u tranquil-pds`.

The log entry shold look something like this:

`INFO tranquil_pds::state: No users exist and invite codes are required. Bootstrap invite code: <invite_code_here>`

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
