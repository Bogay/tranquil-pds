self: {
  lib,
  pkgs,
  config,
  ...
}: let
  cfg = config.services.tranquil-pds;

  inherit (lib) types mkOption;

  settingsFormat = pkgs.formats.toml { };

  backendUrl = "http://127.0.0.1:${toString cfg.settings.server.port}";

  useACME = cfg.nginx.enableACME && cfg.nginx.useACMEHost == null;
  hasSSL = useACME || cfg.nginx.useACMEHost != null;
in {
  _class = "nixos";

  options.services.tranquil-pds = {
    enable = lib.mkEnableOption "tranquil-pds AT Protocol personal data server";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.tranquil-pds;
      defaultText = lib.literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.tranquil-pds";
      description = "The tranquil-pds package to use";
    };

    user = mkOption {
      type = types.str;
      default = "tranquil-pds";
      description = "User under which tranquil-pds runs";
    };

    group = mkOption {
      type = types.str;
      default = "tranquil-pds";
      description = "Group under which tranquil-pds runs";
    };

    dataDir = mkOption {
      type = types.str;
      default = "/var/lib/tranquil-pds";
      description = "Directory for tranquil-pds data (blobs, backups)";
    };

    environmentFiles = mkOption {
      type = types.listOf types.path;
      default = [ ];
      description = ''
        File to load environment variables from. Loaded variables override
        values set in {option}`environment`.

        Use it to set values of `JWT_SECRET`, `DPOP_SECRET` and `MASTER_KEY`.

        Generate these with:
        ```
        openssl rand --hex 32
        ```
      '';
    };

    database.createLocally = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Create the postgres database and user on the local host.
      '';
    };

    frontend.package = mkOption {
      type = types.nullOr types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.tranquil-frontend;
      defaultText = lib.literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.tranquil-frontend";
      description = "Frontend package to serve via nginx (set null to disable frontend)";
    };

    nginx = {
      enable = lib.mkEnableOption "nginx reverse proxy for tranquil-pds";

      enableACME = mkOption {
        type = types.bool;
        default = true;
        description = "Enable ACME for the pds domain";
      };

      useACMEHost = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Use a pre-configured ACME certificate instead of generating one.
          Set this to the cert name from security.acme.certs for wildcard setups.

          REMEMBER: Handle subdomains (*.pds.example.com) require a wildcard cert via DNS-01.
        '';
      };
    };

    settings = mkOption {
      type = types.submodule {
        freeformType = settingsFormat.type;

        options = {
          server = {
            host = mkOption {
              type = types.str;
              default = "127.0.0.1";
              description = "Host for tranquil-pds to listen on";
            };

            port = mkOption {
              type = types.int;
              default = 3000;
              description = "Port for tranquil-pds to listen on";
            };

            hostname = mkOption {
              type = types.str;
              default = "";
              example = "pds.example.com";
              description = "The public-facing hostname of the PDS";
            };

            max_blob_size = mkOption {
              type = types.int;
              default = 10737418240; # 10 GiB
              description = "Maximum allowed blob size in bytes.";
            };
          };

          storage = {
            path = mkOption {
              type = types.path;
              default = "/var/lib/tranquil-pds/blobs";
              description = "Directory for storing blobs";
            };
          };

          backup = {
            path = mkOption {
              type = types.path;
              default = "/var/lib/tranquil-pds/backups";
              description = "Directory for storing backups";
            };
          };

          email = {
            sendmail_path = mkOption {
              type = types.path;
              default = lib.getExe pkgs.system-sendmail;
              description = "Path to the sendmail executable to use for sending emails.";
            };
          };

          signal = {
            cli_path = mkOption {
              type = types.path;
              default = lib.getExe pkgs.signal-cli;
              description = "Path to the signal-cli executable to use for sending Signal notifications.";
            };
          };
        };
      };

      description = ''
        Configuration options to set for the service. Secrets should be
        specified using {option}`environmentFile`.

        Refer to <https://tangled.org/tranquil.farm/tranquil-pds/blob/main/example.toml>
        for available configuration options.
      '';
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      (lib.mkIf cfg.database.createLocally {
        services.postgresql = {
          enable = true;
          ensureDatabases = [ cfg.user ];
          ensureUsers = [
            {
              name = cfg.user;
              ensureDBOwnership = true;
            }
          ];
        };

        services.tranquil-pds.settings.database.url =
          lib.mkDefault "postgresql:///${cfg.user}?host=/run/postgresql";

        systemd.services.tranquil-pds = {
          requires = [ "postgresql.service" ];
          after = [ "postgresql.service" ];
        };
      })

      (lib.mkIf cfg.nginx.enable {
        services.nginx = {
          enable = true;

          virtualHosts.${cfg.settings.server.hostname} = {
            serverAliases = [ "*.${cfg.settings.server.hostname}" ];
            forceSSL = hasSSL;
            enableACME = useACME;
            useACMEHost = cfg.nginx.useACMEHost;

            root = lib.mkIf (cfg.frontend.package != null) cfg.frontend.package;

            extraConfig = "client_max_body_size ${toString cfg.settings.server.max_blob_size};";

            locations = lib.mkMerge [
              {
                "/xrpc/" = {
                  proxyPass = backendUrl;
                  proxyWebsockets = true;
                  extraConfig = ''
                    proxy_read_timeout 86400;
                    proxy_send_timeout 86400;
                    proxy_buffering off;
                    proxy_request_buffering off;
                  '';
                };

                "/oauth/" = {
                  proxyPass = backendUrl;
                  extraConfig = ''
                    proxy_read_timeout 300;
                    proxy_send_timeout 300;
                  '';
                };

                "/.well-known/" = {
                  proxyPass = backendUrl;
                };

                "/webhook/" = {
                  proxyPass = backendUrl;
                };

                "= /metrics" = {
                  proxyPass = backendUrl;
                };

                "= /health" = {
                  proxyPass = backendUrl;
                };

                "= /robots.txt" = {
                  proxyPass = backendUrl;
                };

                "= /logo" = {
                  proxyPass = backendUrl;
                };

                "~ ^/u/[^/]+/did\\.json$" = {
                  proxyPass = backendUrl;
                };
              }

              (lib.optionalAttrs (cfg.frontend.package != null) {
                "= /oauth/client-metadata.json" = {
                  root = "${cfg.frontend.package}";
                  extraConfig = ''
                    default_type application/json;
                    sub_filter_once off;
                    sub_filter_types application/json;
                    sub_filter '__PDS_HOSTNAME__' $host;
                  '';
                };

                "/assets/" = {
                  # TODO: use `add_header_inherit` when nixpkgs updates to nginx 1.29.3+
                  extraConfig = ''
                    expires 1y;
                    add_header Cache-Control "public, immutable";
                  '';
                  tryFiles = "$uri =404";
                };

                "/app/" = {
                  tryFiles = "$uri $uri/ /index.html";
                };

                "= /" = {
                  tryFiles = "/homepage.html /index.html";
                };

                "/" = {
                  tryFiles = "$uri $uri/ /index.html";
                  priority = 9999;
                };
              })
            ];
          };
        };
      })

      {
        users.users.${cfg.user} = {
          isSystemUser = true;
          inherit (cfg) group;
          home = cfg.dataDir;
        };

        users.groups.${cfg.group} = { };

        systemd.tmpfiles.settings."tranquil-pds" =
          lib.genAttrs
            [
              cfg.dataDir
              cfg.settings.storage.path
              cfg.settings.backup.path
            ]
            (_: {
              d = {
                mode = "0750";
                inherit (cfg) user group;
              };
            });

        environment.etc = {
          "tranquil-pds/config.toml".source = settingsFormat.generate "tranquil-pds.toml" cfg.settings;
        };

        systemd.services.tranquil-pds = {
          description = "Tranquil PDS - AT Protocol Personal Data Server";
          after = [ "network-online.target" ];
          wants = [ "network-online.target" ];
          wantedBy = [ "multi-user.target" ];

          serviceConfig = {
            User = cfg.user;
            Group = cfg.group;
            ExecStart = lib.getExe cfg.package;
            Restart = "on-failure";
            RestartSec = 5;

            WorkingDirectory = cfg.dataDir;
            StateDirectory = "tranquil-pds";

            EnvironmentFile = cfg.environmentFiles;

            NoNewPrivileges = true;
            ProtectSystem = "strict";
            ProtectHome = true;
            PrivateTmp = true;
            PrivateDevices = true;
            ProtectKernelTunables = true;
            ProtectKernelModules = true;
            ProtectControlGroups = true;
            RestrictAddressFamilies = [
              "AF_INET"
              "AF_INET6"
              "AF_UNIX"
            ];
            RestrictNamespaces = true;
            LockPersonality = true;
            MemoryDenyWriteExecute = true;
            RestrictRealtime = true;
            RestrictSUIDSGID = true;
            RemoveIPC = true;

            ReadWritePaths = [
              cfg.settings.storage.path
              cfg.settings.backup.path
            ];
          };
        };
      }
    ]
  );
}
