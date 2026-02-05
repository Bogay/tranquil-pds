{
  pkgs,
  self,
  ...
}:
pkgs.testers.nixosTest {
  name = "tranquil-pds";

  nodes.server = {
    config,
    pkgs,
    ...
  }: {
    imports = [self.nixosModules.default];

    services.postgresql = {
      enable = true;
      ensureDatabases = ["tranquil"];
      ensureUsers = [
        {
          name = "tranquil";
          ensureDBOwnership = true;
        }
      ];
      authentication = ''
        local all all trust
        host all all 127.0.0.1/32 trust
        host all all ::1/128 trust
      '';
    };

    services.tranquil-pds = {
      enable = true;
      package = self.packages.${pkgs.stdenv.hostPlatform.system}.tranquil-pds;
      secretsFile = pkgs.writeText "tranquil-secrets" ''
        JWT_SECRET=test-jwt-secret-must-be-32-chars-long
        DPOP_SECRET=test-dpop-secret-must-be-32-chars-long
        MASTER_KEY=test-master-key-must-be-32-chars-long
      '';

      settings = {
        server.pdsHostname = "test.local";
        server.host = "0.0.0.0";

        database.url = "postgres://tranquil@localhost/tranquil";

        storage.blobBackend = "filesystem";
        backup.backend = "filesystem";
      };
    };

    networking.firewall.allowedTCPPorts = [3000];
  };

  testScript = ''
    server.wait_for_unit("postgresql.service")
    server.wait_for_unit("tranquil-pds.service")
    server.wait_for_open_port(3000)

    with subtest("service is running"):
        status = server.succeed("systemctl is-active tranquil-pds")
        assert "active" in status

    with subtest("blob storage directory exists"):
        server.succeed("test -d /var/lib/tranquil-pds/blobs")
        server.succeed("test -d /var/lib/tranquil-pds/backups")

    with subtest("healthcheck responds"):
        server.succeed("curl -sf http://localhost:3000/xrpc/_health")

    with subtest("describeServer returns valid response"):
        result = server.succeed("curl -sf http://localhost:3000/xrpc/com.atproto.server.describeServer")
        assert "availableUserDomains" in result
  '';
}
