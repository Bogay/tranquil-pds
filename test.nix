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

    services.tranquil-pds = {
      enable = true;
      database.createLocally = true;
      secretsFile = pkgs.writeText "tranquil-secrets" ''
        JWT_SECRET=test-jwt-secret-must-be-32-chars-long
        DPOP_SECRET=test-dpop-secret-must-be-32-chars-long
        MASTER_KEY=test-master-key-must-be-32-chars-long
      '';

      nginx = {
        enable = true;
        enableACME = false;
      };

      settings = {
        server.pdsHostname = "test.local";
        server.host = "0.0.0.0";

        storage.blobBackend = "filesystem";
        rateLimiting.disable = true;
        security.allowInsecureSecrets = true;
      };
    };
  };

  testScript = ''
    import json

    server.wait_for_unit("postgresql.service")
    server.wait_for_unit("tranquil-pds.service")
    server.wait_for_unit("nginx.service")
    server.wait_for_open_port(3000)
    server.wait_for_open_port(80)

    def xrpc(method, endpoint, *, headers=None, data=None, raw_body=None, via="nginx"):
        host_header = "-H 'Host: test.local'" if via == "nginx" else ""
        base = "http://localhost" if via == "nginx" else "http://localhost:3000"
        url = f"{base}/xrpc/{endpoint}"

        parts = ["curl", "-sf", "-X", method, host_header]
        if headers:
            parts.extend(f"-H '{k}: {v}'" for k, v in headers.items())
        if data is not None:
            parts.append("-H 'Content-Type: application/json'")
            parts.append(f"-d '{json.dumps(data)}'")
        if raw_body:
            parts.append(f"--data-binary @{raw_body}")
        parts.append(f"'{url}'")

        return server.succeed(" ".join(parts))

    def xrpc_json(method, endpoint, **kwargs):
        return json.loads(xrpc(method, endpoint, **kwargs))

    def xrpc_status(endpoint, *, headers=None, via="nginx"):
        host_header = "-H 'Host: test.local'" if via == "nginx" else ""
        base = "http://localhost" if via == "nginx" else "http://localhost:3000"
        url = f"{base}/xrpc/{endpoint}"

        parts = ["curl", "-s", "-o", "/dev/null", "-w", "'%{http_code}'", host_header]
        if headers:
            parts.extend(f"-H '{k}: {v}'" for k, v in headers.items())
        parts.append(f"'{url}'")

        return server.succeed(" ".join(parts)).strip()

    def http_status(path, *, host="test.local", via="nginx"):
        base = "http://localhost" if via == "nginx" else "http://localhost:3000"
        return server.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' -H 'Host: {host}' '{base}{path}'"
        ).strip()

    def http_get(path, *, host="test.local"):
        return server.succeed(
            f"curl -sf -H 'Host: {host}' 'http://localhost{path}'"
        )

    def http_header(path, header, *, host="test.local"):
        return server.succeed(
            f"curl -sI -H 'Host: {host}' 'http://localhost{path}'"
            f" | grep -i '^{header}:'"
        ).strip()

    # --- testing that stuff is up in general ---

    with subtest("service is running"):
        status = server.succeed("systemctl is-active tranquil-pds")
        assert "active" in status

    with subtest("data directories exist"):
        server.succeed("test -d /var/lib/tranquil-pds/blobs")
        server.succeed("test -d /var/lib/tranquil-pds/backups")

    with subtest("postgres database created"):
        server.succeed("sudo -u tranquil-pds psql -d tranquil-pds -c 'SELECT 1'")

    with subtest("healthcheck via backend"):
        xrpc("GET", "_health", via="backend")

    with subtest("healthcheck via nginx"):
        xrpc("GET", "_health")

    with subtest("describeServer"):
        desc = xrpc_json("GET", "com.atproto.server.describeServer")
        assert "availableUserDomains" in desc
        assert "did" in desc
        assert desc.get("inviteCodeRequired") == False

    with subtest("nginx serves frontend"):
        result = server.succeed("curl -sf -H 'Host: test.local' http://localhost/")
        assert "<html" in result.lower() or "<!" in result

    with subtest("well-known proxied"):
        code = http_status("/.well-known/atproto-did")
        assert code != "502" and code != "504", f"well-known proxy broken: {code}"

    with subtest("health endpoint proxied"):
        code = http_status("/health")
        assert code != "404" and code != "502", f"/health not proxied: {code}"

    with subtest("robots.txt proxied"):
        code = http_status("/robots.txt")
        assert code != "404" and code != "502", f"/robots.txt not proxied: {code}"

    with subtest("metrics endpoint proxied"):
        code = http_status("/metrics")
        assert code != "502", f"/metrics not proxied: {code}"

    with subtest("oauth path proxied"):
        code = http_status("/oauth/.well-known/openid-configuration")
        assert code != "502" and code != "504", f"oauth proxy broken: {code}"

    with subtest("subdomain routing works"):
        code = http_status("/xrpc/_health", host="alice.test.local")
        assert code == "200", f"subdomain routing failed: {code}"

    with subtest("client-metadata.json served with host substitution"):
        meta_raw = http_get("/oauth/client-metadata.json")
        meta = json.loads(meta_raw)
        assert "client_id" in meta, f"no client_id in client-metadata: {meta}"
        assert "test.local" in meta_raw, "host substitution did not apply"

    with subtest("static assets location exists"):
        code = http_status("/assets/nonexistent.js")
        assert code == "404", f"expected 404 for missing asset, got {code}"

    with subtest("spa fallback works"):
        code = http_status("/app/some/deep/route")
        assert code == "200", f"SPA fallback broken: {code}"

    with subtest("firewall ports open"):
        server.succeed("ss -tlnp | grep ':80 '")
        server.succeed("ss -tlnp | grep ':3000 '")

    # --- test little bit of an account lifecycle ---

    with subtest("create account"):
        account = xrpc_json("POST", "com.atproto.server.createAccount", data={
            "handle": "alice.test.local",
            "password": "NixOS-Test-Pass-99!",
            "email": "alice@test.local",
            "didType": "web",
        })
        assert "accessJwt" in account, f"no accessJwt: {account}"
        assert "did" in account, f"no did: {account}"
        access_token = account["accessJwt"]
        did = account["did"]
        assert did.startswith("did:web:"), f"expected did:web, got {did}"

    with subtest("mark account verified"):
        server.succeed(
            f"sudo -u tranquil-pds psql -d tranquil-pds "
            f"-c \"UPDATE users SET email_verified = true WHERE did = '{did}'\""
        )

    auth = {"Authorization": f"Bearer {access_token}"}

    with subtest("get session"):
        session = xrpc_json("GET", "com.atproto.server.getSession", headers=auth)
        assert session["did"] == did
        assert session["handle"] == "alice.test.local"

    with subtest("create record"):
        created = xrpc_json("POST", "com.atproto.repo.createRecord", headers=auth, data={
            "repo": did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "hello from lewis silly nix integration test",
                "createdAt": "2025-01-01T00:00:00.000Z",
            },
        })
        assert "uri" in created, f"no uri: {created}"
        assert "cid" in created, f"no cid: {created}"
        record_uri = created["uri"]
        record_cid = created["cid"]
        rkey = record_uri.split("/")[-1]

    with subtest("read record back"):
        fetched = xrpc_json(
            "GET",
            f"com.atproto.repo.getRecord?repo={did}&collection=app.bsky.feed.post&rkey={rkey}",
        )
        assert fetched["uri"] == record_uri
        assert fetched["cid"] == record_cid
        assert fetched["value"]["text"] == "hello from lewis silly nix integration test"

    with subtest("upload blob"):
        server.succeed("dd if=/dev/urandom bs=1024 count=4 of=/tmp/testblob.bin 2>/dev/null")
        blob_resp = xrpc_json(
            "POST",
            "com.atproto.repo.uploadBlob",
            headers={**auth, "Content-Type": "application/octet-stream"},
            raw_body="/tmp/testblob.bin",
        )
        assert "blob" in blob_resp, f"no blob: {blob_resp}"
        blob_ref = blob_resp["blob"]
        assert blob_ref["size"] == 4096

    with subtest("export repo as car"):
        server.succeed(
            f"curl -sf -H 'Host: test.local' "
            f"-o /tmp/repo.car "
            f"'http://localhost/xrpc/com.atproto.sync.getRepo?did={did}'"
        )
        size = int(server.succeed("stat -c%s /tmp/repo.car").strip())
        assert size > 0, "exported car is empty"

    with subtest("delete record"):
        xrpc_json("POST", "com.atproto.repo.deleteRecord", headers=auth, data={
            "repo": did,
            "collection": "app.bsky.feed.post",
            "rkey": rkey,
        })

    with subtest("deleted record gone"):
        code = xrpc_status(
            f"com.atproto.repo.getRecord?repo={did}&collection=app.bsky.feed.post&rkey={rkey}",
        )
        assert code != "200", f"expected non-200 for deleted record, got {code}"

    with subtest("service still healthy after lifecycle"):
        xrpc("GET", "_health")
  '';
}
