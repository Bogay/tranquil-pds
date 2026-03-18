import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  AtprotoClient,
  buildOAuthAuthorizationUrl,
  clearDPoPKey,
  generateDPoPKeyPair,
  getMigrationOAuthClientId,
  getMigrationOAuthRedirectUri,
  loadDPoPKey,
  saveDPoPKey,
} from "../../lib/migration/atproto-client.ts";
import type { OAuthServerMetadata } from "../../lib/migration/types.ts";

const DPOP_KEY_STORAGE = "migration_dpop_key";

describe("migration/atproto-client", () => {
  beforeEach(() => {
    localStorage.removeItem(DPOP_KEY_STORAGE);
  });

  describe("buildOAuthAuthorizationUrl", () => {
    const mockMetadata: OAuthServerMetadata = {
      issuer: "https://bsky.social",
      authorization_endpoint: "https://bsky.social/oauth/authorize",
      token_endpoint: "https://bsky.social/oauth/token",
      scopes_supported: ["atproto"],
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      dpop_signing_alg_values_supported: ["ES256"],
    };

    it("builds authorization URL with required parameters", () => {
      const url = buildOAuthAuthorizationUrl(mockMetadata, {
        clientId: "https://example.com/oauth-client-metadata.json",
        redirectUri: "https://example.com/migrate",
        codeChallenge: "abc123",
        state: "state123",
      });

      const parsed = new URL(url);
      expect(parsed.origin).toBe("https://bsky.social");
      expect(parsed.pathname).toBe("/oauth/authorize");
      expect(parsed.searchParams.get("response_type")).toBe("code");
      expect(parsed.searchParams.get("client_id")).toBe(
        "https://example.com/oauth-client-metadata.json",
      );
      expect(parsed.searchParams.get("redirect_uri")).toBe(
        "https://example.com/migrate",
      );
      expect(parsed.searchParams.get("code_challenge")).toBe("abc123");
      expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
      expect(parsed.searchParams.get("state")).toBe("state123");
    });

    it("includes default scope when not specified", () => {
      const url = buildOAuthAuthorizationUrl(mockMetadata, {
        clientId: "client",
        redirectUri: "redirect",
        codeChallenge: "challenge",
        state: "state",
      });

      const parsed = new URL(url);
      expect(parsed.searchParams.get("scope")).toBe("atproto");
    });

    it("includes custom scope when specified", () => {
      const url = buildOAuthAuthorizationUrl(mockMetadata, {
        clientId: "client",
        redirectUri: "redirect",
        codeChallenge: "challenge",
        state: "state",
        scope: "atproto identity:*",
      });

      const parsed = new URL(url);
      expect(parsed.searchParams.get("scope")).toBe("atproto identity:*");
    });

    it("includes dpop_jkt when specified", () => {
      const url = buildOAuthAuthorizationUrl(mockMetadata, {
        clientId: "client",
        redirectUri: "redirect",
        codeChallenge: "challenge",
        state: "state",
        dpopJkt: "dpop-thumbprint-123",
      });

      const parsed = new URL(url);
      expect(parsed.searchParams.get("dpop_jkt")).toBe("dpop-thumbprint-123");
    });

    it("includes login_hint when specified", () => {
      const url = buildOAuthAuthorizationUrl(mockMetadata, {
        clientId: "client",
        redirectUri: "redirect",
        codeChallenge: "challenge",
        state: "state",
        loginHint: "alice.bsky.social",
      });

      const parsed = new URL(url);
      expect(parsed.searchParams.get("login_hint")).toBe("alice.bsky.social");
    });

    it("omits optional params when not specified", () => {
      const url = buildOAuthAuthorizationUrl(mockMetadata, {
        clientId: "client",
        redirectUri: "redirect",
        codeChallenge: "challenge",
        state: "state",
      });

      const parsed = new URL(url);
      expect(parsed.searchParams.has("dpop_jkt")).toBe(false);
      expect(parsed.searchParams.has("login_hint")).toBe(false);
    });
  });

  describe("getMigrationOAuthClientId", () => {
    it("returns client metadata URL based on origin", () => {
      const clientId = getMigrationOAuthClientId();
      expect(clientId).toBe(
        `${globalThis.location.origin}/oauth-client-metadata.json`,
      );
    });
  });

  describe("getMigrationOAuthRedirectUri", () => {
    it("returns migrate path based on origin", () => {
      const redirectUri = getMigrationOAuthRedirectUri();
      expect(redirectUri).toBe(`${globalThis.location.origin}/app/migrate`);
    });
  });

  describe("DPoP key management", () => {
    describe("generateDPoPKeyPair", () => {
      it("generates a valid key pair", async () => {
        const keyPair = await generateDPoPKeyPair();

        expect(keyPair.privateKey).toBeDefined();
        expect(keyPair.publicKey).toBeDefined();
        expect(keyPair.jwk).toBeDefined();
        expect(keyPair.thumbprint).toBeDefined();
      });

      it("generates ES256 (P-256) keys", async () => {
        const keyPair = await generateDPoPKeyPair();

        expect(keyPair.jwk.kty).toBe("EC");
        expect(keyPair.jwk.crv).toBe("P-256");
        expect(keyPair.jwk.x).toBeDefined();
        expect(keyPair.jwk.y).toBeDefined();
      });

      it("generates URL-safe thumbprint", async () => {
        const keyPair = await generateDPoPKeyPair();

        expect(keyPair.thumbprint).toMatch(/^[A-Za-z0-9_-]+$/);
      });

      it("generates different keys each time", async () => {
        const keyPair1 = await generateDPoPKeyPair();
        const keyPair2 = await generateDPoPKeyPair();

        expect(keyPair1.thumbprint).not.toBe(keyPair2.thumbprint);
      });
    });

    describe("saveDPoPKey", () => {
      it("saves key pair to localStorage", async () => {
        const keyPair = await generateDPoPKeyPair();

        await saveDPoPKey(keyPair);

        expect(localStorage.getItem(DPOP_KEY_STORAGE)).not.toBeNull();
      });

      it("stores private and public JWK", async () => {
        const keyPair = await generateDPoPKeyPair();

        await saveDPoPKey(keyPair);

        const stored = JSON.parse(localStorage.getItem(DPOP_KEY_STORAGE)!);
        expect(stored.privateJwk).toBeDefined();
        expect(stored.publicJwk).toBeDefined();
        expect(stored.thumbprint).toBe(keyPair.thumbprint);
      });

      it("stores creation timestamp", async () => {
        const before = Date.now();
        const keyPair = await generateDPoPKeyPair();
        await saveDPoPKey(keyPair);
        const after = Date.now();

        const stored = JSON.parse(localStorage.getItem(DPOP_KEY_STORAGE)!);
        expect(stored.createdAt).toBeGreaterThanOrEqual(before);
        expect(stored.createdAt).toBeLessThanOrEqual(after);
      });
    });

    describe("loadDPoPKey", () => {
      it("returns null when no key stored", async () => {
        const keyPair = await loadDPoPKey();
        expect(keyPair).toBeNull();
      });

      it("loads stored key pair", async () => {
        const original = await generateDPoPKeyPair();
        await saveDPoPKey(original);

        const loaded = await loadDPoPKey();

        expect(loaded).not.toBeNull();
        expect(loaded!.thumbprint).toBe(original.thumbprint);
      });

      it("returns null and clears storage for expired key (> 24 hours)", async () => {
        const stored = {
          privateJwk: {
            kty: "EC",
            crv: "P-256",
            x: "test",
            y: "test",
            d: "test",
          },
          publicJwk: { kty: "EC", crv: "P-256", x: "test", y: "test" },
          thumbprint: "test-thumb",
          createdAt: Date.now() - 25 * 60 * 60 * 1000,
        };
        localStorage.setItem(DPOP_KEY_STORAGE, JSON.stringify(stored));

        const loaded = await loadDPoPKey();

        expect(loaded).toBeNull();
        expect(localStorage.getItem(DPOP_KEY_STORAGE)).toBeNull();
      });

      it("returns null and clears storage for invalid data", async () => {
        localStorage.setItem(DPOP_KEY_STORAGE, "not-valid-json");

        const loaded = await loadDPoPKey();

        expect(loaded).toBeNull();
        expect(localStorage.getItem(DPOP_KEY_STORAGE)).toBeNull();
      });
    });

    describe("clearDPoPKey", () => {
      it("removes key from localStorage", async () => {
        const keyPair = await generateDPoPKeyPair();
        await saveDPoPKey(keyPair);
        expect(localStorage.getItem(DPOP_KEY_STORAGE)).not.toBeNull();

        clearDPoPKey();

        expect(localStorage.getItem(DPOP_KEY_STORAGE)).toBeNull();
      });

      it("does not throw when nothing to clear", () => {
        expect(() => clearDPoPKey()).not.toThrow();
      });
    });
  });

  describe("AtprotoClient.verifyHandleOwnership", () => {
    function createMockJsonResponse(data: unknown, status = 200) {
      return new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    }

    it("sends POST with handle and did", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockJsonResponse({ verified: true, method: "dns" }),
      );

      const client = new AtprotoClient("https://pds.example.com");
      await client.verifyHandleOwnership("alice.custom.com", "did:plc:abc123");

      expect(fetch).toHaveBeenCalledWith(
        "https://pds.example.com/xrpc/_identity.verifyHandleOwnership",
        expect.objectContaining({
          method: "POST",
        }),
      );
    });

    it("returns verified result with method", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockJsonResponse({ verified: true, method: "dns" }),
      );

      const client = new AtprotoClient("https://pds.example.com");
      const result = await client.verifyHandleOwnership(
        "alice.custom.com",
        "did:plc:abc123",
      );

      expect(result.verified).toBe(true);
      expect(result.method).toBe("dns");
    });

    it("returns unverified result with error", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockJsonResponse({
          verified: false,
          error: "Handle resolution failed",
        }),
      );

      const client = new AtprotoClient("https://pds.example.com");
      const result = await client.verifyHandleOwnership(
        "nonexistent.example.com",
        "did:plc:abc123",
      );

      expect(result.verified).toBe(false);
      expect(result.error).toBe("Handle resolution failed");
    });

    it("throws on server error responses", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockJsonResponse(
          { error: "InvalidHandle", message: "Invalid handle format" },
          400,
        ),
      );

      const client = new AtprotoClient("https://pds.example.com");
      await expect(
        client.verifyHandleOwnership("@#$!", "did:plc:abc123"),
      ).rejects.toThrow("Invalid handle format");
    });

    it("strips trailing slash from base URL", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockJsonResponse({ verified: true, method: "http" }),
      );

      const client = new AtprotoClient("https://pds.example.com/");
      await client.verifyHandleOwnership("alice.example.com", "did:plc:abc");

      expect(fetch).toHaveBeenCalledWith(
        "https://pds.example.com/xrpc/_identity.verifyHandleOwnership",
        expect.anything(),
      );
    });
  });
});
