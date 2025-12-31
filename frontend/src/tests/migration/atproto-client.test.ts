import { beforeEach, describe, expect, it } from "vitest";
import {
  base64UrlDecode,
  base64UrlEncode,
  buildOAuthAuthorizationUrl,
  clearDPoPKey,
  generateDPoPKeyPair,
  generateOAuthState,
  generatePKCE,
  getMigrationOAuthClientId,
  getMigrationOAuthRedirectUri,
  loadDPoPKey,
  prepareWebAuthnCreationOptions,
  saveDPoPKey,
} from "../../lib/migration/atproto-client";
import type { OAuthServerMetadata } from "../../lib/migration/types";

const DPOP_KEY_STORAGE = "migration_dpop_key";

describe("migration/atproto-client", () => {
  beforeEach(() => {
    localStorage.removeItem(DPOP_KEY_STORAGE);
  });

  describe("base64UrlEncode", () => {
    it("encodes empty buffer", () => {
      const result = base64UrlEncode(new Uint8Array([]));
      expect(result).toBe("");
    });

    it("encodes simple data", () => {
      const data = new TextEncoder().encode("hello");
      const result = base64UrlEncode(data);
      expect(result).toBe("aGVsbG8");
    });

    it("uses URL-safe characters (no +, /, or =)", () => {
      const data = new Uint8Array([251, 255, 254]);
      const result = base64UrlEncode(data);
      expect(result).not.toContain("+");
      expect(result).not.toContain("/");
      expect(result).not.toContain("=");
    });

    it("replaces + with -", () => {
      const data = new Uint8Array([251]);
      const result = base64UrlEncode(data);
      expect(result).toContain("-");
    });

    it("replaces / with _", () => {
      const data = new Uint8Array([255]);
      const result = base64UrlEncode(data);
      expect(result).toContain("_");
    });

    it("accepts ArrayBuffer", () => {
      const arrayBuffer = new ArrayBuffer(4);
      const view = new Uint8Array(arrayBuffer);
      view[0] = 116; // t
      view[1] = 101; // e
      view[2] = 115; // s
      view[3] = 116; // t
      const result = base64UrlEncode(arrayBuffer);
      expect(result).toBe("dGVzdA");
    });
  });

  describe("base64UrlDecode", () => {
    it("decodes empty string", () => {
      const result = base64UrlDecode("");
      expect(result.length).toBe(0);
    });

    it("decodes URL-safe base64", () => {
      const result = base64UrlDecode("aGVsbG8");
      expect(new TextDecoder().decode(result)).toBe("hello");
    });

    it("handles - and _ characters", () => {
      const encoded = base64UrlEncode(new Uint8Array([251, 255, 254]));
      const decoded = base64UrlDecode(encoded);
      expect(decoded).toEqual(new Uint8Array([251, 255, 254]));
    });

    it("is inverse of base64UrlEncode", () => {
      const original = new Uint8Array([0, 1, 2, 255, 254, 253]);
      const encoded = base64UrlEncode(original);
      const decoded = base64UrlDecode(encoded);
      expect(decoded).toEqual(original);
    });

    it("handles missing padding", () => {
      const result = base64UrlDecode("YQ");
      expect(new TextDecoder().decode(result)).toBe("a");
    });
  });

  describe("generateOAuthState", () => {
    it("generates a non-empty string", () => {
      const state = generateOAuthState();
      expect(state).toBeTruthy();
      expect(typeof state).toBe("string");
    });

    it("generates URL-safe characters only", () => {
      const state = generateOAuthState();
      expect(state).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it("generates different values each time", () => {
      const state1 = generateOAuthState();
      const state2 = generateOAuthState();
      expect(state1).not.toBe(state2);
    });
  });

  describe("generatePKCE", () => {
    it("generates code_verifier and code_challenge", async () => {
      const pkce = await generatePKCE();
      expect(pkce.codeVerifier).toBeTruthy();
      expect(pkce.codeChallenge).toBeTruthy();
    });

    it("generates URL-safe code_verifier", async () => {
      const pkce = await generatePKCE();
      expect(pkce.codeVerifier).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it("generates URL-safe code_challenge", async () => {
      const pkce = await generatePKCE();
      expect(pkce.codeChallenge).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it("code_challenge is SHA-256 hash of code_verifier", async () => {
      const pkce = await generatePKCE();

      const encoder = new TextEncoder();
      const data = encoder.encode(pkce.codeVerifier);
      const digest = await crypto.subtle.digest("SHA-256", data);
      const expectedChallenge = base64UrlEncode(new Uint8Array(digest));

      expect(pkce.codeChallenge).toBe(expectedChallenge);
    });

    it("generates different values each time", async () => {
      const pkce1 = await generatePKCE();
      const pkce2 = await generatePKCE();
      expect(pkce1.codeVerifier).not.toBe(pkce2.codeVerifier);
      expect(pkce1.codeChallenge).not.toBe(pkce2.codeChallenge);
    });
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
        clientId: "https://example.com/oauth/client-metadata.json",
        redirectUri: "https://example.com/migrate",
        codeChallenge: "abc123",
        state: "state123",
      });

      const parsed = new URL(url);
      expect(parsed.origin).toBe("https://bsky.social");
      expect(parsed.pathname).toBe("/oauth/authorize");
      expect(parsed.searchParams.get("response_type")).toBe("code");
      expect(parsed.searchParams.get("client_id")).toBe(
        "https://example.com/oauth/client-metadata.json",
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
        `${globalThis.location.origin}/oauth/client-metadata.json`,
      );
    });
  });

  describe("getMigrationOAuthRedirectUri", () => {
    it("returns migrate path based on origin", () => {
      const redirectUri = getMigrationOAuthRedirectUri();
      expect(redirectUri).toBe(`${globalThis.location.origin}/migrate`);
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

  describe("prepareWebAuthnCreationOptions", () => {
    it("decodes challenge from base64url", () => {
      const options = {
        publicKey: {
          challenge: "dGVzdC1jaGFsbGVuZ2U",
          user: {
            id: "dXNlci1pZA",
            name: "test@example.com",
            displayName: "Test User",
          },
          excludeCredentials: [],
          rp: { name: "Test" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        },
      };

      const prepared = prepareWebAuthnCreationOptions(options);

      expect(prepared.challenge).toBeInstanceOf(Uint8Array);
      expect(new TextDecoder().decode(prepared.challenge as Uint8Array)).toBe(
        "test-challenge",
      );
    });

    it("decodes user.id from base64url", () => {
      const options = {
        publicKey: {
          challenge: "Y2hhbGxlbmdl",
          user: {
            id: "dXNlci1pZA",
            name: "test@example.com",
            displayName: "Test User",
          },
          excludeCredentials: [],
          rp: { name: "Test" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        },
      };

      const prepared = prepareWebAuthnCreationOptions(options);

      expect(prepared.user?.id).toBeInstanceOf(Uint8Array);
      expect(new TextDecoder().decode(prepared.user?.id as Uint8Array)).toBe(
        "user-id",
      );
    });

    it("decodes excludeCredentials ids from base64url", () => {
      const options = {
        publicKey: {
          challenge: "Y2hhbGxlbmdl",
          user: {
            id: "dXNlcg",
            name: "test@example.com",
            displayName: "Test User",
          },
          excludeCredentials: [
            { id: "Y3JlZDE", type: "public-key" },
            { id: "Y3JlZDI", type: "public-key" },
          ],
          rp: { name: "Test" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        },
      };

      const prepared = prepareWebAuthnCreationOptions(options);

      expect(prepared.excludeCredentials).toHaveLength(2);
      expect(
        new TextDecoder().decode(
          prepared.excludeCredentials![0].id as Uint8Array,
        ),
      ).toBe("cred1");
      expect(
        new TextDecoder().decode(
          prepared.excludeCredentials![1].id as Uint8Array,
        ),
      ).toBe("cred2");
    });

    it("handles empty excludeCredentials", () => {
      const options = {
        publicKey: {
          challenge: "Y2hhbGxlbmdl",
          user: {
            id: "dXNlcg",
            name: "test@example.com",
            displayName: "Test User",
          },
          rp: { name: "Test" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        },
      };

      const prepared = prepareWebAuthnCreationOptions(options);

      expect(prepared.excludeCredentials).toEqual([]);
    });

    it("preserves other user properties", () => {
      const options = {
        publicKey: {
          challenge: "Y2hhbGxlbmdl",
          user: {
            id: "dXNlcg",
            name: "test@example.com",
            displayName: "Test User",
          },
          excludeCredentials: [],
          rp: { name: "Test" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        },
      };

      const prepared = prepareWebAuthnCreationOptions(options);

      expect(prepared.user?.name).toBe("test@example.com");
      expect(prepared.user?.displayName).toBe("Test User");
    });
  });
});
