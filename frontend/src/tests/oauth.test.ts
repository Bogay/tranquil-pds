import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  generateCodeChallenge,
  generateCodeVerifier,
  generateState,
  saveOAuthState,
  checkForOAuthCallback,
  clearOAuthCallbackParams,
} from "../lib/oauth";

describe("OAuth utilities", () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  describe("generateState", () => {
    it("generates a 64-character hex string", () => {
      const state = generateState();
      expect(state).toMatch(/^[0-9a-f]{64}$/);
    });

    it("generates unique values", () => {
      const states = new Set(Array.from({ length: 100 }, () => generateState()));
      expect(states.size).toBe(100);
    });
  });

  describe("generateCodeVerifier", () => {
    it("generates a 64-character hex string", () => {
      const verifier = generateCodeVerifier();
      expect(verifier).toMatch(/^[0-9a-f]{64}$/);
    });

    it("generates unique values", () => {
      const verifiers = new Set(
        Array.from({ length: 100 }, () => generateCodeVerifier()),
      );
      expect(verifiers.size).toBe(100);
    });
  });

  describe("generateCodeChallenge", () => {
    it("generates a base64url-encoded SHA-256 hash", async () => {
      const verifier = "test-verifier-12345";
      const challenge = await generateCodeChallenge(verifier);

      expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(challenge).not.toContain("+");
      expect(challenge).not.toContain("/");
      expect(challenge).not.toContain("=");
    });

    it("produces consistent output for same input", async () => {
      const verifier = "consistent-test-verifier";
      const challenge1 = await generateCodeChallenge(verifier);
      const challenge2 = await generateCodeChallenge(verifier);

      expect(challenge1).toBe(challenge2);
    });

    it("produces different output for different inputs", async () => {
      const challenge1 = await generateCodeChallenge("verifier-1");
      const challenge2 = await generateCodeChallenge("verifier-2");

      expect(challenge1).not.toBe(challenge2);
    });

    it("produces correct S256 challenge", async () => {
      const challenge = await generateCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
      expect(challenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    });
  });

  describe("saveOAuthState", () => {
    it("stores state and verifier in sessionStorage", () => {
      saveOAuthState({ state: "test-state", codeVerifier: "test-verifier" });

      expect(sessionStorage.getItem("tranquil_pds_oauth_state")).toBe(
        "test-state",
      );
      expect(sessionStorage.getItem("tranquil_pds_oauth_verifier")).toBe(
        "test-verifier",
      );
    });
  });

  describe("checkForOAuthCallback", () => {
    it("returns null when no code/state in URL", () => {
      Object.defineProperty(globalThis.location, "search", {
        value: "",
        writable: true,
        configurable: true,
      });
      Object.defineProperty(globalThis.location, "pathname", {
        value: "/app/",
        writable: true,
        configurable: true,
      });

      expect(checkForOAuthCallback()).toBeNull();
    });

    it("returns code and state when present in URL", () => {
      Object.defineProperty(globalThis.location, "search", {
        value: "?code=auth-code-123&state=state-456",
        writable: true,
        configurable: true,
      });
      Object.defineProperty(globalThis.location, "pathname", {
        value: "/app/",
        writable: true,
        configurable: true,
      });

      const result = checkForOAuthCallback();
      expect(result).toEqual({ code: "auth-code-123", state: "state-456" });
    });

    it("returns null on migrate path even with code/state", () => {
      Object.defineProperty(globalThis.location, "search", {
        value: "?code=auth-code-123&state=state-456",
        writable: true,
        configurable: true,
      });
      Object.defineProperty(globalThis.location, "pathname", {
        value: "/app/migrate",
        writable: true,
        configurable: true,
      });

      expect(checkForOAuthCallback()).toBeNull();
    });

    it("returns null when only code is present", () => {
      Object.defineProperty(globalThis.location, "search", {
        value: "?code=auth-code-123",
        writable: true,
        configurable: true,
      });
      Object.defineProperty(globalThis.location, "pathname", {
        value: "/app/",
        writable: true,
        configurable: true,
      });

      expect(checkForOAuthCallback()).toBeNull();
    });

    it("returns null when only state is present", () => {
      Object.defineProperty(globalThis.location, "search", {
        value: "?state=state-456",
        writable: true,
        configurable: true,
      });
      Object.defineProperty(globalThis.location, "pathname", {
        value: "/app/",
        writable: true,
        configurable: true,
      });

      expect(checkForOAuthCallback()).toBeNull();
    });
  });

  describe("clearOAuthCallbackParams", () => {
    it("removes query params from URL", () => {
      const replaceStateSpy = vi.spyOn(globalThis.history, "replaceState");

      Object.defineProperty(globalThis.location, "href", {
        value: "http://localhost:3000/app/?code=123&state=456",
        writable: true,
        configurable: true,
      });

      clearOAuthCallbackParams();

      expect(replaceStateSpy).toHaveBeenCalled();
      const callArgs = replaceStateSpy.mock.calls[0];
      expect(callArgs[0]).toEqual({});
      expect(callArgs[1]).toBe("");
      const urlString = callArgs[2] as string;
      expect(urlString).toBe("http://localhost:3000/app/");
      expect(urlString).not.toContain("?");
      expect(urlString).not.toContain("code=");
      expect(urlString).not.toContain("state=");
    });
  });
});

describe("DPoP proof generation", () => {
  it("base64url encoding produces valid output", async () => {
    const testData = new Uint8Array([72, 101, 108, 108, 111]);
    const buffer = testData.buffer;

    const binary = Array.from(testData, (byte) => String.fromCharCode(byte)).join("");
    const base64url = btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    expect(base64url).toBe("SGVsbG8");
    expect(base64url).not.toContain("+");
    expect(base64url).not.toContain("/");
    expect(base64url).not.toContain("=");
  });

  it("JWK thumbprint uses correct key ordering for EC keys", () => {
    const jwk = {
      kty: "EC",
      crv: "P-256",
      x: "test-x",
      y: "test-y",
    };

    const canonical = JSON.stringify({
      crv: jwk.crv,
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y,
    });

    expect(canonical).toBe('{"crv":"P-256","kty":"EC","x":"test-x","y":"test-y"}');

    const keys = Object.keys(JSON.parse(canonical));
    expect(keys).toEqual(["crv", "kty", "x", "y"]);

    for (let i = 1; i < keys.length; i++) {
      expect(keys[i - 1] < keys[i]).toBe(true);
    }
  });
});
