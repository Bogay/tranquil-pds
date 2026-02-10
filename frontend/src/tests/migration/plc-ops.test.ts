import { beforeEach, describe, expect, it, vi } from "vitest";
import { PlcOps, plcOps } from "../../lib/migration/plc-ops.ts";
import {
  P256PrivateKeyExportable,
  Secp256k1PrivateKeyExportable,
} from "@atcute/crypto";
import { fromBase58Btc, toBase58Btc } from "@atcute/multibase";

describe("migration/plc-ops", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe("PlcOps class", () => {
    it("uses default PLC directory URL", () => {
      const ops = new PlcOps();
      expect(ops).toBeDefined();
    });

    it("accepts custom PLC directory URL", () => {
      const ops = new PlcOps("https://custom-plc.example.com");
      expect(ops).toBeDefined();
    });
  });

  describe("plcOps singleton", () => {
    it("exports a singleton instance", () => {
      expect(plcOps).toBeInstanceOf(PlcOps);
    });
  });

  describe("getPlcAuditLogs", () => {
    it("throws on HTTP error", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      });

      await expect(plcOps.getPlcAuditLogs("did:plc:notfound")).rejects.toThrow(
        "Failed to fetch PLC audit logs: 404",
      );
    });
  });

  describe("getLastPlcOpFromPlc", () => {
    it("throws when empty array returned", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve([]),
      });

      await expect(
        plcOps.getLastPlcOpFromPlc("did:plc:empty"),
      ).rejects.toThrow();
    });
  });

  describe("createNewSecp256k1Keypair", () => {
    it("generates a keypair with private and public keys", async () => {
      const result = await plcOps.createNewSecp256k1Keypair();

      expect(result.privateKey).toBeDefined();
      expect(result.publicKey).toBeDefined();
      expect(result.publicKey.startsWith("did:key:")).toBe(true);
    });

    it("generates different keypairs each time", async () => {
      const result1 = await plcOps.createNewSecp256k1Keypair();
      const result2 = await plcOps.createNewSecp256k1Keypair();

      expect(result1.privateKey).not.toBe(result2.privateKey);
      expect(result1.publicKey).not.toBe(result2.publicKey);
    });
  });

  describe("getKeyPair", () => {
    it("parses 64-character hex private key", async () => {
      const hexKey = "a".repeat(64);

      const result = await plcOps.getKeyPair(hexKey);

      expect(result.type).toBe("private_key");
      expect(result.didPublicKey.startsWith("did:key:")).toBe(true);
      expect(result.keypair).toBeDefined();
    });

    it("handles whitespace in key input", async () => {
      const hexKey = "  " + "b".repeat(64) + "  ";

      const result = await plcOps.getKeyPair(hexKey);

      expect(result.type).toBe("private_key");
    });

    it("throws for invalid key format", async () => {
      await expect(plcOps.getKeyPair("not-a-valid-key")).rejects.toThrow(
        "Unrecognized key format",
      );
    });

    it("throws for hex key with wrong length", async () => {
      await expect(plcOps.getKeyPair("abc123")).rejects.toThrow();
    });
  });

  describe("getKeyPair - multikey round-trip", () => {
    it("round-trips from createNewSecp256k1Keypair", async () => {
      const { privateKey, publicKey } = await plcOps
        .createNewSecp256k1Keypair();

      const result = await plcOps.getKeyPair(privateKey);

      expect(result.didPublicKey).toBe(publicKey);
    });

    it("produces correct multikey structure (z prefix, codec bytes)", async () => {
      const { privateKey } = await plcOps.createNewSecp256k1Keypair();

      expect(privateKey.startsWith("z")).toBe(true);
      const decoded = fromBase58Btc(privateKey.slice(1));
      expect(decoded[0]).toBe(0x81);
      expect(decoded[1]).toBe(0x26);
      expect(decoded.length).toBe(34);
    });

    it("multikey import matches hex import of same raw bytes", async () => {
      const keypair = await Secp256k1PrivateKeyExportable.createKeypair();
      const multikey = await keypair.exportPrivateKey("multikey");
      const rawHex = await keypair.exportPrivateKey("rawHex");

      const fromMultikey = await plcOps.getKeyPair(multikey);
      const fromHex = await plcOps.getKeyPair(rawHex);

      expect(fromMultikey.didPublicKey).toBe(fromHex.didPublicKey);
    });
  });

  describe("getKeyPair - hex format", () => {
    it("accepts uppercase hex", async () => {
      const result = await plcOps.getKeyPair("A".repeat(64));

      expect(result.type).toBe("private_key");
      expect(result.didPublicKey.startsWith("did:key:")).toBe(true);
    });
  });

  describe("getKeyPair - JWK format", () => {
    it("imports secp256k1 JWK with d parameter", async () => {
      const keypair = await Secp256k1PrivateKeyExportable.createKeypair();
      const jwk = await keypair.exportPrivateKey("jwk");
      const expectedDid = await keypair.exportPublicKey("did");

      const result = await plcOps.getKeyPair(JSON.stringify(jwk));

      expect(result.didPublicKey).toBe(expectedDid);
    });

    it("imports P-256 JWK with d parameter", async () => {
      const keypair = await P256PrivateKeyExportable.createKeypair();
      const jwk = await keypair.exportPrivateKey("jwk");
      const expectedDid = await keypair.exportPublicKey("did");

      const result = await plcOps.getKeyPair(JSON.stringify(jwk));

      expect(result.didPublicKey).toBe(expectedDid);
    });

    it("rejects JWK without d (public key)", async () => {
      const keypair = await Secp256k1PrivateKeyExportable.createKeypair();
      const jwk = await keypair.exportPublicKey("jwk");

      await expect(
        plcOps.getKeyPair(JSON.stringify(jwk)),
      ).rejects.toThrow("public key");
    });

    it("rejects unsupported kty", async () => {
      const jwk = { kty: "RSA", n: "abc", e: "AQAB" };

      await expect(plcOps.getKeyPair(JSON.stringify(jwk))).rejects.toThrow(
        "Unsupported JWK key type",
      );
    });

    it("rejects unsupported crv", async () => {
      const jwk = { kty: "EC", crv: "P-384", d: "AAAA", x: "BBBB", y: "CCCC" };

      await expect(plcOps.getKeyPair(JSON.stringify(jwk))).rejects.toThrow(
        "Unsupported JWK curve",
      );
    });

    it("rejects malformed JSON", async () => {
      await expect(plcOps.getKeyPair("{not valid json")).rejects.toThrow();
    });

    it("produces same public key as hex import of same raw bytes", async () => {
      const keypair = await Secp256k1PrivateKeyExportable.createKeypair();
      const jwk = await keypair.exportPrivateKey("jwk");
      const rawHex = await keypair.exportPrivateKey("rawHex");

      const fromJwk = await plcOps.getKeyPair(JSON.stringify(jwk));
      const fromHex = await plcOps.getKeyPair(rawHex);

      expect(fromJwk.didPublicKey).toBe(fromHex.didPublicKey);
    });
  });

  describe("getKeyPair - plain base58 format", () => {
    it("imports base58-encoded 32-byte raw key", async () => {
      const keypair = await Secp256k1PrivateKeyExportable.createKeypair();
      const rawBytes = await keypair.exportPrivateKey("raw");
      const base58 = toBase58Btc(rawBytes);
      const expectedDid = await keypair.exportPublicKey("did");

      const result = await plcOps.getKeyPair(base58);

      expect(result.didPublicKey).toBe(expectedDid);
    });

    it("produces same public key as hex import of same raw bytes", async () => {
      const keypair = await Secp256k1PrivateKeyExportable.createKeypair();
      const rawBytes = await keypair.exportPrivateKey("raw");
      const rawHex = await keypair.exportPrivateKey("rawHex");
      const base58 = toBase58Btc(rawBytes);

      const fromBase58 = await plcOps.getKeyPair(base58);
      const fromHex = await plcOps.getKeyPair(rawHex);

      expect(fromBase58.didPublicKey).toBe(fromHex.didPublicKey);
    });

    it("rejects wrong decoded length", async () => {
      const shortBytes = new Uint8Array(16);
      crypto.getRandomValues(shortBytes);
      const base58Short = toBase58Btc(shortBytes);

      await expect(plcOps.getKeyPair(base58Short)).rejects.toThrow(
        "expected 32",
      );
    });
  });

  describe("getKeyPair - cross-format consistency", () => {
    it("hex, multikey, and JWK all produce identical did:key", async () => {
      const keypair = await Secp256k1PrivateKeyExportable.createKeypair();
      const rawHex = await keypair.exportPrivateKey("rawHex");
      const multikey = await keypair.exportPrivateKey("multikey");
      const jwk = await keypair.exportPrivateKey("jwk");

      const [fromHex, fromMultikey, fromJwk] = await Promise.all([
        plcOps.getKeyPair(rawHex),
        plcOps.getKeyPair(multikey),
        plcOps.getKeyPair(JSON.stringify(jwk)),
      ]);

      expect(fromHex.didPublicKey).toBe(fromMultikey.didPublicKey);
      expect(fromHex.didPublicKey).toBe(fromJwk.didPublicKey);
    });

    it("hex, multikey, JWK, and base58 all match for P-256", async () => {
      const keypair = await P256PrivateKeyExportable.createKeypair();
      const rawHex = await keypair.exportPrivateKey("rawHex");
      const multikey = await keypair.exportPrivateKey("multikey");
      const jwk = await keypair.exportPrivateKey("jwk");
      const rawBytes = await keypair.exportPrivateKey("raw");
      const base58 = toBase58Btc(rawBytes);

      const [fromHex, fromMultikey, fromJwk, fromBase58] = await Promise.all([
        plcOps.getKeyPair(rawHex, "p256"),
        plcOps.getKeyPair(multikey),
        plcOps.getKeyPair(JSON.stringify(jwk)),
        plcOps.getKeyPair(base58, "p256"),
      ]);

      expect(fromHex.didPublicKey).toBe(fromMultikey.didPublicKey);
      expect(fromHex.didPublicKey).toBe(fromJwk.didPublicKey);
      expect(fromHex.didPublicKey).toBe(fromBase58.didPublicKey);
    });
  });

  describe("getKeyPair - error cases", () => {
    it("rejects empty string", async () => {
      await expect(plcOps.getKeyPair("")).rejects.toThrow(
        "Private key is required",
      );
    });

    it("rejects whitespace-only", async () => {
      await expect(plcOps.getKeyPair("   ")).rejects.toThrow(
        "Private key is required",
      );
    });

    it("rejects did:key: prefix with helpful error", async () => {
      await expect(
        plcOps.getKeyPair(
          "did:key:zQ3shunBKoL5VRgSEX7RQGQEG3TTo6MPVWvT7tcVjjwZCWMEE",
        ),
      ).rejects.toThrow("public key");
    });

    it("rejects unrecognized garbage", async () => {
      await expect(plcOps.getKeyPair("!!!invalid!!!")).rejects.toThrow(
        "Unrecognized key format",
      );
    });

    it("rejects hex with non-hex chars in 64-char string", async () => {
      const almostHex = "g".repeat(64);
      await expect(plcOps.getKeyPair(almostHex)).rejects.toThrow();
    });
  });

  describe("pushPlcOperation", () => {
    it("posts operation to PLC directory", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
      });

      const operation = {
        type: "plc_operation" as const,
        prev: "bafyreiabc",
        alsoKnownAs: ["at://alice.example.com"],
        rotationKeys: ["did:key:z123"],
        services: {
          atproto_pds: {
            type: "AtprotoPersonalDataServer",
            endpoint: "https://pds.example.com",
          },
        },
        verificationMethods: {
          atproto: "did:key:z456",
        },
        sig: "test-signature",
      };

      await plcOps.pushPlcOperation("did:plc:abc123", operation);

      expect(fetch).toHaveBeenCalledWith(
        "https://plc.directory/did:plc:abc123",
        expect.objectContaining({
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(operation),
        }),
      );
    });

    it("throws with error message from PLC directory", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        headers: new Map([["content-type", "application/json"]]),
        json: () => Promise.resolve({ message: "Invalid signature" }),
      });

      const operation = {
        type: "plc_operation" as const,
        prev: "bafyreiabc",
        alsoKnownAs: [],
        rotationKeys: ["did:key:z123"],
        services: {},
        verificationMethods: {},
        sig: "bad-sig",
      };

      await expect(
        plcOps.pushPlcOperation("did:plc:abc123", operation),
      ).rejects.toThrow("Invalid signature");
    });

    it("throws generic error when no message in response", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        headers: new Map([["content-type", "text/plain"]]),
      });

      const operation = {
        type: "plc_operation" as const,
        prev: null,
        alsoKnownAs: [],
        rotationKeys: [],
        services: {},
        verificationMethods: {},
      };

      await expect(
        plcOps.pushPlcOperation("did:plc:abc123", operation),
      ).rejects.toThrow("PLC directory returned HTTP 500");
    });
  });

  describe("createServiceAuthToken", () => {
    it("creates a valid JWT", async () => {
      const { privateKey } = await plcOps.createNewSecp256k1Keypair();
      const keypair = await plcOps.getKeyPair(privateKey);

      const token = await plcOps.createServiceAuthToken(
        "did:plc:issuer",
        "did:web:audience.example.com",
        keypair.keypair,
        "com.atproto.server.createAccount",
      );

      expect(token).toBeDefined();
      const parts = token.split(".");
      expect(parts).toHaveLength(3);
    });

    it("includes correct header", async () => {
      const { privateKey } = await plcOps.createNewSecp256k1Keypair();
      const keypair = await plcOps.getKeyPair(privateKey);

      const token = await plcOps.createServiceAuthToken(
        "did:plc:issuer",
        "did:web:audience",
        keypair.keypair,
        "com.atproto.server.createAccount",
      );

      const headerB64 = token.split(".")[0];
      const header = JSON.parse(
        atob(headerB64.replace(/-/g, "+").replace(/_/g, "/")),
      );
      expect(header.typ).toBe("JWT");
      expect(header.alg).toBe("ES256K");
    });

    it("includes correct payload claims", async () => {
      const { privateKey } = await plcOps.createNewSecp256k1Keypair();
      const keypair = await plcOps.getKeyPair(privateKey);

      const before = Math.floor(Date.now() / 1000);
      const token = await plcOps.createServiceAuthToken(
        "did:plc:myissuer",
        "did:web:myaudience.com",
        keypair.keypair,
        "com.atproto.sync.getRepo",
      );
      const after = Math.floor(Date.now() / 1000);

      const payloadB64 = token.split(".")[1];
      const payload = JSON.parse(
        atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")),
      );

      expect(payload.iss).toBe("did:plc:myissuer");
      expect(payload.aud).toBe("did:web:myaudience.com");
      expect(payload.lxm).toBe("com.atproto.sync.getRepo");
      expect(payload.iat).toBeGreaterThanOrEqual(before);
      expect(payload.iat).toBeLessThanOrEqual(after);
      expect(payload.exp).toBe(payload.iat + 60);
      expect(payload.jti).toBeDefined();
    });
  });

  describe("signAndPublishNewOp", () => {
    it("throws when no rotation keys provided", async () => {
      const { privateKey } = await plcOps.createNewSecp256k1Keypair();
      const keypair = await plcOps.getKeyPair(privateKey);

      await expect(
        plcOps.signAndPublishNewOp(
          "did:plc:test",
          keypair.keypair,
          ["at://alice.example.com"],
          [],
          "https://pds.example.com",
          "did:key:zVerify",
          "bafyreiprev",
        ),
      ).rejects.toThrow("No rotation keys provided");
    });

    it("throws when more than 5 unique rotation keys provided", async () => {
      const { privateKey } = await plcOps.createNewSecp256k1Keypair();
      const keypair = await plcOps.getKeyPair(privateKey);

      const tooManyKeys = [
        "did:key:z1",
        "did:key:z2",
        "did:key:z3",
        "did:key:z4",
        "did:key:z5",
        "did:key:z6",
      ];

      await expect(
        plcOps.signAndPublishNewOp(
          "did:plc:test",
          keypair.keypair,
          [],
          tooManyKeys,
          "https://pds.example.com",
          "did:key:zVerify",
          "bafyreiprev",
        ),
      ).rejects.toThrow("Maximum 5 rotation keys allowed");
    });
  });

  describe("signPlcOperationWithCredentials", () => {
    it("throws when no rotation keys provided", async () => {
      const { privateKey } = await plcOps.createNewSecp256k1Keypair();
      const keypair = await plcOps.getKeyPair(privateKey);

      await expect(
        plcOps.signPlcOperationWithCredentials(
          "did:plc:test",
          keypair.keypair,
          {
            rotationKeys: [],
            alsoKnownAs: [],
            verificationMethods: {},
            services: {},
          },
          [],
          "bafyreiprev",
        ),
      ).rejects.toThrow("No rotation keys provided");
    });

    it("throws when more than 5 rotation keys provided", async () => {
      const { privateKey } = await plcOps.createNewSecp256k1Keypair();
      const keypair = await plcOps.getKeyPair(privateKey);

      await expect(
        plcOps.signPlcOperationWithCredentials(
          "did:plc:test",
          keypair.keypair,
          {
            rotationKeys: ["did:key:z1", "did:key:z2", "did:key:z3"],
            alsoKnownAs: [],
            verificationMethods: {},
            services: {},
          },
          ["did:key:z4", "did:key:z5", "did:key:z6"],
          "bafyreiprev",
        ),
      ).rejects.toThrow("Maximum 5 rotation keys allowed");
    });
  });
});
