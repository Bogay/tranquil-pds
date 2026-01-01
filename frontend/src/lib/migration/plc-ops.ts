import {
  defs,
  type IndexedEntry,
  normalizeOp,
  type Operation,
} from "@atcute/did-plc";
import {
  P256PrivateKey,
  parsePrivateMultikey,
  Secp256k1PrivateKey,
  Secp256k1PrivateKeyExportable,
} from "@atcute/crypto";
import * as CBOR from "@atcute/cbor";
import { fromBase16, toBase64Url } from "@atcute/multibase";

export type PrivateKey = P256PrivateKey | Secp256k1PrivateKey;

export interface KeypairInfo {
  type: "private_key";
  didPublicKey: `did:key:${string}`;
  keypair: PrivateKey;
}

export interface PlcService {
  type: string;
  endpoint: string;
}

export interface PlcOperationData {
  type: "plc_operation";
  prev: string;
  alsoKnownAs: string[];
  rotationKeys: string[];
  services: Record<string, PlcService>;
  verificationMethods: Record<string, string>;
  sig?: string;
}

const jsonToB64Url = (obj: unknown): string => {
  const enc = new TextEncoder();
  const json = JSON.stringify(obj);
  return toBase64Url(enc.encode(json));
};

export class PlcOps {
  private plcDirectoryUrl: string;

  constructor(plcDirectoryUrl = "https://plc.directory") {
    this.plcDirectoryUrl = plcDirectoryUrl;
  }

  async getPlcAuditLogs(did: string): Promise<IndexedEntry[]> {
    const response = await fetch(`${this.plcDirectoryUrl}/${did}/log/audit`);
    if (!response.ok) {
      throw new Error(`Failed to fetch PLC audit logs: ${response.status}`);
    }
    const json = await response.json();
    return defs.indexedEntryLog.parse(json);
  }

  async getLastPlcOpFromPlc(
    did: string,
  ): Promise<{ lastOperation: Operation; base: IndexedEntry }> {
    const logs = await this.getPlcAuditLogs(did);
    const lastOp = logs.at(-1);
    if (!lastOp) {
      throw new Error("No PLC operations found for this DID");
    }
    return { lastOperation: normalizeOp(lastOp.operation), base: lastOp };
  }

  async getCurrentRotationKeysForUser(did: string): Promise<string[]> {
    const { lastOperation } = await this.getLastPlcOpFromPlc(did);
    return lastOperation.rotationKeys || [];
  }

  async createNewSecp256k1Keypair(): Promise<
    { privateKey: string; publicKey: `did:key:${string}` }
  > {
    const keypair = await Secp256k1PrivateKeyExportable.createKeypair();
    const publicKey = await keypair.exportPublicKey("did");
    const privateKey = await keypair.exportPrivateKey("multikey");
    return { privateKey, publicKey };
  }

  async getKeyPair(
    privateKeyString: string,
    type: "secp256k1" | "p256" = "secp256k1",
  ): Promise<KeypairInfo> {
    const HEX_REGEX = /^[0-9a-f]+$/i;
    const MULTIKEY_REGEX = /^z[a-km-zA-HJ-NP-Z1-9]+$/;
    let keypair: PrivateKey | undefined;

    const trimmed = privateKeyString.trim();

    if (HEX_REGEX.test(trimmed) && trimmed.length === 64) {
      const privateKeyBytes = fromBase16(trimmed);
      if (type === "p256") {
        keypair = await P256PrivateKey.importRaw(privateKeyBytes);
      } else {
        keypair = await Secp256k1PrivateKey.importRaw(privateKeyBytes);
      }
    } else if (MULTIKEY_REGEX.test(trimmed)) {
      const match = parsePrivateMultikey(trimmed);
      const privateKeyBytes = match.privateKeyBytes;
      if (match.type === "p256") {
        keypair = await P256PrivateKey.importRaw(privateKeyBytes);
      } else if (match.type === "secp256k1") {
        keypair = await Secp256k1PrivateKey.importRaw(privateKeyBytes);
      } else {
        throw new Error(`Unsupported key type: ${match.type}`);
      }
    } else {
      throw new Error(
        "Invalid key format. Expected 64-char hex or multikey format.",
      );
    }

    if (!keypair) {
      throw new Error("Failed to parse private key");
    }

    return {
      type: "private_key",
      didPublicKey: await keypair.exportPublicKey("did"),
      keypair,
    };
  }

  async signAndPublishNewOp(
    did: string,
    signingRotationKey: PrivateKey,
    alsoKnownAs: string[],
    rotationKeys: string[],
    pds: string,
    verificationKey: string,
    prev: string,
  ): Promise<void> {
    const rotationKeysToUse = [...new Set(rotationKeys)];
    if (rotationKeysToUse.length === 0) {
      throw new Error("No rotation keys provided");
    }
    if (rotationKeysToUse.length > 5) {
      throw new Error("Maximum 5 rotation keys allowed");
    }

    const operation: PlcOperationData = {
      type: "plc_operation",
      prev,
      alsoKnownAs,
      rotationKeys: rotationKeysToUse,
      services: {
        atproto_pds: {
          type: "AtprotoPersonalDataServer",
          endpoint: pds,
        },
      },
      verificationMethods: {
        atproto: verificationKey,
      },
    };

    const opBytes = CBOR.encode(operation);
    const sigBytes = await signingRotationKey.sign(opBytes);
    const signature = toBase64Url(sigBytes);

    const signedOperation = {
      ...operation,
      sig: signature,
    };

    await this.pushPlcOperation(did, signedOperation);
  }

  async pushPlcOperation(
    did: string,
    operation: PlcOperationData,
  ): Promise<void> {
    const response = await fetch(`${this.plcDirectoryUrl}/${did}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(operation),
    });

    if (!response.ok) {
      const contentType = response.headers.get("content-type");
      if (contentType?.includes("application/json")) {
        const json = await response.json();
        if (
          typeof json === "object" && json !== null &&
          typeof json.message === "string"
        ) {
          throw new Error(json.message);
        }
      }
      throw new Error(`PLC directory returned HTTP ${response.status}`);
    }
  }

  async createServiceAuthToken(
    iss: string,
    aud: string,
    keypair: PrivateKey,
    lxm: string,
  ): Promise<string> {
    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + 60;

    const jti = (() => {
      const bytes = new Uint8Array(16);
      crypto.getRandomValues(bytes);
      return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    })();

    const header = { typ: "JWT", alg: "ES256K" };
    const payload = { iat, iss, aud, exp, lxm, jti };

    const headerB64 = jsonToB64Url(header);
    const payloadB64 = jsonToB64Url(payload);
    const toSignStr = `${headerB64}.${payloadB64}`;

    const toSignBytes = new TextEncoder().encode(toSignStr);
    const sigBytes = await keypair.sign(toSignBytes);
    const sigB64 = toBase64Url(sigBytes);

    return `${toSignStr}.${sigB64}`;
  }

  async signPlcOperationWithCredentials(
    did: string,
    signingKey: PrivateKey,
    credentials: {
      rotationKeys?: string[];
      alsoKnownAs?: string[];
      verificationMethods?: Record<string, string>;
      services?: Record<string, PlcService>;
    },
    additionalRotationKeys: string[],
    prevCid: string,
  ): Promise<void> {
    const rotationKeys = [
      ...new Set([
        ...(additionalRotationKeys || []),
        ...(credentials.rotationKeys || []),
      ]),
    ];

    if (rotationKeys.length === 0) {
      throw new Error("No rotation keys provided");
    }
    if (rotationKeys.length > 5) {
      throw new Error("Maximum 5 rotation keys allowed");
    }

    const operation: PlcOperationData = {
      type: "plc_operation",
      prev: prevCid,
      alsoKnownAs: credentials.alsoKnownAs || [],
      rotationKeys,
      services: credentials.services || {},
      verificationMethods: credentials.verificationMethods || {},
    };

    const opBytes = CBOR.encode(operation);
    const sigBytes = await signingKey.sign(opBytes);
    const signature = toBase64Url(sigBytes);

    const signedOperation = {
      ...operation,
      sig: signature,
    };

    await this.pushPlcOperation(did, signedOperation);
  }
}

export const plcOps = new PlcOps();
