import type {
  AccountStatus,
  BlobRef,
  CreateAccountParams,
  DidCredentials,
  DidDocument,
  MigrationError,
  PlcOperation,
  Preferences,
  ServerDescription,
  Session,
} from "./types";

export class AtprotoClient {
  private baseUrl: string;
  private accessToken: string | null = null;

  constructor(pdsUrl: string) {
    this.baseUrl = pdsUrl.replace(/\/$/, "");
  }

  setAccessToken(token: string | null) {
    this.accessToken = token;
  }

  getAccessToken(): string | null {
    return this.accessToken;
  }

  private async xrpc<T>(
    method: string,
    options?: {
      httpMethod?: "GET" | "POST";
      params?: Record<string, string>;
      body?: unknown;
      authToken?: string;
      rawBody?: Uint8Array | Blob;
      contentType?: string;
    },
  ): Promise<T> {
    const {
      httpMethod = "GET",
      params,
      body,
      authToken,
      rawBody,
      contentType,
    } = options ?? {};

    let url = `${this.baseUrl}/xrpc/${method}`;
    if (params) {
      const searchParams = new URLSearchParams(params);
      url += `?${searchParams}`;
    }

    const headers: Record<string, string> = {};
    const token = authToken ?? this.accessToken;
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    let requestBody: BodyInit | undefined;
    if (rawBody) {
      headers["Content-Type"] = contentType ?? "application/octet-stream";
      requestBody = rawBody;
    } else if (body) {
      headers["Content-Type"] = "application/json";
      requestBody = JSON.stringify(body);
    } else if (httpMethod === "POST") {
      headers["Content-Type"] = "application/json";
    }

    const res = await fetch(url, {
      method: httpMethod,
      headers,
      body: requestBody,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({
        error: "Unknown",
        message: res.statusText,
      }));
      const error = new Error(err.message) as Error & {
        status: number;
        error: string;
      };
      error.status = res.status;
      error.error = err.error;
      throw error;
    }

    const responseContentType = res.headers.get("content-type") ?? "";
    if (responseContentType.includes("application/json")) {
      return res.json();
    }
    return res.arrayBuffer().then((buf) => new Uint8Array(buf)) as T;
  }

  async login(
    identifier: string,
    password: string,
    authFactorToken?: string,
  ): Promise<Session> {
    const body: Record<string, string> = { identifier, password };
    if (authFactorToken) {
      body.authFactorToken = authFactorToken;
    }

    const session = await this.xrpc<Session>("com.atproto.server.createSession", {
      httpMethod: "POST",
      body,
    });

    this.accessToken = session.accessJwt;
    return session;
  }

  async refreshSession(refreshJwt: string): Promise<Session> {
    const session = await this.xrpc<Session>(
      "com.atproto.server.refreshSession",
      {
        httpMethod: "POST",
        authToken: refreshJwt,
      },
    );
    this.accessToken = session.accessJwt;
    return session;
  }

  async describeServer(): Promise<ServerDescription> {
    return this.xrpc<ServerDescription>("com.atproto.server.describeServer");
  }

  async getServiceAuth(
    aud: string,
    lxm?: string,
  ): Promise<{ token: string }> {
    const params: Record<string, string> = { aud };
    if (lxm) {
      params.lxm = lxm;
    }
    return this.xrpc("com.atproto.server.getServiceAuth", { params });
  }

  async getRepo(did: string): Promise<Uint8Array> {
    return this.xrpc("com.atproto.sync.getRepo", {
      params: { did },
    });
  }

  async listBlobs(
    did: string,
    cursor?: string,
    limit = 100,
  ): Promise<{ cids: string[]; cursor?: string }> {
    const params: Record<string, string> = { did, limit: String(limit) };
    if (cursor) {
      params.cursor = cursor;
    }
    return this.xrpc("com.atproto.sync.listBlobs", { params });
  }

  async getBlob(did: string, cid: string): Promise<Uint8Array> {
    return this.xrpc("com.atproto.sync.getBlob", {
      params: { did, cid },
    });
  }

  async uploadBlob(
    data: Uint8Array,
    mimeType: string,
  ): Promise<{ blob: BlobRef }> {
    return this.xrpc("com.atproto.repo.uploadBlob", {
      httpMethod: "POST",
      rawBody: data,
      contentType: mimeType,
    });
  }

  async getPreferences(): Promise<Preferences> {
    return this.xrpc("app.bsky.actor.getPreferences");
  }

  async putPreferences(preferences: Preferences): Promise<void> {
    await this.xrpc("app.bsky.actor.putPreferences", {
      httpMethod: "POST",
      body: preferences,
    });
  }

  async createAccount(
    params: CreateAccountParams,
    serviceToken?: string,
  ): Promise<Session> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (serviceToken) {
      headers["Authorization"] = `Bearer ${serviceToken}`;
    }

    const res = await fetch(
      `${this.baseUrl}/xrpc/com.atproto.server.createAccount`,
      {
        method: "POST",
        headers,
        body: JSON.stringify(params),
      },
    );

    if (!res.ok) {
      const err = await res.json().catch(() => ({
        error: "Unknown",
        message: res.statusText,
      }));
      const error = new Error(err.message) as Error & {
        status: number;
        error: string;
      };
      error.status = res.status;
      error.error = err.error;
      throw error;
    }

    const session = (await res.json()) as Session;
    this.accessToken = session.accessJwt;
    return session;
  }

  async importRepo(car: Uint8Array): Promise<void> {
    await this.xrpc("com.atproto.repo.importRepo", {
      httpMethod: "POST",
      rawBody: car,
      contentType: "application/vnd.ipld.car",
    });
  }

  async listMissingBlobs(
    cursor?: string,
    limit = 100,
  ): Promise<{ blobs: Array<{ cid: string; recordUri: string }>; cursor?: string }> {
    const params: Record<string, string> = { limit: String(limit) };
    if (cursor) {
      params.cursor = cursor;
    }
    return this.xrpc("com.atproto.repo.listMissingBlobs", { params });
  }

  async requestPlcOperationSignature(): Promise<void> {
    await this.xrpc("com.atproto.identity.requestPlcOperationSignature", {
      httpMethod: "POST",
    });
  }

  async signPlcOperation(params: {
    token?: string;
    rotationKeys?: string[];
    alsoKnownAs?: string[];
    verificationMethods?: { atproto?: string };
    services?: { atproto_pds?: { type: string; endpoint: string } };
  }): Promise<{ operation: PlcOperation }> {
    return this.xrpc("com.atproto.identity.signPlcOperation", {
      httpMethod: "POST",
      body: params,
    });
  }

  async submitPlcOperation(operation: PlcOperation): Promise<void> {
    await this.xrpc("com.atproto.identity.submitPlcOperation", {
      httpMethod: "POST",
      body: { operation },
    });
  }

  async getRecommendedDidCredentials(): Promise<DidCredentials> {
    return this.xrpc("com.atproto.identity.getRecommendedDidCredentials");
  }

  async activateAccount(): Promise<void> {
    await this.xrpc("com.atproto.server.activateAccount", {
      httpMethod: "POST",
    });
  }

  async deactivateAccount(): Promise<void> {
    await this.xrpc("com.atproto.server.deactivateAccount", {
      httpMethod: "POST",
    });
  }

  async checkAccountStatus(): Promise<AccountStatus> {
    return this.xrpc("com.atproto.server.checkAccountStatus");
  }

  async getMigrationStatus(): Promise<{
    did: string;
    didType: string;
    migrated: boolean;
    migratedToPds?: string;
    migratedAt?: string;
  }> {
    return this.xrpc("com.tranquil.account.getMigrationStatus");
  }

  async updateMigrationForwarding(pdsUrl: string): Promise<{
    success: boolean;
    migratedToPds: string;
    migratedAt: string;
  }> {
    return this.xrpc("com.tranquil.account.updateMigrationForwarding", {
      httpMethod: "POST",
      body: { pdsUrl },
    });
  }

  async clearMigrationForwarding(): Promise<{ success: boolean }> {
    return this.xrpc("com.tranquil.account.clearMigrationForwarding", {
      httpMethod: "POST",
    });
  }

  async resolveHandle(handle: string): Promise<{ did: string }> {
    return this.xrpc("com.atproto.identity.resolveHandle", {
      params: { handle },
    });
  }

  async loginDeactivated(
    identifier: string,
    password: string,
  ): Promise<Session> {
    const session = await this.xrpc<Session>("com.atproto.server.createSession", {
      httpMethod: "POST",
      body: { identifier, password, allowDeactivated: true },
    });
    this.accessToken = session.accessJwt;
    return session;
  }

  async verifyToken(
    token: string,
    identifier: string,
  ): Promise<{ success: boolean; did: string; purpose: string; channel: string }> {
    return this.xrpc("com.tranquil.account.verifyToken", {
      httpMethod: "POST",
      body: { token, identifier },
    });
  }

  async resendMigrationVerification(): Promise<void> {
    await this.xrpc("com.atproto.server.resendMigrationVerification", {
      httpMethod: "POST",
    });
  }
}

export async function resolveDidDocument(did: string): Promise<DidDocument> {
  if (did.startsWith("did:plc:")) {
    const res = await fetch(`https://plc.directory/${did}`);
    if (!res.ok) {
      throw new Error(`Failed to resolve DID: ${res.statusText}`);
    }
    return res.json();
  }

  if (did.startsWith("did:web:")) {
    const domain = did.slice(8).replace(/%3A/g, ":");
    const url = domain.includes("/")
      ? `https://${domain}/did.json`
      : `https://${domain}/.well-known/did.json`;

    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Failed to resolve DID: ${res.statusText}`);
    }
    return res.json();
  }

  throw new Error(`Unsupported DID method: ${did}`);
}

export async function resolvePdsUrl(
  handleOrDid: string,
): Promise<{ did: string; pdsUrl: string }> {
  let did: string;

  if (handleOrDid.startsWith("did:")) {
    did = handleOrDid;
  } else {
    const handle = handleOrDid.replace(/^@/, "");

    if (handle.endsWith(".bsky.social")) {
      const res = await fetch(
        `https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(handle)}`,
      );
      if (!res.ok) {
        throw new Error(`Failed to resolve handle: ${res.statusText}`);
      }
      const data = await res.json();
      did = data.did;
    } else {
      const dnsRes = await fetch(
        `https://dns.google/resolve?name=_atproto.${handle}&type=TXT`,
      );
      if (dnsRes.ok) {
        const dnsData = await dnsRes.json();
        const txtRecords = dnsData.Answer ?? [];
        for (const record of txtRecords) {
          const txt = record.data?.replace(/"/g, "") ?? "";
          if (txt.startsWith("did=")) {
            did = txt.slice(4);
            break;
          }
        }
      }

      if (!did) {
        const wellKnownRes = await fetch(
          `https://${handle}/.well-known/atproto-did`,
        );
        if (wellKnownRes.ok) {
          did = (await wellKnownRes.text()).trim();
        }
      }

      if (!did) {
        throw new Error(`Could not resolve handle: ${handle}`);
      }
    }
  }

  const didDoc = await resolveDidDocument(did);

  const pdsService = didDoc.service?.find(
    (s: { type: string }) => s.type === "AtprotoPersonalDataServer",
  );

  if (!pdsService) {
    throw new Error("No PDS service found in DID document");
  }

  return { did, pdsUrl: pdsService.serviceEndpoint };
}

export function createLocalClient(): AtprotoClient {
  return new AtprotoClient(window.location.origin);
}
