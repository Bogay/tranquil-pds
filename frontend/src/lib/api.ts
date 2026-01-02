const API_BASE = "/xrpc";

export class ApiError extends Error {
  public did?: string;
  public reauthMethods?: string[];
  constructor(
    public status: number,
    public error: string,
    message: string,
    did?: string,
    reauthMethods?: string[],
  ) {
    super(message);
    this.name = "ApiError";
    this.did = did;
    this.reauthMethods = reauthMethods;
  }
}

let tokenRefreshCallback: (() => Promise<string | null>) | null = null;

export function setTokenRefreshCallback(
  callback: () => Promise<string | null>,
) {
  tokenRefreshCallback = callback;
}

async function xrpc<T>(method: string, options?: {
  method?: "GET" | "POST";
  params?: Record<string, string>;
  body?: unknown;
  token?: string;
  skipRetry?: boolean;
}): Promise<T> {
  const { method: httpMethod = "GET", params, body, token, skipRetry } =
    options ?? {};
  let url = `${API_BASE}/${method}`;
  if (params) {
    const searchParams = new URLSearchParams(params);
    url += `?${searchParams}`;
  }
  const headers: Record<string, string> = {};
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  if (body) {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(url, {
    method: httpMethod,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({
      error: "Unknown",
      message: res.statusText,
    }));
    if (
      res.status === 401 &&
      (err.error === "AuthenticationFailed" || err.error === "ExpiredToken") &&
      token && tokenRefreshCallback && !skipRetry
    ) {
      const newToken = await tokenRefreshCallback();
      if (newToken && newToken !== token) {
        return xrpc(method, { ...options, token: newToken, skipRetry: true });
      }
    }
    throw new ApiError(
      res.status,
      err.error,
      err.message,
      err.did,
      err.reauthMethods,
    );
  }
  return res.json();
}

export interface Session {
  did: string;
  handle: string;
  email?: string;
  emailConfirmed?: boolean;
  preferredChannel?: string;
  preferredChannelVerified?: boolean;
  isAdmin?: boolean;
  active?: boolean;
  status?: "active" | "deactivated" | "migrated";
  migratedToPds?: string;
  migratedAt?: string;
  accessJwt: string;
  refreshJwt: string;
}

export interface VerificationMethod {
  id: string;
  type: string;
  publicKeyMultibase: string;
}

export interface DidDocument {
  "@context": string[];
  id: string;
  alsoKnownAs: string[];
  verificationMethod: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyMultibase: string;
  }>;
  service: Array<{
    id: string;
    type: string;
    serviceEndpoint: string;
  }>;
}

export interface AppPassword {
  name: string;
  createdAt: string;
  scopes?: string;
  createdByController?: string;
}

export interface InviteCode {
  code: string;
  available: number;
  disabled: boolean;
  forAccount: string;
  createdBy: string;
  createdAt: string;
  uses: { usedBy: string; usedByHandle?: string; usedAt: string }[];
}

export type VerificationChannel = "email" | "discord" | "telegram" | "signal";

export type DidType = "plc" | "web" | "web-external";

export interface CreateAccountParams {
  handle: string;
  email: string;
  password: string;
  inviteCode?: string;
  didType?: DidType;
  did?: string;
  signingKey?: string;
  verificationChannel?: VerificationChannel;
  discordId?: string;
  telegramUsername?: string;
  signalNumber?: string;
}

export interface CreateAccountResult {
  handle: string;
  did: string;
  verificationRequired: boolean;
  verificationChannel: string;
}

export interface ConfirmSignupResult {
  accessJwt: string;
  refreshJwt: string;
  handle: string;
  did: string;
  email?: string;
  emailConfirmed?: boolean;
  preferredChannel?: string;
  preferredChannelVerified?: boolean;
}

export const api = {
  async createAccount(
    params: CreateAccountParams,
    byodToken?: string,
  ): Promise<CreateAccountResult> {
    const url = `${API_BASE}/com.atproto.server.createAccount`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (byodToken) {
      headers["Authorization"] = `Bearer ${byodToken}`;
    }
    const response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        handle: params.handle,
        email: params.email,
        password: params.password,
        inviteCode: params.inviteCode,
        didType: params.didType,
        did: params.did,
        signingKey: params.signingKey,
        verificationChannel: params.verificationChannel,
        discordId: params.discordId,
        telegramUsername: params.telegramUsername,
        signalNumber: params.signalNumber,
      }),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new ApiError(response.status, data.error, data.message);
    }
    return data;
  },

  async createAccountWithServiceAuth(
    serviceAuthToken: string,
    params: {
      did: string;
      handle: string;
      email: string;
      password: string;
      inviteCode?: string;
    },
  ): Promise<Session> {
    const url = `${API_BASE}/com.atproto.server.createAccount`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${serviceAuthToken}`,
      },
      body: JSON.stringify({
        did: params.did,
        handle: params.handle,
        email: params.email,
        password: params.password,
        inviteCode: params.inviteCode,
      }),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new ApiError(response.status, data.error, data.message);
    }
    return data;
  },

  confirmSignup(
    did: string,
    verificationCode: string,
  ): Promise<ConfirmSignupResult> {
    return xrpc("com.atproto.server.confirmSignup", {
      method: "POST",
      body: { did, verificationCode },
    });
  },

  resendVerification(did: string): Promise<{ success: boolean }> {
    return xrpc("com.atproto.server.resendVerification", {
      method: "POST",
      body: { did },
    });
  },

  createSession(identifier: string, password: string): Promise<Session> {
    return xrpc("com.atproto.server.createSession", {
      method: "POST",
      body: { identifier, password },
    });
  },

  checkEmailVerified(identifier: string): Promise<{ verified: boolean }> {
    return xrpc("_checkEmailVerified", {
      method: "POST",
      body: { identifier },
    });
  },

  getSession(token: string): Promise<Session> {
    return xrpc("com.atproto.server.getSession", { token });
  },

  refreshSession(refreshJwt: string): Promise<Session> {
    return xrpc("com.atproto.server.refreshSession", {
      method: "POST",
      token: refreshJwt,
    });
  },

  async deleteSession(token: string): Promise<void> {
    await xrpc("com.atproto.server.deleteSession", {
      method: "POST",
      token,
    });
  },

  listAppPasswords(token: string): Promise<{ passwords: AppPassword[] }> {
    return xrpc("com.atproto.server.listAppPasswords", { token });
  },

  createAppPassword(
    token: string,
    name: string,
    scopes?: string,
  ): Promise<
    { name: string; password: string; createdAt: string; scopes?: string }
  > {
    return xrpc("com.atproto.server.createAppPassword", {
      method: "POST",
      token,
      body: { name, scopes },
    });
  },

  async revokeAppPassword(token: string, name: string): Promise<void> {
    await xrpc("com.atproto.server.revokeAppPassword", {
      method: "POST",
      token,
      body: { name },
    });
  },

  getAccountInviteCodes(token: string): Promise<{ codes: InviteCode[] }> {
    return xrpc("com.atproto.server.getAccountInviteCodes", { token });
  },

  createInviteCode(
    token: string,
    useCount: number = 1,
  ): Promise<{ code: string }> {
    return xrpc("com.atproto.server.createInviteCode", {
      method: "POST",
      token,
      body: { useCount },
    });
  },

  async requestPasswordReset(email: string): Promise<void> {
    await xrpc("com.atproto.server.requestPasswordReset", {
      method: "POST",
      body: { email },
    });
  },

  async resetPassword(token: string, password: string): Promise<void> {
    await xrpc("com.atproto.server.resetPassword", {
      method: "POST",
      body: { token, password },
    });
  },

  requestEmailUpdate(
    token: string,
  ): Promise<{ tokenRequired: boolean }> {
    return xrpc("com.atproto.server.requestEmailUpdate", {
      method: "POST",
      token,
    });
  },

  async updateEmail(
    token: string,
    email: string,
    emailToken?: string,
  ): Promise<void> {
    await xrpc("com.atproto.server.updateEmail", {
      method: "POST",
      token,
      body: { email, token: emailToken },
    });
  },

  async updateHandle(token: string, handle: string): Promise<void> {
    await xrpc("com.atproto.identity.updateHandle", {
      method: "POST",
      token,
      body: { handle },
    });
  },

  async requestAccountDelete(token: string): Promise<void> {
    await xrpc("com.atproto.server.requestAccountDelete", {
      method: "POST",
      token,
    });
  },

  async deleteAccount(
    did: string,
    password: string,
    deleteToken: string,
  ): Promise<void> {
    await xrpc("com.atproto.server.deleteAccount", {
      method: "POST",
      body: { did, password, token: deleteToken },
    });
  },

  describeServer(): Promise<{
    availableUserDomains: string[];
    inviteCodeRequired: boolean;
    links?: { privacyPolicy?: string; termsOfService?: string };
    version?: string;
    availableCommsChannels?: string[];
    selfHostedDidWebEnabled?: boolean;
  }> {
    return xrpc("com.atproto.server.describeServer");
  },

  listRepos(limit?: number): Promise<{
    repos: Array<{ did: string; head: string; rev: string }>;
    cursor?: string;
  }> {
    const params: Record<string, string> = {};
    if (limit) params.limit = String(limit);
    return xrpc("com.atproto.sync.listRepos", { params });
  },

  getNotificationPrefs(token: string): Promise<{
    preferredChannel: string;
    email: string;
    discordId: string | null;
    discordVerified: boolean;
    telegramUsername: string | null;
    telegramVerified: boolean;
    signalNumber: string | null;
    signalVerified: boolean;
  }> {
    return xrpc("_account.getNotificationPrefs", { token });
  },

  updateNotificationPrefs(token: string, prefs: {
    preferredChannel?: string;
    discordId?: string;
    telegramUsername?: string;
    signalNumber?: string;
  }): Promise<{ success: boolean }> {
    return xrpc("_account.updateNotificationPrefs", {
      method: "POST",
      token,
      body: prefs,
    });
  },

  confirmChannelVerification(
    token: string,
    channel: string,
    identifier: string,
    code: string,
  ): Promise<{ success: boolean }> {
    return xrpc("_account.confirmChannelVerification", {
      method: "POST",
      token,
      body: { channel, identifier, code },
    });
  },

  getNotificationHistory(token: string): Promise<{
    notifications: Array<{
      createdAt: string;
      channel: string;
      notificationType: string;
      status: string;
      subject: string | null;
      body: string;
    }>;
  }> {
    return xrpc("_account.getNotificationHistory", { token });
  },

  getServerStats(token: string): Promise<{
    userCount: number;
    repoCount: number;
    recordCount: number;
    blobStorageBytes: number;
  }> {
    return xrpc("_admin.getServerStats", { token });
  },

  getServerConfig(): Promise<{
    serverName: string;
    primaryColor: string | null;
    primaryColorDark: string | null;
    secondaryColor: string | null;
    secondaryColorDark: string | null;
    logoCid: string | null;
  }> {
    return xrpc("_server.getConfig");
  },

  updateServerConfig(
    token: string,
    config: {
      serverName?: string;
      primaryColor?: string;
      primaryColorDark?: string;
      secondaryColor?: string;
      secondaryColorDark?: string;
      logoCid?: string;
    },
  ): Promise<{ success: boolean }> {
    return xrpc("_admin.updateServerConfig", {
      method: "POST",
      token,
      body: config,
    });
  },

  async uploadBlob(
    token: string,
    file: File,
  ): Promise<
    {
      blob: {
        $type: string;
        ref: { $link: string };
        mimeType: string;
        size: number;
      };
    }
  > {
    const res = await fetch("/xrpc/com.atproto.repo.uploadBlob", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": file.type,
      },
      body: file,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({
        error: "Unknown",
        message: res.statusText,
      }));
      throw new ApiError(res.status, err.error, err.message);
    }
    return res.json();
  },

  async changePassword(
    token: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    await xrpc("_account.changePassword", {
      method: "POST",
      token,
      body: { currentPassword, newPassword },
    });
  },

  removePassword(token: string): Promise<{ success: boolean }> {
    return xrpc("_account.removePassword", {
      method: "POST",
      token,
    });
  },

  getPasswordStatus(token: string): Promise<{ hasPassword: boolean }> {
    return xrpc("_account.getPasswordStatus", { token });
  },

  getLegacyLoginPreference(
    token: string,
  ): Promise<{ allowLegacyLogin: boolean; hasMfa: boolean }> {
    return xrpc("_account.getLegacyLoginPreference", { token });
  },

  updateLegacyLoginPreference(
    token: string,
    allowLegacyLogin: boolean,
  ): Promise<{ allowLegacyLogin: boolean }> {
    return xrpc("_account.updateLegacyLoginPreference", {
      method: "POST",
      token,
      body: { allowLegacyLogin },
    });
  },

  updateLocale(
    token: string,
    preferredLocale: string,
  ): Promise<{ preferredLocale: string }> {
    return xrpc("_account.updateLocale", {
      method: "POST",
      token,
      body: { preferredLocale },
    });
  },

  listSessions(token: string): Promise<{
    sessions: Array<{
      id: string;
      sessionType: string;
      clientName: string | null;
      createdAt: string;
      expiresAt: string;
      isCurrent: boolean;
    }>;
  }> {
    return xrpc("_account.listSessions", { token });
  },

  async revokeSession(token: string, sessionId: string): Promise<void> {
    await xrpc("_account.revokeSession", {
      method: "POST",
      token,
      body: { sessionId },
    });
  },

  revokeAllSessions(token: string): Promise<{ revokedCount: number }> {
    return xrpc("_account.revokeAllSessions", {
      method: "POST",
      token,
    });
  },

  searchAccounts(token: string, options?: {
    handle?: string;
    cursor?: string;
    limit?: number;
  }): Promise<{
    cursor?: string;
    accounts: Array<{
      did: string;
      handle: string;
      email?: string;
      indexedAt: string;
      emailConfirmedAt?: string;
      deactivatedAt?: string;
    }>;
  }> {
    const params: Record<string, string> = {};
    if (options?.handle) params.handle = options.handle;
    if (options?.cursor) params.cursor = options.cursor;
    if (options?.limit) params.limit = String(options.limit);
    return xrpc("com.atproto.admin.searchAccounts", { token, params });
  },

  getInviteCodes(token: string, options?: {
    sort?: "recent" | "usage";
    cursor?: string;
    limit?: number;
  }): Promise<{
    cursor?: string;
    codes: Array<{
      code: string;
      available: number;
      disabled: boolean;
      forAccount: string;
      createdBy: string;
      createdAt: string;
      uses: Array<{ usedBy: string; usedAt: string }>;
    }>;
  }> {
    const params: Record<string, string> = {};
    if (options?.sort) params.sort = options.sort;
    if (options?.cursor) params.cursor = options.cursor;
    if (options?.limit) params.limit = String(options.limit);
    return xrpc("com.atproto.admin.getInviteCodes", { token, params });
  },

  async disableInviteCodes(
    token: string,
    codes?: string[],
    accounts?: string[],
  ): Promise<void> {
    await xrpc("com.atproto.admin.disableInviteCodes", {
      method: "POST",
      token,
      body: { codes, accounts },
    });
  },

  getAccountInfo(token: string, did: string): Promise<{
    did: string;
    handle: string;
    email?: string;
    indexedAt: string;
    emailConfirmedAt?: string;
    invitesDisabled?: boolean;
    deactivatedAt?: string;
  }> {
    return xrpc("com.atproto.admin.getAccountInfo", { token, params: { did } });
  },

  async disableAccountInvites(token: string, account: string): Promise<void> {
    await xrpc("com.atproto.admin.disableAccountInvites", {
      method: "POST",
      token,
      body: { account },
    });
  },

  async enableAccountInvites(token: string, account: string): Promise<void> {
    await xrpc("com.atproto.admin.enableAccountInvites", {
      method: "POST",
      token,
      body: { account },
    });
  },

  async adminDeleteAccount(token: string, did: string): Promise<void> {
    await xrpc("com.atproto.admin.deleteAccount", {
      method: "POST",
      token,
      body: { did },
    });
  },

  describeRepo(token: string, repo: string): Promise<{
    handle: string;
    did: string;
    didDoc: unknown;
    collections: string[];
    handleIsCorrect: boolean;
  }> {
    return xrpc("com.atproto.repo.describeRepo", {
      token,
      params: { repo },
    });
  },

  listRecords(token: string, repo: string, collection: string, options?: {
    limit?: number;
    cursor?: string;
    reverse?: boolean;
  }): Promise<{
    records: Array<{ uri: string; cid: string; value: unknown }>;
    cursor?: string;
  }> {
    const params: Record<string, string> = { repo, collection };
    if (options?.limit) params.limit = String(options.limit);
    if (options?.cursor) params.cursor = options.cursor;
    if (options?.reverse) params.reverse = "true";
    return xrpc("com.atproto.repo.listRecords", { token, params });
  },

  getRecord(
    token: string,
    repo: string,
    collection: string,
    rkey: string,
  ): Promise<{
    uri: string;
    cid: string;
    value: unknown;
  }> {
    return xrpc("com.atproto.repo.getRecord", {
      token,
      params: { repo, collection, rkey },
    });
  },

  createRecord(
    token: string,
    repo: string,
    collection: string,
    record: unknown,
    rkey?: string,
  ): Promise<{
    uri: string;
    cid: string;
  }> {
    return xrpc("com.atproto.repo.createRecord", {
      method: "POST",
      token,
      body: { repo, collection, record, rkey },
    });
  },

  putRecord(
    token: string,
    repo: string,
    collection: string,
    rkey: string,
    record: unknown,
  ): Promise<{
    uri: string;
    cid: string;
  }> {
    return xrpc("com.atproto.repo.putRecord", {
      method: "POST",
      token,
      body: { repo, collection, rkey, record },
    });
  },

  async deleteRecord(
    token: string,
    repo: string,
    collection: string,
    rkey: string,
  ): Promise<void> {
    await xrpc("com.atproto.repo.deleteRecord", {
      method: "POST",
      token,
      body: { repo, collection, rkey },
    });
  },

  getTotpStatus(
    token: string,
  ): Promise<{ enabled: boolean; hasBackupCodes: boolean }> {
    return xrpc("com.atproto.server.getTotpStatus", { token });
  },

  createTotpSecret(
    token: string,
  ): Promise<{ uri: string; qrBase64: string }> {
    return xrpc("com.atproto.server.createTotpSecret", {
      method: "POST",
      token,
    });
  },

  enableTotp(
    token: string,
    code: string,
  ): Promise<{ success: boolean; backupCodes: string[] }> {
    return xrpc("com.atproto.server.enableTotp", {
      method: "POST",
      token,
      body: { code },
    });
  },

  disableTotp(
    token: string,
    password: string,
    code: string,
  ): Promise<{ success: boolean }> {
    return xrpc("com.atproto.server.disableTotp", {
      method: "POST",
      token,
      body: { password, code },
    });
  },

  regenerateBackupCodes(
    token: string,
    password: string,
    code: string,
  ): Promise<{ backupCodes: string[] }> {
    return xrpc("com.atproto.server.regenerateBackupCodes", {
      method: "POST",
      token,
      body: { password, code },
    });
  },

  startPasskeyRegistration(
    token: string,
    friendlyName?: string,
  ): Promise<{ options: unknown }> {
    return xrpc("com.atproto.server.startPasskeyRegistration", {
      method: "POST",
      token,
      body: { friendlyName },
    });
  },

  finishPasskeyRegistration(
    token: string,
    credential: unknown,
    friendlyName?: string,
  ): Promise<{ id: string; credentialId: string }> {
    return xrpc("com.atproto.server.finishPasskeyRegistration", {
      method: "POST",
      token,
      body: { credential, friendlyName },
    });
  },

  listPasskeys(token: string): Promise<{
    passkeys: Array<{
      id: string;
      credentialId: string;
      friendlyName: string | null;
      createdAt: string;
      lastUsed: string | null;
    }>;
  }> {
    return xrpc("com.atproto.server.listPasskeys", { token });
  },

  async deletePasskey(token: string, id: string): Promise<void> {
    await xrpc("com.atproto.server.deletePasskey", {
      method: "POST",
      token,
      body: { id },
    });
  },

  async updatePasskey(
    token: string,
    id: string,
    friendlyName: string,
  ): Promise<void> {
    await xrpc("com.atproto.server.updatePasskey", {
      method: "POST",
      token,
      body: { id, friendlyName },
    });
  },

  listTrustedDevices(token: string): Promise<{
    devices: Array<{
      id: string;
      userAgent: string | null;
      friendlyName: string | null;
      trustedAt: string | null;
      trustedUntil: string | null;
      lastSeenAt: string;
    }>;
  }> {
    return xrpc("_account.listTrustedDevices", { token });
  },

  revokeTrustedDevice(
    token: string,
    deviceId: string,
  ): Promise<{ success: boolean }> {
    return xrpc("_account.revokeTrustedDevice", {
      method: "POST",
      token,
      body: { deviceId },
    });
  },

  updateTrustedDevice(
    token: string,
    deviceId: string,
    friendlyName: string,
  ): Promise<{ success: boolean }> {
    return xrpc("_account.updateTrustedDevice", {
      method: "POST",
      token,
      body: { deviceId, friendlyName },
    });
  },

  getReauthStatus(token: string): Promise<{
    requiresReauth: boolean;
    lastReauthAt: string | null;
    availableMethods: string[];
  }> {
    return xrpc("_account.getReauthStatus", { token });
  },

  reauthPassword(
    token: string,
    password: string,
  ): Promise<{ success: boolean; reauthAt: string }> {
    return xrpc("_account.reauthPassword", {
      method: "POST",
      token,
      body: { password },
    });
  },

  reauthTotp(
    token: string,
    code: string,
  ): Promise<{ success: boolean; reauthAt: string }> {
    return xrpc("_account.reauthTotp", {
      method: "POST",
      token,
      body: { code },
    });
  },

  reauthPasskeyStart(token: string): Promise<{ options: unknown }> {
    return xrpc("_account.reauthPasskeyStart", {
      method: "POST",
      token,
    });
  },

  reauthPasskeyFinish(
    token: string,
    credential: unknown,
  ): Promise<{ success: boolean; reauthAt: string }> {
    return xrpc("_account.reauthPasskeyFinish", {
      method: "POST",
      token,
      body: { credential },
    });
  },

  reserveSigningKey(did?: string): Promise<{ signingKey: string }> {
    return xrpc("com.atproto.server.reserveSigningKey", {
      method: "POST",
      body: { did },
    });
  },

  getRecommendedDidCredentials(token: string): Promise<{
    rotationKeys?: string[];
    alsoKnownAs?: string[];
    verificationMethods?: { atproto?: string };
    services?: { atproto_pds?: { type: string; endpoint: string } };
  }> {
    return xrpc("com.atproto.identity.getRecommendedDidCredentials", { token });
  },

  async activateAccount(token: string): Promise<void> {
    await xrpc("com.atproto.server.activateAccount", {
      method: "POST",
      token,
    });
  },

  async createPasskeyAccount(params: {
    handle: string;
    email?: string;
    inviteCode?: string;
    didType?: DidType;
    did?: string;
    signingKey?: string;
    verificationChannel?: VerificationChannel;
    discordId?: string;
    telegramUsername?: string;
    signalNumber?: string;
  }, byodToken?: string): Promise<{
    did: string;
    handle: string;
    setupToken: string;
    setupExpiresAt: string;
  }> {
    const url = `${API_BASE}/_account.createPasskeyAccount`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (byodToken) {
      headers["Authorization"] = `Bearer ${byodToken}`;
    }
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(params),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({
        error: "Unknown",
        message: res.statusText,
      }));
      throw new ApiError(res.status, err.error, err.message);
    }
    return res.json();
  },

  startPasskeyRegistrationForSetup(
    did: string,
    setupToken: string,
    friendlyName?: string,
  ): Promise<{ options: unknown }> {
    return xrpc("_account.startPasskeyRegistrationForSetup", {
      method: "POST",
      body: { did, setupToken, friendlyName },
    });
  },

  completePasskeySetup(
    did: string,
    setupToken: string,
    passkeyCredential: unknown,
    passkeyFriendlyName?: string,
  ): Promise<{
    did: string;
    handle: string;
    appPassword: string;
    appPasswordName: string;
  }> {
    return xrpc("_account.completePasskeySetup", {
      method: "POST",
      body: { did, setupToken, passkeyCredential, passkeyFriendlyName },
    });
  },

  requestPasskeyRecovery(email: string): Promise<{ success: boolean }> {
    return xrpc("_account.requestPasskeyRecovery", {
      method: "POST",
      body: { email },
    });
  },

  recoverPasskeyAccount(
    did: string,
    recoveryToken: string,
    newPassword: string,
  ): Promise<{ success: boolean }> {
    return xrpc("_account.recoverPasskeyAccount", {
      method: "POST",
      body: { did, recoveryToken, newPassword },
    });
  },

  verifyMigrationEmail(
    token: string,
    email: string,
  ): Promise<{ success: boolean; did: string }> {
    return xrpc("com.atproto.server.verifyMigrationEmail", {
      method: "POST",
      body: { token, email },
    });
  },

  resendMigrationVerification(email: string): Promise<{ sent: boolean }> {
    return xrpc("com.atproto.server.resendMigrationVerification", {
      method: "POST",
      body: { email },
    });
  },

  verifyToken(
    token: string,
    identifier: string,
    accessToken?: string,
  ): Promise<{
    success: boolean;
    did: string;
    purpose: string;
    channel: string;
  }> {
    return xrpc("_account.verifyToken", {
      method: "POST",
      body: { token, identifier },
      token: accessToken,
    });
  },

  getDidDocument(token: string): Promise<DidDocument> {
    return xrpc("_account.getDidDocument", { token });
  },

  updateDidDocument(
    token: string,
    params: {
      verificationMethods?: VerificationMethod[];
      alsoKnownAs?: string[];
      serviceEndpoint?: string;
    },
  ): Promise<{ success: boolean }> {
    return xrpc("_account.updateDidDocument", {
      method: "POST",
      token,
      body: params,
    });
  },

  async deactivateAccount(
    token: string,
    deleteAfter?: string,
  ): Promise<void> {
    await xrpc("com.atproto.server.deactivateAccount", {
      method: "POST",
      token,
      body: { deleteAfter },
    });
  },

  async getRepo(token: string, did: string): Promise<ArrayBuffer> {
    const url = `${API_BASE}/com.atproto.sync.getRepo?did=${
      encodeURIComponent(did)
    }`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({
        error: "Unknown",
        message: res.statusText,
      }));
      throw new ApiError(res.status, err.error, err.message);
    }
    return res.arrayBuffer();
  },

  listBackups(token: string): Promise<{
    backups: Array<{
      id: string;
      repoRev: string;
      repoRootCid: string;
      blockCount: number;
      sizeBytes: number;
      createdAt: string;
    }>;
    backupEnabled: boolean;
  }> {
    return xrpc("_backup.listBackups", { token });
  },

  async getBackup(token: string, id: string): Promise<Blob> {
    const url = `${API_BASE}/_backup.getBackup?id=${encodeURIComponent(id)}`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({
        error: "Unknown",
        message: res.statusText,
      }));
      throw new ApiError(res.status, err.error, err.message);
    }
    return res.blob();
  },

  createBackup(token: string): Promise<{
    id: string;
    repoRev: string;
    sizeBytes: number;
    blockCount: number;
  }> {
    return xrpc("_backup.createBackup", {
      method: "POST",
      token,
    });
  },

  async deleteBackup(token: string, id: string): Promise<void> {
    await xrpc("_backup.deleteBackup", {
      method: "POST",
      token,
      params: { id },
    });
  },

  setBackupEnabled(
    token: string,
    enabled: boolean,
  ): Promise<{ enabled: boolean }> {
    return xrpc("_backup.setEnabled", {
      method: "POST",
      token,
      body: { enabled },
    });
  },

  async importRepo(token: string, car: Uint8Array): Promise<void> {
    const url = `${API_BASE}/com.atproto.repo.importRepo`;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/vnd.ipld.car",
      },
      body: car,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({
        error: "Unknown",
        message: res.statusText,
      }));
      throw new ApiError(res.status, err.error, err.message);
    }
  },
};
