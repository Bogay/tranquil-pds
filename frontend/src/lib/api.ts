const API_BASE = '/xrpc'

export class ApiError extends Error {
  public did?: string
  public reauthMethods?: string[]
  constructor(public status: number, public error: string, message: string, did?: string, reauthMethods?: string[]) {
    super(message)
    this.name = 'ApiError'
    this.did = did
    this.reauthMethods = reauthMethods
  }
}

async function xrpc<T>(method: string, options?: {
  method?: 'GET' | 'POST'
  params?: Record<string, string>
  body?: unknown
  token?: string
}): Promise<T> {
  const { method: httpMethod = 'GET', params, body, token } = options ?? {}
  let url = `${API_BASE}/${method}`
  if (params) {
    const searchParams = new URLSearchParams(params)
    url += `?${searchParams}`
  }
  const headers: Record<string, string> = {}
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  if (body) {
    headers['Content-Type'] = 'application/json'
  }
  const res = await fetch(url, {
    method: httpMethod,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Unknown', message: res.statusText }))
    throw new ApiError(res.status, err.error, err.message, err.did, err.reauthMethods)
  }
  return res.json()
}

export interface Session {
  did: string
  handle: string
  email?: string
  emailConfirmed?: boolean
  preferredChannel?: string
  preferredChannelVerified?: boolean
  isAdmin?: boolean
  active?: boolean
  status?: 'active' | 'deactivated'
  accessJwt: string
  refreshJwt: string
}

export interface AppPassword {
  name: string
  createdAt: string
}

export interface InviteCode {
  code: string
  available: number
  disabled: boolean
  forAccount: string
  createdBy: string
  createdAt: string
  uses: { usedBy: string; usedAt: string }[]
}

export type VerificationChannel = 'email' | 'discord' | 'telegram' | 'signal'

export type DidType = 'plc' | 'web' | 'web-external'

export interface CreateAccountParams {
  handle: string
  email: string
  password: string
  inviteCode?: string
  didType?: DidType
  did?: string
  verificationChannel?: VerificationChannel
  discordId?: string
  telegramUsername?: string
  signalNumber?: string
}

export interface CreateAccountResult {
  handle: string
  did: string
  verificationRequired: boolean
  verificationChannel: string
}

export interface ConfirmSignupResult {
  accessJwt: string
  refreshJwt: string
  handle: string
  did: string
  email?: string
  emailConfirmed?: boolean
  preferredChannel?: string
  preferredChannelVerified?: boolean
}

export const api = {
  async createAccount(params: CreateAccountParams): Promise<CreateAccountResult> {
    return xrpc('com.atproto.server.createAccount', {
      method: 'POST',
      body: {
        handle: params.handle,
        email: params.email,
        password: params.password,
        inviteCode: params.inviteCode,
        didType: params.didType,
        did: params.did,
        verificationChannel: params.verificationChannel,
        discordId: params.discordId,
        telegramUsername: params.telegramUsername,
        signalNumber: params.signalNumber,
      },
    })
  },

  async confirmSignup(did: string, verificationCode: string): Promise<ConfirmSignupResult> {
    return xrpc('com.atproto.server.confirmSignup', {
      method: 'POST',
      body: { did, verificationCode },
    })
  },

  async resendVerification(did: string): Promise<{ success: boolean }> {
    return xrpc('com.atproto.server.resendVerification', {
      method: 'POST',
      body: { did },
    })
  },

  async createSession(identifier: string, password: string): Promise<Session> {
    return xrpc('com.atproto.server.createSession', {
      method: 'POST',
      body: { identifier, password },
    })
  },

  async getSession(token: string): Promise<Session> {
    return xrpc('com.atproto.server.getSession', { token })
  },

  async refreshSession(refreshJwt: string): Promise<Session> {
    return xrpc('com.atproto.server.refreshSession', {
      method: 'POST',
      token: refreshJwt,
    })
  },

  async deleteSession(token: string): Promise<void> {
    await xrpc('com.atproto.server.deleteSession', {
      method: 'POST',
      token,
    })
  },

  async listAppPasswords(token: string): Promise<{ passwords: AppPassword[] }> {
    return xrpc('com.atproto.server.listAppPasswords', { token })
  },

  async createAppPassword(token: string, name: string): Promise<{ name: string; password: string; createdAt: string }> {
    return xrpc('com.atproto.server.createAppPassword', {
      method: 'POST',
      token,
      body: { name },
    })
  },

  async revokeAppPassword(token: string, name: string): Promise<void> {
    await xrpc('com.atproto.server.revokeAppPassword', {
      method: 'POST',
      token,
      body: { name },
    })
  },

  async getAccountInviteCodes(token: string): Promise<{ codes: InviteCode[] }> {
    return xrpc('com.atproto.server.getAccountInviteCodes', { token })
  },

  async createInviteCode(token: string, useCount: number = 1): Promise<{ code: string }> {
    return xrpc('com.atproto.server.createInviteCode', {
      method: 'POST',
      token,
      body: { useCount },
    })
  },

  async requestPasswordReset(email: string): Promise<void> {
    await xrpc('com.atproto.server.requestPasswordReset', {
      method: 'POST',
      body: { email },
    })
  },

  async resetPassword(token: string, password: string): Promise<void> {
    await xrpc('com.atproto.server.resetPassword', {
      method: 'POST',
      body: { token, password },
    })
  },

  async requestEmailUpdate(token: string, email: string): Promise<{ tokenRequired: boolean }> {
    return xrpc('com.atproto.server.requestEmailUpdate', {
      method: 'POST',
      token,
      body: { email },
    })
  },

  async updateEmail(token: string, email: string, emailToken?: string): Promise<void> {
    await xrpc('com.atproto.server.updateEmail', {
      method: 'POST',
      token,
      body: { email, token: emailToken },
    })
  },

  async updateHandle(token: string, handle: string): Promise<void> {
    await xrpc('com.atproto.identity.updateHandle', {
      method: 'POST',
      token,
      body: { handle },
    })
  },

  async requestAccountDelete(token: string): Promise<void> {
    await xrpc('com.atproto.server.requestAccountDelete', {
      method: 'POST',
      token,
    })
  },

  async deleteAccount(did: string, password: string, deleteToken: string): Promise<void> {
    await xrpc('com.atproto.server.deleteAccount', {
      method: 'POST',
      body: { did, password, token: deleteToken },
    })
  },

  async describeServer(): Promise<{
    availableUserDomains: string[]
    inviteCodeRequired: boolean
    links?: { privacyPolicy?: string; termsOfService?: string }
  }> {
    return xrpc('com.atproto.server.describeServer')
  },

  async getNotificationPrefs(token: string): Promise<{
    preferredChannel: string
    email: string
    discordId: string | null
    discordVerified: boolean
    telegramUsername: string | null
    telegramVerified: boolean
    signalNumber: string | null
    signalVerified: boolean
  }> {
    return xrpc('com.tranquil.account.getNotificationPrefs', { token })
  },

  async updateNotificationPrefs(token: string, prefs: {
    preferredChannel?: string
    discordId?: string
    telegramUsername?: string
    signalNumber?: string
  }): Promise<{ success: boolean }> {
    return xrpc('com.tranquil.account.updateNotificationPrefs', {
      method: 'POST',
      token,
      body: prefs,
    })
  },

  async confirmChannelVerification(token: string, channel: string, code: string): Promise<{ success: boolean }> {
    return xrpc('com.tranquil.account.confirmChannelVerification', {
      method: 'POST',
      token,
      body: { channel, code },
    })
  },

  async getNotificationHistory(token: string): Promise<{
    notifications: Array<{
      createdAt: string
      channel: string
      notificationType: string
      status: string
      subject: string | null
      body: string
    }>
  }> {
    return xrpc('com.tranquil.account.getNotificationHistory', { token })
  },

  async getServerStats(token: string): Promise<{
    userCount: number
    repoCount: number
    recordCount: number
    blobStorageBytes: number
  }> {
    return xrpc('com.tranquil.admin.getServerStats', { token })
  },

  async changePassword(token: string, currentPassword: string, newPassword: string): Promise<void> {
    await xrpc('com.tranquil.account.changePassword', {
      method: 'POST',
      token,
      body: { currentPassword, newPassword },
    })
  },

  async removePassword(token: string): Promise<{ success: boolean }> {
    return xrpc('com.tranquil.account.removePassword', {
      method: 'POST',
      token,
    })
  },

  async getPasswordStatus(token: string): Promise<{ hasPassword: boolean }> {
    return xrpc('com.tranquil.account.getPasswordStatus', { token })
  },

  async getLegacyLoginPreference(token: string): Promise<{ allowLegacyLogin: boolean; hasMfa: boolean }> {
    return xrpc('com.tranquil.account.getLegacyLoginPreference', { token })
  },

  async updateLegacyLoginPreference(token: string, allowLegacyLogin: boolean): Promise<{ allowLegacyLogin: boolean }> {
    return xrpc('com.tranquil.account.updateLegacyLoginPreference', {
      method: 'POST',
      token,
      body: { allowLegacyLogin },
    })
  },

  async updateLocale(token: string, preferredLocale: string): Promise<{ preferredLocale: string }> {
    return xrpc('com.tranquil.account.updateLocale', {
      method: 'POST',
      token,
      body: { preferredLocale },
    })
  },

  async listSessions(token: string): Promise<{
    sessions: Array<{
      id: string
      sessionType: string
      clientName: string | null
      createdAt: string
      expiresAt: string
      isCurrent: boolean
    }>
  }> {
    return xrpc('com.tranquil.account.listSessions', { token })
  },

  async revokeSession(token: string, sessionId: string): Promise<void> {
    await xrpc('com.tranquil.account.revokeSession', {
      method: 'POST',
      token,
      body: { sessionId },
    })
  },

  async revokeAllSessions(token: string): Promise<{ revokedCount: number }> {
    return xrpc('com.tranquil.account.revokeAllSessions', {
      method: 'POST',
      token,
    })
  },

  async searchAccounts(token: string, options?: {
    handle?: string
    cursor?: string
    limit?: number
  }): Promise<{
    cursor?: string
    accounts: Array<{
      did: string
      handle: string
      email?: string
      indexedAt: string
      emailConfirmedAt?: string
      deactivatedAt?: string
    }>
  }> {
    const params: Record<string, string> = {}
    if (options?.handle) params.handle = options.handle
    if (options?.cursor) params.cursor = options.cursor
    if (options?.limit) params.limit = String(options.limit)
    return xrpc('com.atproto.admin.searchAccounts', { token, params })
  },

  async getInviteCodes(token: string, options?: {
    sort?: 'recent' | 'usage'
    cursor?: string
    limit?: number
  }): Promise<{
    cursor?: string
    codes: Array<{
      code: string
      available: number
      disabled: boolean
      forAccount: string
      createdBy: string
      createdAt: string
      uses: Array<{ usedBy: string; usedAt: string }>
    }>
  }> {
    const params: Record<string, string> = {}
    if (options?.sort) params.sort = options.sort
    if (options?.cursor) params.cursor = options.cursor
    if (options?.limit) params.limit = String(options.limit)
    return xrpc('com.atproto.admin.getInviteCodes', { token, params })
  },

  async disableInviteCodes(token: string, codes?: string[], accounts?: string[]): Promise<void> {
    await xrpc('com.atproto.admin.disableInviteCodes', {
      method: 'POST',
      token,
      body: { codes, accounts },
    })
  },

  async getAccountInfo(token: string, did: string): Promise<{
    did: string
    handle: string
    email?: string
    indexedAt: string
    emailConfirmedAt?: string
    invitesDisabled?: boolean
    deactivatedAt?: string
  }> {
    return xrpc('com.atproto.admin.getAccountInfo', { token, params: { did } })
  },

  async disableAccountInvites(token: string, account: string): Promise<void> {
    await xrpc('com.atproto.admin.disableAccountInvites', {
      method: 'POST',
      token,
      body: { account },
    })
  },

  async enableAccountInvites(token: string, account: string): Promise<void> {
    await xrpc('com.atproto.admin.enableAccountInvites', {
      method: 'POST',
      token,
      body: { account },
    })
  },

  async adminDeleteAccount(token: string, did: string): Promise<void> {
    await xrpc('com.atproto.admin.deleteAccount', {
      method: 'POST',
      token,
      body: { did },
    })
  },

  async describeRepo(token: string, repo: string): Promise<{
    handle: string
    did: string
    didDoc: unknown
    collections: string[]
    handleIsCorrect: boolean
  }> {
    return xrpc('com.atproto.repo.describeRepo', {
      token,
      params: { repo },
    })
  },

  async listRecords(token: string, repo: string, collection: string, options?: {
    limit?: number
    cursor?: string
    reverse?: boolean
  }): Promise<{
    records: Array<{ uri: string; cid: string; value: unknown }>
    cursor?: string
  }> {
    const params: Record<string, string> = { repo, collection }
    if (options?.limit) params.limit = String(options.limit)
    if (options?.cursor) params.cursor = options.cursor
    if (options?.reverse) params.reverse = 'true'
    return xrpc('com.atproto.repo.listRecords', { token, params })
  },

  async getRecord(token: string, repo: string, collection: string, rkey: string): Promise<{
    uri: string
    cid: string
    value: unknown
  }> {
    return xrpc('com.atproto.repo.getRecord', {
      token,
      params: { repo, collection, rkey },
    })
  },

  async createRecord(token: string, repo: string, collection: string, record: unknown, rkey?: string): Promise<{
    uri: string
    cid: string
  }> {
    return xrpc('com.atproto.repo.createRecord', {
      method: 'POST',
      token,
      body: { repo, collection, record, rkey },
    })
  },

  async putRecord(token: string, repo: string, collection: string, rkey: string, record: unknown): Promise<{
    uri: string
    cid: string
  }> {
    return xrpc('com.atproto.repo.putRecord', {
      method: 'POST',
      token,
      body: { repo, collection, rkey, record },
    })
  },

  async deleteRecord(token: string, repo: string, collection: string, rkey: string): Promise<void> {
    await xrpc('com.atproto.repo.deleteRecord', {
      method: 'POST',
      token,
      body: { repo, collection, rkey },
    })
  },

  async getTotpStatus(token: string): Promise<{ enabled: boolean; hasBackupCodes: boolean }> {
    return xrpc('com.atproto.server.getTotpStatus', { token })
  },

  async createTotpSecret(token: string): Promise<{ uri: string; qrBase64: string }> {
    return xrpc('com.atproto.server.createTotpSecret', { method: 'POST', token })
  },

  async enableTotp(token: string, code: string): Promise<{ success: boolean; backupCodes: string[] }> {
    return xrpc('com.atproto.server.enableTotp', {
      method: 'POST',
      token,
      body: { code },
    })
  },

  async disableTotp(token: string, password: string, code: string): Promise<{ success: boolean }> {
    return xrpc('com.atproto.server.disableTotp', {
      method: 'POST',
      token,
      body: { password, code },
    })
  },

  async regenerateBackupCodes(token: string, password: string, code: string): Promise<{ backupCodes: string[] }> {
    return xrpc('com.atproto.server.regenerateBackupCodes', {
      method: 'POST',
      token,
      body: { password, code },
    })
  },

  async startPasskeyRegistration(token: string, friendlyName?: string): Promise<{ options: unknown }> {
    return xrpc('com.atproto.server.startPasskeyRegistration', {
      method: 'POST',
      token,
      body: { friendlyName },
    })
  },

  async finishPasskeyRegistration(token: string, credential: unknown, friendlyName?: string): Promise<{ id: string; credentialId: string }> {
    return xrpc('com.atproto.server.finishPasskeyRegistration', {
      method: 'POST',
      token,
      body: { credential, friendlyName },
    })
  },

  async listPasskeys(token: string): Promise<{
    passkeys: Array<{
      id: string
      credentialId: string
      friendlyName: string | null
      createdAt: string
      lastUsed: string | null
    }>
  }> {
    return xrpc('com.atproto.server.listPasskeys', { token })
  },

  async deletePasskey(token: string, id: string): Promise<void> {
    await xrpc('com.atproto.server.deletePasskey', {
      method: 'POST',
      token,
      body: { id },
    })
  },

  async updatePasskey(token: string, id: string, friendlyName: string): Promise<void> {
    await xrpc('com.atproto.server.updatePasskey', {
      method: 'POST',
      token,
      body: { id, friendlyName },
    })
  },

  async listTrustedDevices(token: string): Promise<{
    devices: Array<{
      id: string
      userAgent: string | null
      friendlyName: string | null
      trustedAt: string | null
      trustedUntil: string | null
      lastSeenAt: string
    }>
  }> {
    return xrpc('com.tranquil.account.listTrustedDevices', { token })
  },

  async revokeTrustedDevice(token: string, deviceId: string): Promise<{ success: boolean }> {
    return xrpc('com.tranquil.account.revokeTrustedDevice', {
      method: 'POST',
      token,
      body: { deviceId },
    })
  },

  async updateTrustedDevice(token: string, deviceId: string, friendlyName: string): Promise<{ success: boolean }> {
    return xrpc('com.tranquil.account.updateTrustedDevice', {
      method: 'POST',
      token,
      body: { deviceId, friendlyName },
    })
  },

  async getReauthStatus(token: string): Promise<{
    requiresReauth: boolean
    lastReauthAt: string | null
    availableMethods: string[]
  }> {
    return xrpc('com.tranquil.account.getReauthStatus', { token })
  },

  async reauthPassword(token: string, password: string): Promise<{ success: boolean; reauthAt: string }> {
    return xrpc('com.tranquil.account.reauthPassword', {
      method: 'POST',
      token,
      body: { password },
    })
  },

  async reauthTotp(token: string, code: string): Promise<{ success: boolean; reauthAt: string }> {
    return xrpc('com.tranquil.account.reauthTotp', {
      method: 'POST',
      token,
      body: { code },
    })
  },

  async reauthPasskeyStart(token: string): Promise<{ options: unknown }> {
    return xrpc('com.tranquil.account.reauthPasskeyStart', {
      method: 'POST',
      token,
    })
  },

  async reauthPasskeyFinish(token: string, credential: unknown): Promise<{ success: boolean; reauthAt: string }> {
    return xrpc('com.tranquil.account.reauthPasskeyFinish', {
      method: 'POST',
      token,
      body: { credential },
    })
  },

  async createPasskeyAccount(params: {
    handle: string
    email?: string
    inviteCode?: string
    didType?: DidType
    did?: string
    signingKey?: string
    verificationChannel?: VerificationChannel
    discordId?: string
    telegramUsername?: string
    signalNumber?: string
  }): Promise<{
    did: string
    handle: string
    setupToken: string
    setupExpiresAt: string
  }> {
    return xrpc('com.tranquil.account.createPasskeyAccount', {
      method: 'POST',
      body: params,
    })
  },

  async startPasskeyRegistrationForSetup(did: string, setupToken: string, friendlyName?: string): Promise<{ options: unknown }> {
    return xrpc('com.tranquil.account.startPasskeyRegistrationForSetup', {
      method: 'POST',
      body: { did, setupToken, friendlyName },
    })
  },

  async completePasskeySetup(did: string, setupToken: string, passkeyCredential: unknown, passkeyFriendlyName?: string): Promise<{
    did: string
    handle: string
    appPassword: string
    appPasswordName: string
  }> {
    return xrpc('com.tranquil.account.completePasskeySetup', {
      method: 'POST',
      body: { did, setupToken, passkeyCredential, passkeyFriendlyName },
    })
  },

  async requestPasskeyRecovery(email: string): Promise<{ success: boolean }> {
    return xrpc('com.tranquil.account.requestPasskeyRecovery', {
      method: 'POST',
      body: { email },
    })
  },

  async recoverPasskeyAccount(did: string, recoveryToken: string, newPassword: string): Promise<{ success: boolean }> {
    return xrpc('com.tranquil.account.recoverPasskeyAccount', {
      method: 'POST',
      body: { did, recoveryToken, newPassword },
    })
  },
}
