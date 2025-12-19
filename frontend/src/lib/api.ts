const API_BASE = '/xrpc'

export class ApiError extends Error {
  public did?: string
  constructor(public status: number, public error: string, message: string, did?: string) {
    super(message)
    this.name = 'ApiError'
    this.did = did
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
    throw new ApiError(res.status, err.error, err.message, err.did)
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

export interface CreateAccountParams {
  handle: string
  email: string
  password: string
  inviteCode?: string
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

  async requestEmailUpdate(token: string): Promise<{ tokenRequired: boolean }> {
    return xrpc('com.atproto.server.requestEmailUpdate', {
      method: 'POST',
      token,
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

  async listSessions(token: string): Promise<{
    sessions: Array<{
      id: string
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
}
