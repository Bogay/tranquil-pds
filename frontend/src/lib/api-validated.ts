import { z } from 'zod'
import { ok, err, type Result } from './types/result'
import { ApiError } from './api'
import type { AccessToken, RefreshToken, Did, Handle, Nsid, Rkey } from './types/branded'
import {
  sessionSchema,
  serverDescriptionSchema,
  appPasswordSchema,
  createdAppPasswordSchema,
  listSessionsResponseSchema,
  totpStatusSchema,
  totpSecretSchema,
  enableTotpResponseSchema,
  listPasskeysResponseSchema,
  listTrustedDevicesResponseSchema,
  reauthStatusSchema,
  notificationPrefsSchema,
  didDocumentSchema,
  repoDescriptionSchema,
  listRecordsResponseSchema,
  recordResponseSchema,
  createRecordResponseSchema,
  serverStatsSchema,
  serverConfigSchema,
  passwordStatusSchema,
  successResponseSchema,
  legacyLoginPreferenceSchema,
  accountInfoSchema,
  searchAccountsResponseSchema,
  listBackupsResponseSchema,
  createBackupResponseSchema,
  type ValidatedSession,
  type ValidatedServerDescription,
  type ValidatedListSessionsResponse,
  type ValidatedTotpStatus,
  type ValidatedTotpSecret,
  type ValidatedEnableTotpResponse,
  type ValidatedListPasskeysResponse,
  type ValidatedListTrustedDevicesResponse,
  type ValidatedReauthStatus,
  type ValidatedNotificationPrefs,
  type ValidatedDidDocument,
  type ValidatedRepoDescription,
  type ValidatedListRecordsResponse,
  type ValidatedRecordResponse,
  type ValidatedCreateRecordResponse,
  type ValidatedServerStats,
  type ValidatedServerConfig,
  type ValidatedPasswordStatus,
  type ValidatedSuccessResponse,
  type ValidatedLegacyLoginPreference,
  type ValidatedAccountInfo,
  type ValidatedSearchAccountsResponse,
  type ValidatedListBackupsResponse,
  type ValidatedCreateBackupResponse,
  type ValidatedCreatedAppPassword,
  type ValidatedAppPassword,
} from './types/schemas'

const API_BASE = '/xrpc'

interface XrpcOptions {
  method?: 'GET' | 'POST'
  params?: Record<string, string>
  body?: unknown
  token?: string
}

class ValidationError extends Error {
  constructor(
    public issues: z.ZodIssue[],
    message: string = 'API response validation failed'
  ) {
    super(message)
    this.name = 'ValidationError'
  }
}

async function xrpcValidated<T>(
  method: string,
  schema: z.ZodType<T>,
  options?: XrpcOptions
): Promise<Result<T, ApiError | ValidationError>> {
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

  try {
    const res = await fetch(url, {
      method: httpMethod,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    })

    if (!res.ok) {
      const errData = await res.json().catch(() => ({
        error: 'Unknown',
        message: res.statusText,
      }))
      return err(new ApiError(res.status, errData.error, errData.message))
    }

    const data = await res.json()
    const parsed = schema.safeParse(data)

    if (!parsed.success) {
      return err(new ValidationError(parsed.error.issues))
    }

    return ok(parsed.data)
  } catch (e) {
    if (e instanceof ApiError || e instanceof ValidationError) {
      return err(e)
    }
    return err(new ApiError(0, 'Unknown', e instanceof Error ? e.message : String(e)))
  }
}

export const validatedApi = {
  getSession(token: AccessToken): Promise<Result<ValidatedSession, ApiError | ValidationError>> {
    return xrpcValidated('com.atproto.server.getSession', sessionSchema, { token })
  },

  refreshSession(refreshJwt: RefreshToken): Promise<Result<ValidatedSession, ApiError | ValidationError>> {
    return xrpcValidated('com.atproto.server.refreshSession', sessionSchema, {
      method: 'POST',
      token: refreshJwt,
    })
  },

  createSession(
    identifier: string,
    password: string
  ): Promise<Result<ValidatedSession, ApiError | ValidationError>> {
    return xrpcValidated('com.atproto.server.createSession', sessionSchema, {
      method: 'POST',
      body: { identifier, password },
    })
  },

  describeServer(): Promise<Result<ValidatedServerDescription, ApiError | ValidationError>> {
    return xrpcValidated('com.atproto.server.describeServer', serverDescriptionSchema)
  },

  listAppPasswords(
    token: AccessToken
  ): Promise<Result<{ passwords: ValidatedAppPassword[] }, ApiError | ValidationError>> {
    return xrpcValidated(
      'com.atproto.server.listAppPasswords',
      z.object({ passwords: z.array(appPasswordSchema) }),
      { token }
    )
  },

  createAppPassword(
    token: AccessToken,
    name: string,
    scopes?: string
  ): Promise<Result<ValidatedCreatedAppPassword, ApiError | ValidationError>> {
    return xrpcValidated('com.atproto.server.createAppPassword', createdAppPasswordSchema, {
      method: 'POST',
      token,
      body: { name, scopes },
    })
  },

  listSessions(token: AccessToken): Promise<Result<ValidatedListSessionsResponse, ApiError | ValidationError>> {
    return xrpcValidated('_account.listSessions', listSessionsResponseSchema, { token })
  },

  getTotpStatus(token: AccessToken): Promise<Result<ValidatedTotpStatus, ApiError | ValidationError>> {
    return xrpcValidated('com.atproto.server.getTotpStatus', totpStatusSchema, { token })
  },

  createTotpSecret(token: AccessToken): Promise<Result<ValidatedTotpSecret, ApiError | ValidationError>> {
    return xrpcValidated('com.atproto.server.createTotpSecret', totpSecretSchema, {
      method: 'POST',
      token,
    })
  },

  enableTotp(
    token: AccessToken,
    code: string
  ): Promise<Result<ValidatedEnableTotpResponse, ApiError | ValidationError>> {
    return xrpcValidated('com.atproto.server.enableTotp', enableTotpResponseSchema, {
      method: 'POST',
      token,
      body: { code },
    })
  },

  listPasskeys(token: AccessToken): Promise<Result<ValidatedListPasskeysResponse, ApiError | ValidationError>> {
    return xrpcValidated('com.atproto.server.listPasskeys', listPasskeysResponseSchema, { token })
  },

  listTrustedDevices(
    token: AccessToken
  ): Promise<Result<ValidatedListTrustedDevicesResponse, ApiError | ValidationError>> {
    return xrpcValidated('_account.listTrustedDevices', listTrustedDevicesResponseSchema, { token })
  },

  getReauthStatus(token: AccessToken): Promise<Result<ValidatedReauthStatus, ApiError | ValidationError>> {
    return xrpcValidated('_account.getReauthStatus', reauthStatusSchema, { token })
  },

  getNotificationPrefs(
    token: AccessToken
  ): Promise<Result<ValidatedNotificationPrefs, ApiError | ValidationError>> {
    return xrpcValidated('_account.getNotificationPrefs', notificationPrefsSchema, { token })
  },

  getDidDocument(token: AccessToken): Promise<Result<ValidatedDidDocument, ApiError | ValidationError>> {
    return xrpcValidated('_account.getDidDocument', didDocumentSchema, { token })
  },

  describeRepo(
    token: AccessToken,
    repo: Did
  ): Promise<Result<ValidatedRepoDescription, ApiError | ValidationError>> {
    return xrpcValidated('com.atproto.repo.describeRepo', repoDescriptionSchema, {
      token,
      params: { repo },
    })
  },

  listRecords(
    token: AccessToken,
    repo: Did,
    collection: Nsid,
    options?: { limit?: number; cursor?: string; reverse?: boolean }
  ): Promise<Result<ValidatedListRecordsResponse, ApiError | ValidationError>> {
    const params: Record<string, string> = { repo, collection }
    if (options?.limit) params.limit = String(options.limit)
    if (options?.cursor) params.cursor = options.cursor
    if (options?.reverse) params.reverse = 'true'
    return xrpcValidated('com.atproto.repo.listRecords', listRecordsResponseSchema, {
      token,
      params,
    })
  },

  getRecord(
    token: AccessToken,
    repo: Did,
    collection: Nsid,
    rkey: Rkey
  ): Promise<Result<ValidatedRecordResponse, ApiError | ValidationError>> {
    return xrpcValidated('com.atproto.repo.getRecord', recordResponseSchema, {
      token,
      params: { repo, collection, rkey },
    })
  },

  createRecord(
    token: AccessToken,
    repo: Did,
    collection: Nsid,
    record: unknown,
    rkey?: Rkey
  ): Promise<Result<ValidatedCreateRecordResponse, ApiError | ValidationError>> {
    return xrpcValidated('com.atproto.repo.createRecord', createRecordResponseSchema, {
      method: 'POST',
      token,
      body: { repo, collection, record, rkey },
    })
  },

  getServerStats(token: AccessToken): Promise<Result<ValidatedServerStats, ApiError | ValidationError>> {
    return xrpcValidated('_admin.getServerStats', serverStatsSchema, { token })
  },

  getServerConfig(): Promise<Result<ValidatedServerConfig, ApiError | ValidationError>> {
    return xrpcValidated('_server.getConfig', serverConfigSchema)
  },

  getPasswordStatus(token: AccessToken): Promise<Result<ValidatedPasswordStatus, ApiError | ValidationError>> {
    return xrpcValidated('_account.getPasswordStatus', passwordStatusSchema, { token })
  },

  changePassword(
    token: AccessToken,
    currentPassword: string,
    newPassword: string
  ): Promise<Result<ValidatedSuccessResponse, ApiError | ValidationError>> {
    return xrpcValidated('_account.changePassword', successResponseSchema, {
      method: 'POST',
      token,
      body: { currentPassword, newPassword },
    })
  },

  getLegacyLoginPreference(
    token: AccessToken
  ): Promise<Result<ValidatedLegacyLoginPreference, ApiError | ValidationError>> {
    return xrpcValidated('_account.getLegacyLoginPreference', legacyLoginPreferenceSchema, { token })
  },

  getAccountInfo(
    token: AccessToken,
    did: Did
  ): Promise<Result<ValidatedAccountInfo, ApiError | ValidationError>> {
    return xrpcValidated('com.atproto.admin.getAccountInfo', accountInfoSchema, {
      token,
      params: { did },
    })
  },

  searchAccounts(
    token: AccessToken,
    options?: { handle?: string; cursor?: string; limit?: number }
  ): Promise<Result<ValidatedSearchAccountsResponse, ApiError | ValidationError>> {
    const params: Record<string, string> = {}
    if (options?.handle) params.handle = options.handle
    if (options?.cursor) params.cursor = options.cursor
    if (options?.limit) params.limit = String(options.limit)
    return xrpcValidated('com.atproto.admin.searchAccounts', searchAccountsResponseSchema, {
      token,
      params,
    })
  },

  listBackups(token: AccessToken): Promise<Result<ValidatedListBackupsResponse, ApiError | ValidationError>> {
    return xrpcValidated('_backup.listBackups', listBackupsResponseSchema, { token })
  },

  createBackup(token: AccessToken): Promise<Result<ValidatedCreateBackupResponse, ApiError | ValidationError>> {
    return xrpcValidated('_backup.createBackup', createBackupResponseSchema, {
      method: 'POST',
      token,
    })
  },
}

export { ValidationError }
