import { api, type Session, type CreateAccountParams, type CreateAccountResult, ApiError } from './api'
import { startOAuthLogin, handleOAuthCallback, checkForOAuthCallback, clearOAuthCallbackParams, refreshOAuthToken } from './oauth'
import { setLocale, type SupportedLocale } from './i18n'

function applyLocaleFromSession(sessionInfo: { preferredLocale?: string | null }) {
  if (sessionInfo.preferredLocale) {
    setLocale(sessionInfo.preferredLocale as SupportedLocale)
  }
}

const STORAGE_KEY = 'tranquil_pds_session'
const ACCOUNTS_KEY = 'tranquil_pds_accounts'

export interface SavedAccount {
  did: string
  handle: string
  accessJwt: string
  refreshJwt: string
}

interface AuthState {
  session: Session | null
  loading: boolean
  error: string | null
  savedAccounts: SavedAccount[]
}

let state = $state<AuthState>({
  session: null,
  loading: true,
  error: null,
  savedAccounts: [],
})

function saveSession(session: Session | null) {
  if (session) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(session))
  } else {
    localStorage.removeItem(STORAGE_KEY)
  }
}

function loadSession(): Session | null {
  const stored = localStorage.getItem(STORAGE_KEY)
  if (stored) {
    try {
      return JSON.parse(stored)
    } catch {
      return null
    }
  }
  return null
}

function loadSavedAccounts(): SavedAccount[] {
  const stored = localStorage.getItem(ACCOUNTS_KEY)
  if (stored) {
    try {
      return JSON.parse(stored)
    } catch {
      return []
    }
  }
  return []
}

function saveSavedAccounts(accounts: SavedAccount[]) {
  localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(accounts))
}

function addOrUpdateSavedAccount(session: Session) {
  const accounts = loadSavedAccounts()
  const existing = accounts.findIndex(a => a.did === session.did)
  const savedAccount: SavedAccount = {
    did: session.did,
    handle: session.handle,
    accessJwt: session.accessJwt,
    refreshJwt: session.refreshJwt,
  }
  if (existing >= 0) {
    accounts[existing] = savedAccount
  } else {
    accounts.push(savedAccount)
  }
  saveSavedAccounts(accounts)
  state.savedAccounts = accounts
}

function removeSavedAccount(did: string) {
  const accounts = loadSavedAccounts().filter(a => a.did !== did)
  saveSavedAccounts(accounts)
  state.savedAccounts = accounts
}

export async function initAuth() {
  state.loading = true
  state.error = null
  state.savedAccounts = loadSavedAccounts()

  const oauthCallback = checkForOAuthCallback()
  if (oauthCallback) {
    clearOAuthCallbackParams()
    try {
      const tokens = await handleOAuthCallback(oauthCallback.code, oauthCallback.state)
      const sessionInfo = await api.getSession(tokens.access_token)
      const session: Session = {
        ...sessionInfo,
        accessJwt: tokens.access_token,
        refreshJwt: tokens.refresh_token || '',
      }
      state.session = session
      saveSession(session)
      addOrUpdateSavedAccount(session)
      applyLocaleFromSession(sessionInfo)
      state.loading = false
      return
    } catch (e) {
      state.error = e instanceof Error ? e.message : 'OAuth login failed'
      state.loading = false
      return
    }
  }

  const stored = loadSession()
  if (stored) {
    try {
      const sessionInfo = await api.getSession(stored.accessJwt)
      state.session = { ...sessionInfo, accessJwt: stored.accessJwt, refreshJwt: stored.refreshJwt }
      addOrUpdateSavedAccount(state.session)
      applyLocaleFromSession(sessionInfo)
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        try {
          const tokens = await refreshOAuthToken(stored.refreshJwt)
          const sessionInfo = await api.getSession(tokens.access_token)
          const session: Session = {
            ...sessionInfo,
            accessJwt: tokens.access_token,
            refreshJwt: tokens.refresh_token || stored.refreshJwt,
          }
          state.session = session
          saveSession(session)
          addOrUpdateSavedAccount(session)
          applyLocaleFromSession(sessionInfo)
        } catch {
          saveSession(null)
          state.session = null
        }
      } else {
        saveSession(null)
        state.session = null
      }
    }
  }
  state.loading = false
}

export async function login(identifier: string, password: string): Promise<void> {
  state.loading = true
  state.error = null
  try {
    const session = await api.createSession(identifier, password)
    state.session = session
    saveSession(session)
    addOrUpdateSavedAccount(session)
  } catch (e) {
    if (e instanceof ApiError) {
      state.error = e.message
    } else {
      state.error = 'Login failed'
    }
    throw e
  } finally {
    state.loading = false
  }
}

export async function loginWithOAuth(): Promise<void> {
  state.loading = true
  state.error = null
  try {
    await startOAuthLogin()
  } catch (e) {
    state.loading = false
    state.error = e instanceof Error ? e.message : 'Failed to start OAuth login'
    throw e
  }
}

export async function register(params: CreateAccountParams): Promise<CreateAccountResult> {
  try {
    const result = await api.createAccount(params)
    return result
  } catch (e) {
    if (e instanceof ApiError) {
      state.error = e.message
    } else {
      state.error = 'Registration failed'
    }
    throw e
  }
}

export async function confirmSignup(did: string, verificationCode: string): Promise<void> {
  state.loading = true
  state.error = null
  try {
    const result = await api.confirmSignup(did, verificationCode)
    const session: Session = {
      did: result.did,
      handle: result.handle,
      accessJwt: result.accessJwt,
      refreshJwt: result.refreshJwt,
      email: result.email,
      emailConfirmed: result.emailConfirmed,
      preferredChannel: result.preferredChannel,
      preferredChannelVerified: result.preferredChannelVerified,
    }
    state.session = session
    saveSession(session)
    addOrUpdateSavedAccount(session)
  } catch (e) {
    if (e instanceof ApiError) {
      state.error = e.message
    } else {
      state.error = 'Verification failed'
    }
    throw e
  } finally {
    state.loading = false
  }
}

export async function resendVerification(did: string): Promise<void> {
  try {
    await api.resendVerification(did)
  } catch (e) {
    if (e instanceof ApiError) {
      throw e
    }
    throw new Error('Failed to resend verification code')
  }
}

export async function logout(): Promise<void> {
  if (state.session) {
    try {
      await api.deleteSession(state.session.accessJwt)
    } catch {
      // Ignore errors on logout
    }
  }
  state.session = null
  saveSession(null)
}

export async function switchAccount(did: string): Promise<void> {
  const account = state.savedAccounts.find(a => a.did === did)
  if (!account) {
    throw new Error('Account not found')
  }
  state.loading = true
  state.error = null
  try {
    const session = await api.getSession(account.accessJwt)
    state.session = { ...session, accessJwt: account.accessJwt, refreshJwt: account.refreshJwt }
    saveSession(state.session)
    addOrUpdateSavedAccount(state.session)
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      try {
        const tokens = await refreshOAuthToken(account.refreshJwt)
        const sessionInfo = await api.getSession(tokens.access_token)
        const session: Session = {
          ...sessionInfo,
          accessJwt: tokens.access_token,
          refreshJwt: tokens.refresh_token || account.refreshJwt,
        }
        state.session = session
        saveSession(session)
        addOrUpdateSavedAccount(session)
      } catch {
        removeSavedAccount(did)
        state.error = 'Session expired. Please log in again.'
        throw new Error('Session expired')
      }
    } else {
      state.error = 'Failed to switch account'
      throw e
    }
  } finally {
    state.loading = false
  }
}

export function forgetAccount(did: string): void {
  removeSavedAccount(did)
}

export function getAuthState() {
  return state
}

export async function refreshSession(): Promise<void> {
  if (!state.session) return
  try {
    const sessionInfo = await api.getSession(state.session.accessJwt)
    state.session = {
      ...sessionInfo,
      accessJwt: state.session.accessJwt,
      refreshJwt: state.session.refreshJwt,
    }
    saveSession(state.session)
    addOrUpdateSavedAccount(state.session)
  } catch (e) {
    console.error('Failed to refresh session:', e)
  }
}

export function getToken(): string | null {
  return state.session?.accessJwt ?? null
}

export function isAuthenticated(): boolean {
  return state.session !== null
}

export function _testSetState(newState: { session: Session | null; loading: boolean; error: string | null; savedAccounts?: SavedAccount[] }) {
  state.session = newState.session
  state.loading = newState.loading
  state.error = newState.error
  state.savedAccounts = newState.savedAccounts ?? []
}

export function _testReset() {
  state.session = null
  state.loading = true
  state.error = null
  state.savedAccounts = []
  localStorage.removeItem(STORAGE_KEY)
  localStorage.removeItem(ACCOUNTS_KEY)
}
