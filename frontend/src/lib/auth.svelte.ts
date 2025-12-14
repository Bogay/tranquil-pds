import { api, type Session, type CreateAccountParams, type CreateAccountResult, ApiError } from './api'
const STORAGE_KEY = 'bspds_session'
interface AuthState {
  session: Session | null
  loading: boolean
  error: string | null
}
let state = $state<AuthState>({
  session: null,
  loading: true,
  error: null,
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
export async function initAuth() {
  state.loading = true
  state.error = null
  const stored = loadSession()
  if (stored) {
    try {
      const session = await api.getSession(stored.accessJwt)
      state.session = { ...session, accessJwt: stored.accessJwt, refreshJwt: stored.refreshJwt }
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        try {
          const refreshed = await api.refreshSession(stored.refreshJwt)
          state.session = refreshed
          saveSession(refreshed)
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
export function getAuthState() {
  return state
}
export function getToken(): string | null {
  return state.session?.accessJwt ?? null
}
export function isAuthenticated(): boolean {
  return state.session !== null
}
export function _testSetState(newState: { session: Session | null; loading: boolean; error: string | null }) {
  state.session = newState.session
  state.loading = newState.loading
  state.error = newState.error
}
export function _testReset() {
  state.session = null
  state.loading = true
  state.error = null
  localStorage.removeItem(STORAGE_KEY)
}
