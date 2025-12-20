<script lang="ts">
  import { navigate } from '../lib/router.svelte'

  let username = $state('')
  let password = $state('')
  let rememberDevice = $state(false)
  let submitting = $state(false)
  let error = $state<string | null>(null)
  let hasPasskeys = $state(false)
  let hasTotp = $state(false)
  let checkingSecurityStatus = $state(false)
  let securityStatusChecked = $state(false)
  let passkeySupported = $state(false)
  let clientName = $state<string | null>(null)

  $effect(() => {
    passkeySupported = window.PublicKeyCredential !== undefined
  })

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.hash.split('?')[1] || '')
    return params.get('request_uri')
  }

  function getErrorFromUrl(): string | null {
    const params = new URLSearchParams(window.location.hash.split('?')[1] || '')
    return params.get('error')
  }

  $effect(() => {
    const urlError = getErrorFromUrl()
    if (urlError) {
      error = urlError
    }
  })

  $effect(() => {
    fetchAuthRequestInfo()
  })

  async function fetchAuthRequestInfo() {
    const requestUri = getRequestUri()
    if (!requestUri) return

    try {
      const response = await fetch(`/oauth/authorize?request_uri=${encodeURIComponent(requestUri)}`, {
        headers: { 'Accept': 'application/json' }
      })
      if (response.ok) {
        const data = await response.json()
        if (data.login_hint && !username) {
          username = data.login_hint
        }
        if (data.client_name) {
          clientName = data.client_name
        }
      }
    } catch {
      // Ignore errors fetching auth info
    }
  }

  let checkTimeout: ReturnType<typeof setTimeout> | null = null

  $effect(() => {
    if (checkTimeout) {
      clearTimeout(checkTimeout)
    }
    hasPasskeys = false
    hasTotp = false
    securityStatusChecked = false
    if (username.length >= 3) {
      checkTimeout = setTimeout(() => checkUserSecurityStatus(), 500)
    }
  })

  async function checkUserSecurityStatus() {
    if (!username || checkingSecurityStatus) return
    checkingSecurityStatus = true
    try {
      const response = await fetch(`/oauth/security-status?identifier=${encodeURIComponent(username)}`)
      if (response.ok) {
        const data = await response.json()
        hasPasskeys = passkeySupported && data.hasPasskeys === true
        hasTotp = data.hasTotp === true
        securityStatusChecked = true
      }
    } catch {
      hasPasskeys = false
      hasTotp = false
    } finally {
      checkingSecurityStatus = false
    }
  }


  async function handlePasskeyLogin() {
    const requestUri = getRequestUri()
    if (!requestUri || !username) {
      error = 'Missing required parameters'
      return
    }

    submitting = true
    error = null

    try {
      const startResponse = await fetch('/oauth/passkey/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          request_uri: requestUri,
          identifier: username
        })
      })

      if (!startResponse.ok) {
        const data = await startResponse.json()
        error = data.error_description || data.error || 'Failed to start passkey login'
        submitting = false
        return
      }

      const { options } = await startResponse.json()

      const credential = await navigator.credentials.get({
        publicKey: prepareCredentialRequestOptions(options.publicKey)
      }) as PublicKeyCredential | null

      if (!credential) {
        error = 'Passkey authentication was cancelled'
        submitting = false
        return
      }

      const assertionResponse = credential.response as AuthenticatorAssertionResponse
      const credentialData = {
        id: credential.id,
        type: credential.type,
        rawId: arrayBufferToBase64Url(credential.rawId),
        response: {
          clientDataJSON: arrayBufferToBase64Url(assertionResponse.clientDataJSON),
          authenticatorData: arrayBufferToBase64Url(assertionResponse.authenticatorData),
          signature: arrayBufferToBase64Url(assertionResponse.signature),
          userHandle: assertionResponse.userHandle ? arrayBufferToBase64Url(assertionResponse.userHandle) : null
        }
      }

      const finishResponse = await fetch('/oauth/passkey/finish', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          request_uri: requestUri,
          credential: credentialData
        })
      })

      const data = await finishResponse.json()

      if (!finishResponse.ok) {
        error = data.error_description || data.error || 'Passkey authentication failed'
        submitting = false
        return
      }

      if (data.needs_totp) {
        navigate(`/oauth/totp?request_uri=${encodeURIComponent(requestUri)}`)
        return
      }

      if (data.needs_2fa) {
        navigate(`/oauth/2fa?request_uri=${encodeURIComponent(requestUri)}&channel=${encodeURIComponent(data.channel || '')}`)
        return
      }

      if (data.redirect_uri) {
        window.location.href = data.redirect_uri
        return
      }

      error = 'Unexpected response from server'
      submitting = false
    } catch (e) {
      console.error('Passkey login error:', e)
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        error = 'Passkey authentication was cancelled'
      } else {
        error = `Failed to authenticate with passkey: ${e instanceof Error ? e.message : String(e)}`
      }
      submitting = false
    }
  }

  function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer)
    let binary = ''
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  }

  function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
    const padded = base64 + '='.repeat((4 - base64.length % 4) % 4)
    const binary = atob(padded)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i)
    }
    return bytes.buffer
  }

  function prepareCredentialRequestOptions(options: any): PublicKeyCredentialRequestOptions {
    return {
      ...options,
      challenge: base64UrlToArrayBuffer(options.challenge),
      allowCredentials: options.allowCredentials?.map((cred: any) => ({
        ...cred,
        id: base64UrlToArrayBuffer(cred.id)
      })) || []
    }
  }

  async function handleSubmit(e: Event) {
    e.preventDefault()
    const requestUri = getRequestUri()
    if (!requestUri) {
      error = 'Missing request_uri parameter'
      return
    }

    submitting = true
    error = null

    try {
      const response = await fetch('/oauth/authorize', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          request_uri: requestUri,
          username,
          password,
          remember_device: rememberDevice
        })
      })

      const data = await response.json()

      if (!response.ok) {
        error = data.error_description || data.error || 'Login failed'
        submitting = false
        return
      }

      if (data.needs_totp) {
        navigate(`/oauth/totp?request_uri=${encodeURIComponent(requestUri)}`)
        return
      }

      if (data.needs_2fa) {
        navigate(`/oauth/2fa?request_uri=${encodeURIComponent(requestUri)}&channel=${encodeURIComponent(data.channel || '')}`)
        return
      }

      if (data.redirect_uri) {
        window.location.href = data.redirect_uri
        return
      }

      error = 'Unexpected response from server'
      submitting = false
    } catch {
      error = 'Failed to connect to server'
      submitting = false
    }
  }

  async function handleCancel() {
    const requestUri = getRequestUri()
    if (!requestUri) {
      window.history.back()
      return
    }

    submitting = true
    try {
      const response = await fetch('/oauth/authorize/deny', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ request_uri: requestUri })
      })

      const data = await response.json()
      if (data.redirect_uri) {
        window.location.href = data.redirect_uri
      }
    } catch {
      window.history.back()
    }
  }
</script>

<div class="oauth-login-container">
  <h1>Sign In</h1>
  <p class="subtitle">
    {#if clientName}
      Sign in to continue to <strong>{clientName}</strong>
    {:else}
      Sign in to continue to the application
    {/if}
  </p>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <form onsubmit={handleSubmit}>
    <div class="field">
      <label for="username">Handle or Email</label>
      <input
        id="username"
        type="text"
        bind:value={username}
        placeholder="you@example.com or handle"
        disabled={submitting}
        required
        autocomplete="username"
      />
    </div>

    {#if securityStatusChecked && passkeySupported}
      <button
        type="button"
        class="passkey-btn"
        class:passkey-unavailable={!hasPasskeys}
        onclick={handlePasskeyLogin}
        disabled={submitting || !hasPasskeys || !username}
        title={hasPasskeys ? 'Sign in with your passkey' : 'No passkeys registered for this account'}
      >
        <svg class="passkey-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M15 7a4 4 0 1 0-8 0 4 4 0 0 0 8 0z" />
          <path d="M17 17v4l3-2-3-2z" />
          <path d="M12 11c-4 0-6 2-6 4v4h9" />
        </svg>
        <span class="passkey-text">
          {#if submitting}
            Authenticating...
          {:else if hasPasskeys}
            Sign in with passkey
          {:else}
            Passkey not set up
          {/if}
        </span>
      </button>

      <div class="auth-divider">
        <span>or use password</span>
      </div>
    {/if}

    <div class="field">
      <label for="password">Password</label>
      <input
        id="password"
        type="password"
        bind:value={password}
        disabled={submitting}
        required
        autocomplete="current-password"
      />
    </div>

    <label class="remember-device">
      <input type="checkbox" bind:checked={rememberDevice} disabled={submitting} />
      <span>Remember this device</span>
    </label>

    <div class="actions">
      <button type="button" class="cancel-btn" onclick={handleCancel} disabled={submitting}>
        Cancel
      </button>
      <button type="submit" class="submit-btn" disabled={submitting || !username || !password}>
        {submitting ? 'Signing in...' : 'Sign In'}
      </button>
    </div>
  </form>
</div>

<style>
  .oauth-login-container {
    max-width: 400px;
    margin: 4rem auto;
    padding: 2rem;
  }

  h1 {
    margin: 0 0 0.5rem 0;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0 0 2rem 0;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  label {
    font-size: 0.875rem;
    font-weight: 500;
  }

  input[type="text"],
  input[type="password"] {
    padding: 0.75rem;
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    font-size: 1rem;
    background: var(--bg-input);
    color: var(--text-primary);
  }

  input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .remember-device {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .remember-device input {
    width: 16px;
    height: 16px;
  }

  .error {
    padding: 0.75rem;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: 4px;
    color: var(--error-text);
    margin-bottom: 1rem;
  }

  .actions {
    display: flex;
    gap: 1rem;
    margin-top: 0.5rem;
  }

  .actions button {
    flex: 1;
    padding: 0.75rem;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    transition: background-color 0.15s;
  }

  .actions button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .cancel-btn {
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
  }

  .cancel-btn:hover:not(:disabled) {
    background: var(--error-bg);
    border-color: var(--error-border);
    color: var(--error-text);
  }

  .submit-btn {
    background: var(--accent);
    color: white;
  }

  .submit-btn:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .auth-divider {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin: 0.5rem 0;
  }

  .auth-divider::before,
  .auth-divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border-color-light);
  }

  .auth-divider span {
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .passkey-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    width: 100%;
    padding: 0.75rem;
    background: var(--accent);
    color: white;
    border: 1px solid var(--accent);
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    transition: background-color 0.15s, border-color 0.15s, opacity 0.15s;
  }

  .passkey-btn:hover:not(:disabled) {
    background: var(--accent-hover);
    border-color: var(--accent-hover);
  }

  .passkey-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .passkey-btn.passkey-unavailable {
    background: var(--bg-secondary);
    color: var(--text-secondary);
    border-color: var(--border-color);
  }

  .passkey-icon {
    width: 20px;
    height: 20px;
  }

  .passkey-text {
    flex: 1;
    text-align: left;
  }
</style>
