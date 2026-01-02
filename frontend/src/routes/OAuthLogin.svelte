<script lang="ts">
  import { navigate } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'

  let username = $state('')
  let password = $state('')
  let rememberDevice = $state(false)
  let submitting = $state(false)
  let error = $state<string | null>(null)
  let hasPasskeys = $state(false)
  let hasTotp = $state(false)
  let hasPassword = $state(true)
  let isDelegated = $state(false)
  let userDid = $state<string | null>(null)
  let checkingSecurityStatus = $state(false)
  let securityStatusChecked = $state(false)
  let passkeySupported = $state(false)
  let clientName = $state<string | null>(null)

  $effect(() => {
    passkeySupported = window.PublicKeyCredential !== undefined
  })

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('request_uri')
  }

  function getErrorFromUrl(): string | null {
    const params = new URLSearchParams(window.location.search)
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
        hasPassword = data.hasPassword !== false
        isDelegated = data.isDelegated === true
        userDid = data.did || null
        securityStatusChecked = true

        if (!hasPassword && !hasPasskeys && isDelegated && data.did) {
          const requestUri = getRequestUri()
          if (requestUri) {
            navigate(`/oauth/delegation?request_uri=${encodeURIComponent(requestUri)}&delegated_did=${encodeURIComponent(data.did)}`)
            return
          }
        }
      }
    } catch {
      hasPasskeys = false
      hasTotp = false
      hasPassword = true
      isDelegated = false
    } finally {
      checkingSecurityStatus = false
    }
  }


  async function handlePasskeyLogin() {
    const requestUri = getRequestUri()
    if (!requestUri || !username) {
      error = $_('common.error')
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
        error = $_('common.error')
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

      error = $_('common.error')
      submitting = false
    } catch (e) {
      console.error('Passkey login error:', e)
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        error = $_('common.error')
      } else {
        error = `${$_('common.error')}: ${e instanceof Error ? e.message : String(e)}`
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
      error = $_('common.error')
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

      error = $_('common.error')
      submitting = false
    } catch {
      error = $_('common.error')
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
  <header class="page-header">
    <h1>{$_('oauth.login.title')}</h1>
    <p class="subtitle">
      {#if clientName}
        {$_('oauth.login.subtitle')} <strong>{clientName}</strong>
      {:else}
        {$_('oauth.login.subtitle')}
      {/if}
    </p>
  </header>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <form onsubmit={handleSubmit}>
    <div class="field">
      <label for="username">{$_('register.handle')}</label>
      <input
        id="username"
        type="text"
        bind:value={username}
        placeholder={$_('register.emailPlaceholder')}
        disabled={submitting}
        required
        autocomplete="username"
      />
    </div>

    {#if passkeySupported && username.length >= 3}
      <div class="auth-methods">
        <div class="passkey-method">
          <h3>{$_('oauth.login.signInWithPasskey')}</h3>
          <button
            type="button"
            class="passkey-btn"
            class:passkey-unavailable={!hasPasskeys || checkingSecurityStatus || !securityStatusChecked}
            onclick={handlePasskeyLogin}
            disabled={submitting || !hasPasskeys || !username || checkingSecurityStatus || !securityStatusChecked}
            title={checkingSecurityStatus ? $_('oauth.login.passkeyHintChecking') : hasPasskeys ? $_('oauth.login.passkeyHintAvailable') : $_('oauth.login.passkeyHintNotAvailable')}
          >
            <svg class="passkey-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M15 7a4 4 0 1 0-8 0 4 4 0 0 0 8 0z" />
              <path d="M17 17v4l3-2-3-2z" />
              <path d="M12 11c-4 0-6 2-6 4v4h9" />
            </svg>
            <span class="passkey-text">
              {#if submitting}
                {$_('oauth.login.authenticating')}
              {:else if checkingSecurityStatus || !securityStatusChecked}
                {$_('oauth.login.checkingPasskey')}
              {:else if hasPasskeys}
                {$_('oauth.login.usePasskey')}
              {:else}
                {$_('oauth.login.passkeyNotSetUp')}
              {/if}
            </span>
          </button>
          <p class="method-hint">{$_('oauth.login.passkeyHint')}</p>
        </div>

        <div class="method-divider">
          <span>{$_('oauth.login.orUsePassword')}</span>
        </div>

        <div class="password-method">
          <h3>{$_('oauth.login.password')}</h3>
          <div class="field">
            <input
              id="password"
              type="password"
              bind:value={password}
              disabled={submitting}
              required
              autocomplete="current-password"
              placeholder={$_('oauth.login.passwordPlaceholder')}
            />
          </div>

          <label class="remember-device">
            <input type="checkbox" bind:checked={rememberDevice} disabled={submitting} />
            <span>{$_('oauth.login.rememberDevice')}</span>
          </label>

          <button type="submit" class="submit-btn" disabled={submitting || !username || !password}>
            {submitting ? $_('oauth.login.signingIn') : $_('oauth.login.title')}
          </button>
        </div>
      </div>

      <div class="actions">
        <button type="button" class="cancel-btn" onclick={handleCancel} disabled={submitting}>
          {$_('common.cancel')}
        </button>
      </div>
    {:else}
      <div class="field">
        <label for="password">{$_('oauth.login.password')}</label>
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
        <span>{$_('oauth.login.rememberDevice')}</span>
      </label>

      <div class="actions">
        <button type="button" class="cancel-btn" onclick={handleCancel} disabled={submitting}>
          {$_('common.cancel')}
        </button>
        <button type="submit" class="submit-btn" disabled={submitting || !username || !password}>
          {submitting ? $_('oauth.login.signingIn') : $_('oauth.login.title')}
        </button>
      </div>
    {/if}
  </form>

  <p class="help-links">
    <a href="/app/reset-password">{$_('login.forgotPassword')}</a> &middot; <a href="/app/request-passkey-recovery">{$_('login.lostPasskey')}</a>
  </p>
</div>

<style>
  .help-links {
    text-align: center;
    margin-top: var(--space-4);
    font-size: var(--text-sm);
  }

  .help-links a {
    color: var(--accent);
    text-decoration: none;
  }

  .help-links a:hover {
    text-decoration: underline;
  }

  .oauth-login-container {
    max-width: var(--width-md);
    margin: var(--space-9) auto;
    padding: var(--space-7);
  }

  .page-header {
    margin-bottom: var(--space-6);
  }

  h1 {
    margin: 0 0 var(--space-2) 0;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .auth-methods {
    display: grid;
    grid-template-columns: 1fr;
    gap: var(--space-5);
    margin-top: var(--space-4);
  }

  @media (min-width: 600px) {
    .auth-methods {
      grid-template-columns: 1fr auto 1fr;
      align-items: start;
    }
  }

  .passkey-method,
  .password-method {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    padding: var(--space-5);
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
  }

  .passkey-method h3,
  .password-method h3 {
    margin: 0;
    font-size: var(--text-sm);
    font-weight: var(--font-semibold);
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .method-hint {
    margin: 0;
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .method-divider {
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-muted);
    font-size: var(--text-sm);
  }

  @media (min-width: 600px) {
    .method-divider {
      flex-direction: column;
      padding: 0 var(--space-3);
    }

    .method-divider::before,
    .method-divider::after {
      content: '';
      width: 1px;
      height: var(--space-6);
      background: var(--border-color);
    }

    .method-divider span {
      writing-mode: vertical-rl;
      text-orientation: mixed;
      transform: rotate(180deg);
      padding: var(--space-2) 0;
    }
  }

  @media (max-width: 599px) {
    .method-divider {
      gap: var(--space-4);
    }

    .method-divider::before,
    .method-divider::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border-color);
    }
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  label {
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
  }

  input[type="text"],
  input[type="password"] {
    padding: var(--space-3);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-size: var(--text-base);
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
    gap: var(--space-2);
    cursor: pointer;
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  .remember-device input {
    width: 16px;
    height: 16px;
  }

  .error {
    padding: var(--space-3);
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: var(--radius-md);
    color: var(--error-text);
    margin-bottom: var(--space-4);
  }

  .actions {
    display: flex;
    gap: var(--space-4);
    margin-top: var(--space-2);
  }

  .actions button {
    flex: 1;
    padding: var(--space-3);
    border: none;
    border-radius: var(--radius-md);
    font-size: var(--text-base);
    cursor: pointer;
    transition: background-color var(--transition-fast);
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
    color: var(--text-inverse);
  }

  .submit-btn:hover:not(:disabled) {
    background: var(--accent-hover);
  }


  .passkey-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: var(--space-2);
    width: 100%;
    padding: var(--space-3);
    background: var(--accent);
    color: var(--text-inverse);
    border: 1px solid var(--accent);
    border-radius: var(--radius-md);
    font-size: var(--text-base);
    cursor: pointer;
    transition: background-color var(--transition-fast), border-color var(--transition-fast), opacity var(--transition-fast);
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
