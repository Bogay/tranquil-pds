<script lang="ts">
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'
  import { startOAuthLogin } from '../lib/oauth'
  import {
    prepareRequestOptions,
    serializeAssertionResponse,
    type WebAuthnRequestOptionsResponse,
  } from '../lib/webauthn'
  import SsoIcon from '../components/SsoIcon.svelte'

  interface SsoProvider {
    provider: string
    name: string
    icon: string
  }

  let username = $state('')
  let ssoProviders = $state<SsoProvider[]>([])
  let ssoLoading = $state<string | null>(null)
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
    fetchSsoProviders()
  })

  async function fetchSsoProviders() {
    try {
      const response = await fetch('/oauth/sso/providers')
      if (response.ok) {
        const data = await response.json()
        ssoProviders = (data.providers || []).toSorted((a: SsoProvider, b: SsoProvider) => a.name.localeCompare(b.name))
      }
    } catch {
      ssoProviders = []
    }
  }

  async function handleSsoLogin(provider: string) {
    const requestUri = getRequestUri()
    if (!requestUri) {
      error = $_('common.error')
      return
    }

    ssoLoading = provider
    error = null

    try {
      const response = await fetch('/oauth/sso/initiate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          provider,
          request_uri: requestUri,
          action: 'login'
        })
      })

      const data = await response.json()

      if (!response.ok) {
        error = data.error_description || data.error || 'Failed to start SSO login'
        ssoLoading = null
        return
      }

      if (data.redirect_url) {
        window.location.href = data.redirect_url
        return
      }

      error = $_('common.error')
      ssoLoading = null
    } catch {
      error = $_('common.error')
      ssoLoading = null
    }
  }

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

        if (isDelegated && data.did) {
          const requestUri = getRequestUri()
          if (requestUri) {
            navigate(routes.oauthDelegation, { params: { request_uri: requestUri, delegated_did: data.did } })
            return
          } else {
            await startOAuthLogin(username)
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
      const publicKeyOptions = prepareRequestOptions(options as WebAuthnRequestOptionsResponse)

      const credential = await navigator.credentials.get({
        publicKey: publicKeyOptions
      }) as PublicKeyCredential | null

      if (!credential) {
        error = $_('common.error')
        submitting = false
        return
      }

      const credentialData = serializeAssertionResponse(credential)

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
        navigate(routes.oauthTotp, { params: { request_uri: requestUri } })
        return
      }

      if (data.needs_2fa) {
        navigate(routes.oauth2fa, { params: { request_uri: requestUri, channel: data.channel || '' } })
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
        navigate(routes.oauthTotp, { params: { request_uri: requestUri } })
        return
      }

      if (data.needs_2fa) {
        navigate(routes.oauth2fa, { params: { request_uri: requestUri, channel: data.channel || '' } })
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

  function handleCancel() {
    window.location.href = '/'
  }
</script>

<div class="page-sm">
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
    <div class="message error">{error}</div>
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

    {#if ssoProviders.length > 0}
      <div class="sso-section sso-section-top">
        <div class="sso-buttons">
          {#each ssoProviders as provider}
            <button
              type="button"
              class="sso-btn sso-btn-prominent"
              onclick={() => handleSsoLogin(provider.provider)}
              disabled={submitting || ssoLoading !== null}
            >
              {#if ssoLoading === provider.provider}
                <span class="spinner sm"></span>
              {:else}
                <SsoIcon provider={provider.icon} size={20} />
              {/if}
              <span>{provider.name}</span>
            </button>
          {/each}
        </div>
        <div class="sso-divider">
          <span>{$_('oauth.login.orUseCredentials')}</span>
        </div>
      </div>
    {/if}

    {#if passkeySupported && username.length >= 3}
      <div class="auth-methods" class:single-method={!hasPassword}>
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

        {#if hasPassword}
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
        {/if}
      </div>

      <div class="cancel-row">
        <button type="button" class="cancel-btn-subtle" onclick={handleCancel} disabled={submitting}>
          {$_('common.cancel')}
        </button>
      </div>
    {:else}
      {#if hasPassword || !securityStatusChecked}
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
          <button type="submit" class="submit-btn" disabled={submitting || !username || !password}>
            {submitting ? $_('oauth.login.signingIn') : $_('oauth.login.title')}
          </button>
        </div>
      {/if}

      <div class="cancel-row">
        <button type="button" class="cancel-btn-subtle" onclick={handleCancel} disabled={submitting}>
          {$_('common.cancel')}
        </button>
      </div>
    {/if}
  </form>

  <p class="help-links">
    <a href={getFullUrl(routes.resetPassword)}>{$_('login.forgotPassword')}</a> &middot; <a href={getFullUrl(routes.requestPasskeyRecovery)}>{$_('login.lostPasskey')}</a>
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

  .auth-methods.single-method {
    grid-template-columns: 1fr;
  }

  @media (min-width: 600px) {
    .auth-methods.single-method {
      grid-template-columns: 1fr;
      max-width: 400px;
      margin: var(--space-4) auto 0;
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

  .actions {
    display: flex;
    gap: var(--space-4);
    margin-top: var(--space-2);
  }

  .actions button {
    flex: 1;
  }

  .cancel-row {
    display: flex;
    justify-content: center;
    margin-top: var(--space-4);
  }

  .cancel-btn-subtle {
    padding: var(--space-2) var(--space-4);
    background: transparent;
    color: var(--text-muted);
    border: none;
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    cursor: pointer;
    transition: color var(--transition-fast);
  }

  .cancel-btn-subtle:hover:not(:disabled) {
    color: var(--text-secondary);
  }

  .cancel-btn-subtle:disabled {
    opacity: 0.6;
    cursor: not-allowed;
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

  .sso-section {
    margin-top: var(--space-6);
  }

  .sso-section-top {
    margin-top: var(--space-4);
    margin-bottom: 0;
  }

  .sso-section-top .sso-divider {
    margin-top: var(--space-5);
    margin-bottom: 0;
  }

  .sso-divider {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    margin-bottom: var(--space-4);
    color: var(--text-muted);
    font-size: var(--text-sm);
  }

  .sso-divider::before,
  .sso-divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border-color);
  }

  .sso-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-3);
    justify-content: center;
  }

  .sso-btn {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-4);
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background-color var(--transition-fast), border-color var(--transition-fast);
  }

  .sso-btn-prominent {
    padding: var(--space-3) var(--space-5);
    font-size: var(--text-base);
    font-weight: var(--font-medium);
  }

  .sso-btn:hover:not(:disabled) {
    background: var(--bg-tertiary);
    border-color: var(--accent);
  }

  .sso-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
</style>
