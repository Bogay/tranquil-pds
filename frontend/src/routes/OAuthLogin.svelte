<script lang="ts">
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'
  import { startOAuthLogin, ensureRequestUri } from '../lib/oauth'
  import {
    prepareRequestOptions,
    serializeAssertionResponse,
    type WebAuthnRequestOptionsResponse,
  } from '../lib/webauthn'
  import SsoIcon from '../components/SsoIcon.svelte'
  import { getRandomHandle } from '../components/RandomHandle.svelte'

  const handlePlaceholder = getRandomHandle()

  interface SsoProvider {
    provider: string
    name: string
    icon: string
  }

  const PENDING_VERIFICATION_KEY = 'tranquil_pds_pending_verification'

  function storePendingVerification(data: { did?: string; handle?: string; channel?: string }) {
    if (data.did) {
      localStorage.setItem(PENDING_VERIFICATION_KEY, JSON.stringify({
        did: data.did,
        handle: data.handle ?? '',
        channel: data.channel ?? '',
      }))
    }
  }

  let username = $state('')
  let ssoProviders = $state<SsoProvider[]>([])
  let ssoLoading = $state<string | null>(null)
  let password = $state('')
  let rememberDevice = $state(false)
  let submitting = $state(false)
  let error = $state<string | null>(null)
  let verificationResent = $state(false)
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
      if (urlError === 'account_not_verified') {
        verificationResent = true
      } else {
        error = urlError
      }
    }
  })

  $effect(() => {
    ensureRequestUri('').catch(() => {})
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
    verificationResent = false

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
        if (data.error === 'account_not_verified') {
          verificationResent = true
          storePendingVerification(data)
          submitting = false
          return
        }
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
        if (data.error === 'account_not_verified') {
          verificationResent = true
          storePendingVerification(data)
          submitting = false
          return
        }
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
    verificationResent = false

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
        if (data.error === 'account_not_verified') {
          verificationResent = true
          storePendingVerification(data)
          submitting = false
          return
        }
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
    {#if clientName}
      <p class="subtitle">{$_('oauth.login.subtitle')} <strong>{clientName}</strong></p>
    {/if}
  </header>

  {#if verificationResent}
    <div class="message warning">
      <p>{$_('oauth.login.verificationResent')}</p>
      <a href={`${getFullUrl(routes.verify)}${getRequestUri() ? `?request_uri=${encodeURIComponent(getRequestUri()!)}` : ''}`}>{$_('verify.tokenTitle')}</a>
    </div>
  {:else if error}
    <div class="message error">{error}</div>
  {/if}

  <form onsubmit={handleSubmit}>
    <div>
      <label for="username">{$_('register.handle')}</label>
      <input
        id="username"
        type="text"
        bind:value={username}
        placeholder={handlePlaceholder}
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
                <span>{$_('common.loading')}</span>
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
            style="width: 100%"
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

            <div class="actions">
              <button type="button" class="ghost sm" onclick={handleCancel} disabled={submitting}>
                {$_('common.cancel')}
              </button>
              <button type="submit" disabled={submitting || !username || !password}>
                {submitting ? $_('oauth.login.signingIn') : $_('oauth.login.title')}
              </button>
            </div>
          </div>
        {/if}
      </div>
    {:else}
      {#if hasPassword || !securityStatusChecked}
        <div>
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
          <button type="button" class="ghost sm" onclick={handleCancel} disabled={submitting}>
            {$_('common.cancel')}
          </button>
          <button type="submit" disabled={submitting || !username || !password}>
            {submitting ? $_('oauth.login.signingIn') : $_('oauth.login.title')}
          </button>
        </div>
      {/if}
    {/if}
  </form>

  <p class="help-links">
    <a href={getFullUrl(routes.resetPassword)}>{$_('login.forgotPassword')}</a> &middot; <a href={getFullUrl(routes.requestPasskeyRecovery)}>{$_('login.lostPasskey')}</a>
  </p>
</div>
