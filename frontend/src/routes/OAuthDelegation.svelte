<script lang="ts">
  import { navigate } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'

  let delegatedDid = $state<string | null>(null)
  let delegatedHandle = $state<string | null>(null)
  let controllerIdentifier = $state('')
  let controllerDid = $state<string | null>(null)
  let password = $state('')
  let rememberDevice = $state(false)
  let submitting = $state(false)
  let loading = $state(true)
  let error = $state<string | null>(null)
  let hasPasskeys = $state(false)
  let hasTotp = $state(false)
  let passkeySupported = $state(false)
  let step = $state<'identifier' | 'password'>('identifier')

  $effect(() => {
    passkeySupported = window.PublicKeyCredential !== undefined
  })

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('request_uri')
  }

  function getDelegatedDid(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('delegated_did')
  }

  $effect(() => {
    loadDelegationInfo()
  })

  async function loadDelegationInfo() {
    const requestUri = getRequestUri()
    delegatedDid = getDelegatedDid()

    if (!requestUri || !delegatedDid) {
      error = $_('oauthDelegation.missingParams')
      loading = false
      return
    }

    try {
      const response = await fetch(`/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(delegatedDid.replace('did:', ''))}`)
      if (response.ok) {
        const data = await response.json()
        delegatedHandle = data.handle || delegatedDid
      } else {
        const handleResponse = await fetch(`/xrpc/com.atproto.repo.describeRepo?repo=${encodeURIComponent(delegatedDid)}`)
        if (handleResponse.ok) {
          const data = await handleResponse.json()
          delegatedHandle = data.handle || delegatedDid
        } else {
          delegatedHandle = delegatedDid
        }
      }
    } catch {
      delegatedHandle = delegatedDid
    } finally {
      loading = false
    }
  }

  async function handleIdentifierSubmit(e: Event) {
    e.preventDefault()
    if (!controllerIdentifier.trim()) return

    submitting = true
    error = null

    try {
      let resolvedDid = controllerIdentifier.trim()
      if (!resolvedDid.startsWith('did:')) {
        resolvedDid = resolvedDid.replace(/^@/, '')
        const response = await fetch(`/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(resolvedDid)}`)
        if (!response.ok) {
          error = $_('oauthDelegation.controllerNotFound')
          submitting = false
          return
        }
        const data = await response.json()
        resolvedDid = data.did
      }

      controllerDid = resolvedDid

      const securityResponse = await fetch(`/oauth/security-status?identifier=${encodeURIComponent(controllerIdentifier.trim().replace(/^@/, ''))}`)
      if (securityResponse.ok) {
        const data = await securityResponse.json()
        hasPasskeys = passkeySupported && data.hasPasskeys === true
        hasTotp = data.hasTotp === true
      }

      step = 'password'
    } catch {
      error = $_('oauthDelegation.controllerNotFound')
    } finally {
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

  async function handlePasskeyLogin() {
    const requestUri = getRequestUri()
    if (!requestUri || !controllerDid || !delegatedDid) {
      error = $_('oauthDelegation.missingInfo')
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
          identifier: controllerIdentifier.trim().replace(/^@/, '')
        })
      })

      if (!startResponse.ok) {
        const data = await startResponse.json()
        error = data.error_description || data.error || $_('oauthDelegation.failedPasskeyStart')
        submitting = false
        return
      }

      const { options } = await startResponse.json()

      const credential = await navigator.credentials.get({
        publicKey: prepareCredentialRequestOptions(options.publicKey)
      }) as PublicKeyCredential | null

      if (!credential) {
        error = $_('oauthDelegation.passkeyCancelled')
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
          identifier: controllerIdentifier.trim().replace(/^@/, ''),
          credential: credentialData,
          delegated_did: delegatedDid,
          controller_did: controllerDid
        })
      })

      const data = await finishResponse.json()

      if (!finishResponse.ok || data.success === false || data.error) {
        error = data.error_description || data.error || $_('oauthDelegation.passkeyFailed')
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

      error = $_('oauthDelegation.unexpectedResponse')
      submitting = false
    } catch (e) {
      console.error('Passkey login error:', e)
      error = $_('oauthDelegation.authFailed')
      submitting = false
    }
  }

  async function handlePasswordSubmit(e: Event) {
    e.preventDefault()
    const requestUri = getRequestUri()
    if (!requestUri || !controllerDid || !delegatedDid) {
      error = $_('oauthDelegation.missingInfo')
      return
    }

    submitting = true
    error = null

    try {
      const response = await fetch('/oauth/delegation/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          request_uri: requestUri,
          delegated_did: delegatedDid,
          controller_did: controllerDid,
          password,
          remember_device: rememberDevice
        })
      })

      const data = await response.json()

      if (!response.ok || data.success === false || data.error) {
        error = data.error_description || data.error || $_('oauthDelegation.authFailed')
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

      error = $_('oauthDelegation.unexpectedResponse')
      submitting = false
    } catch {
      error = $_('oauthDelegation.authFailed')
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

  function goBack() {
    step = 'identifier'
    password = ''
    error = null
  }
</script>

<div class="delegation-container">
  {#if loading}
    <div class="loading">
      <p>{$_('oauthDelegation.loading')}</p>
    </div>
  {:else if step === 'identifier'}
    <header class="page-header">
      <h1>{$_('oauthDelegation.title')}</h1>
      <p class="subtitle">
        {$_('oauthDelegation.isDelegated', { values: { handle: delegatedHandle } })}
        <br />{$_('oauthDelegation.enterControllerHandle')}
      </p>
    </header>

    {#if error}
      <div class="error">{error}</div>
    {/if}

    <form onsubmit={handleIdentifierSubmit}>
      <div class="field">
        <label for="controller-identifier">{$_('oauthDelegation.controllerHandle')}</label>
        <input
          id="controller-identifier"
          type="text"
          bind:value={controllerIdentifier}
          disabled={submitting}
          required
          autocomplete="username"
          placeholder={$_('oauthDelegation.handlePlaceholder')}
        />
      </div>

      <div class="actions">
        <button type="button" class="cancel-btn" onclick={handleCancel} disabled={submitting}>
          {$_('common.cancel')}
        </button>
        <button type="submit" class="submit-btn" disabled={submitting || !controllerIdentifier.trim()}>
          {submitting ? $_('oauthDelegation.checking') : $_('common.continue')}
        </button>
      </div>
    </form>
  {:else if step === 'password'}
    <header class="page-header">
      <h1>{$_('oauthDelegation.signInAsController')}</h1>
      <p class="subtitle">
        {$_('oauthDelegation.authenticateAs', { values: { controller: '@' + controllerIdentifier.replace(/^@/, ''), delegated: delegatedHandle } })}
      </p>
    </header>

    {#if error}
      <div class="error">{error}</div>
    {/if}

    <button class="back-link" onclick={goBack} disabled={submitting}>
      &larr; {$_('oauthDelegation.useDifferentController')}
    </button>

    <form onsubmit={handlePasswordSubmit}>
      {#if passkeySupported && hasPasskeys}
        <div class="auth-methods">
          <div class="passkey-method">
            <h3>{$_('oauthDelegation.signInWithPasskey')}</h3>
            <button
              type="button"
              class="passkey-btn"
              onclick={handlePasskeyLogin}
              disabled={submitting}
            >
              <svg class="passkey-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M15 7a4 4 0 1 0-8 0 4 4 0 0 0 8 0z" />
                <path d="M17 17v4l3-2-3-2z" />
                <path d="M12 11c-4 0-6 2-6 4v4h9" />
              </svg>
              <span class="passkey-text">
                {submitting ? $_('oauthDelegation.authenticating') : $_('oauthDelegation.usePasskey')}
              </span>
            </button>
          </div>

          <div class="method-divider">
            <span>{$_('oauthDelegation.or')}</span>
          </div>

          <div class="password-method">
            <h3>{$_('oauthDelegation.password')}</h3>
            <div class="field">
              <input
                type="password"
                bind:value={password}
                disabled={submitting}
                required
                autocomplete="current-password"
                placeholder={$_('oauthDelegation.enterPassword')}
              />
            </div>

            <label class="remember-device">
              <input type="checkbox" bind:checked={rememberDevice} disabled={submitting} />
              <span>{$_('oauthDelegation.rememberDevice')}</span>
            </label>

            <button type="submit" class="submit-btn" disabled={submitting || !password}>
              {submitting ? $_('oauthDelegation.signingIn') : $_('oauthDelegation.signIn')}
            </button>
          </div>
        </div>
      {:else}
        <div class="field">
          <label for="password">{$_('oauthDelegation.password')}</label>
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
          <span>{$_('oauthDelegation.rememberDevice')}</span>
        </label>

        <div class="actions">
          <button type="button" class="cancel-btn" onclick={handleCancel} disabled={submitting}>
            {$_('common.cancel')}
          </button>
          <button type="submit" class="submit-btn" disabled={submitting || !password}>
            {submitting ? $_('oauthDelegation.signingIn') : $_('oauthDelegation.signIn')}
          </button>
        </div>
      {/if}
    </form>
  {:else}
    <header class="page-header">
      <h1>{$_('oauthDelegation.title')}</h1>
    </header>
    <div class="error">{error || $_('oauthDelegation.unableToLoad')}</div>
    <div class="actions">
      <button type="button" class="cancel-btn" onclick={handleCancel}>
        {$_('oauthDelegation.goBack')}
      </button>
    </div>
  {/if}
</div>

<style>
  .delegation-container {
    max-width: var(--width-md);
    margin: var(--space-9) auto;
    padding: var(--space-7);
  }

  .loading {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 200px;
    color: var(--text-secondary);
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
    line-height: 1.6;
  }

  .back-link {
    display: inline-flex;
    align-items: center;
    padding: var(--space-2) 0;
    background: none;
    border: none;
    color: var(--accent);
    font-size: var(--text-sm);
    cursor: pointer;
    margin-bottom: var(--space-4);
  }

  .back-link:hover:not(:disabled) {
    text-decoration: underline;
  }

  .back-link:disabled {
    opacity: 0.6;
    cursor: not-allowed;
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

  input[type="password"],
  input[type="text"] {
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
    transition: background-color var(--transition-fast), border-color var(--transition-fast);
  }

  .passkey-btn:hover:not(:disabled) {
    background: var(--accent-hover);
    border-color: var(--accent-hover);
  }

  .passkey-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
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
