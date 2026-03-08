<script lang="ts">
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { api } from '../lib/api'
  import { _ } from '../lib/i18n'
  import {
    createRegistrationFlow,
    restoreRegistrationFlow,
    VerificationStep,
    KeyChoiceStep,
    DidDocStep,
    AppPasswordStep,
  } from '../lib/registration'
  import {
    prepareCreationOptions,
    serializeAttestationResponse,
    type WebAuthnCreationOptionsResponse,
  } from '../lib/webauthn'
  import AccountTypeSwitcher from '../components/AccountTypeSwitcher.svelte'
  import HandleInput from '../components/HandleInput.svelte'

  let serverInfo = $state<{
    availableUserDomains: string[]
    inviteCodeRequired: boolean
    availableCommsChannels?: string[]
    selfHostedDidWebEnabled?: boolean
  } | null>(null)
  let loadingServerInfo = $state(true)
  let serverInfoLoaded = false
  let ssoAvailable = $state(false)

  let flow = $state<ReturnType<typeof createRegistrationFlow> | null>(null)
  let passkeyName = $state('')
  let clientName = $state<string | null>(null)
  let selectedDomain = $state('')

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('request_uri')
  }

  $effect(() => {
    if (!serverInfoLoaded) {
      serverInfoLoaded = true
      loadServerInfo()
      fetchClientName()
      checkSsoAvailable()
    }
  })

  async function checkSsoAvailable() {
    try {
      const response = await fetch('/oauth/sso/providers')
      if (response.ok) {
        const data = await response.json()
        ssoAvailable = (data.providers?.length ?? 0) > 0
      }
    } catch {
      ssoAvailable = false
    }
  }

  async function fetchClientName() {
    const requestUri = getRequestUri()
    if (!requestUri) return

    try {
      const response = await fetch(`/oauth/authorize?request_uri=${encodeURIComponent(requestUri)}`, {
        headers: { 'Accept': 'application/json' }
      })
      if (response.ok) {
        const data = await response.json()
        clientName = data.client_name || null
      }
    } catch {
      clientName = null
    }
  }

  $effect(() => {
    if (flow?.state.step === 'redirect-to-dashboard') {
      completeOAuthRegistration()
    }
  })

  let creatingStarted = false
  $effect(() => {
    if (flow?.state.step === 'creating' && !creatingStarted) {
      creatingStarted = true
      flow.createPasskeyAccount()
    }
  })

  async function loadServerInfo() {
    try {
      const restored = restoreRegistrationFlow()
      if (restored && restored.state.mode === 'passkey') {
        flow = restored
        serverInfo = await api.describeServer()
      } else {
        serverInfo = await api.describeServer()
        const hostname = serverInfo?.availableUserDomains?.[0] || window.location.hostname
        flow = createRegistrationFlow('passkey', hostname)
      }
      selectedDomain = serverInfo?.availableUserDomains?.[0] || window.location.hostname
    } catch (e) {
      console.error('Failed to load server info:', e)
    } finally {
      loadingServerInfo = false
    }
  }

  function validateInfoStep(): string | null {
    if (!flow) return 'Flow not initialized'
    const info = flow.info
    if (!info.handle.trim()) return $_('registerPasskey.errors.handleRequired')
    if (info.handle.includes('.')) return $_('registerPasskey.errors.handleNoDots')
    if (serverInfo?.inviteCodeRequired && !info.inviteCode?.trim()) {
      return $_('registerPasskey.errors.inviteRequired')
    }
    if (info.didType === 'web-external') {
      if (!info.externalDid?.trim()) return $_('registerPasskey.errors.externalDidRequired')
      if (!info.externalDid.trim().startsWith('did:web:')) return $_('registerPasskey.errors.externalDidFormat')
    }
    switch (info.verificationChannel) {
      case 'email':
        if (!info.email.trim()) return $_('registerPasskey.errors.emailRequired')
        break
      case 'discord':
        if (!info.discordUsername?.trim()) return $_('registerPasskey.errors.discordRequired')
        break
      case 'telegram':
        if (!info.telegramUsername?.trim()) return $_('registerPasskey.errors.telegramRequired')
        break
      case 'signal':
        if (!info.signalUsername?.trim()) return $_('registerPasskey.errors.signalRequired')
        break
    }
    return null
  }

  async function handleInfoSubmit(e: Event) {
    e.preventDefault()
    if (!flow) return

    const validationError = validateInfoStep()
    if (validationError) {
      flow.setError(validationError)
      return
    }

    if (!window.PublicKeyCredential) {
      flow.setError($_('registerPasskey.errors.passkeysNotSupported'))
      return
    }

    flow.clearError()
    flow.proceedFromInfo()
  }

  async function handlePasskeyRegistration() {
    if (!flow || !flow.account) return

    flow.setSubmitting(true)
    flow.clearError()

    try {
      const { options } = await api.startPasskeyRegistrationForSetup(
        flow.account.did,
        flow.account.setupToken!,
        passkeyName || undefined
      )

      const publicKeyOptions = prepareCreationOptions(options as unknown as WebAuthnCreationOptionsResponse)
      const credential = await navigator.credentials.create({
        publicKey: publicKeyOptions
      })

      if (!credential) {
        flow.setError($_('registerPasskey.errors.passkeyCancelled'))
        flow.setSubmitting(false)
        return
      }

      const credentialResponse = serializeAttestationResponse(credential as PublicKeyCredential)

      const result = await api.completePasskeySetup(
        flow.account.did,
        flow.account.setupToken!,
        credentialResponse,
        passkeyName || undefined
      )

      flow.setPasskeyComplete(result.appPassword, result.appPasswordName)
    } catch (err) {
      if (err instanceof DOMException && err.name === 'NotAllowedError') {
        flow.setError($_('registerPasskey.errors.passkeyCancelled'))
      } else if (err instanceof Error) {
        flow.setError(err.message || $_('registerPasskey.errors.passkeyFailed'))
      } else {
        flow.setError($_('registerPasskey.errors.passkeyFailed'))
      }
    } finally {
      flow.setSubmitting(false)
    }
  }

  async function completeOAuthRegistration() {
    const requestUri = getRequestUri()
    if (!requestUri || !flow?.account) {
      navigate(routes.dashboard)
      return
    }

    try {
      const response = await fetch('/oauth/register/complete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          request_uri: requestUri,
          did: flow.account.did,
          app_password: flow.account.appPassword,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        flow.setError(data.error_description || data.error || $_('common.error'))
        return
      }

      if (data.redirect_uri) {
        window.location.href = data.redirect_uri
        return
      }

      navigate(routes.dashboard)
    } catch {
      flow.setError($_('common.error'))
    }
  }

  function isChannelAvailable(ch: string): boolean {
    const available = serverInfo?.availableCommsChannels ?? ['email']
    return available.includes(ch)
  }

  function channelLabel(ch: string): string {
    switch (ch) {
      case 'email':
        return $_('register.email')
      case 'discord':
        return $_('register.discord')
      case 'telegram':
        return $_('register.telegram')
      case 'signal':
        return $_('register.signal')
      default:
        return ch
    }
  }

  let fullHandle = $derived(() => {
    if (!flow?.info.handle.trim()) return ''
    if (flow.info.handle.includes('.')) return flow.info.handle.trim()
    return selectedDomain ? `${flow.info.handle.trim()}.${selectedDomain}` : flow.info.handle.trim()
  })

  async function handleCancel() {
    const requestUri = getRequestUri()
    if (!requestUri) {
      window.history.back()
      return
    }

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

  function goToLogin() {
    const requestUri = getRequestUri()
    if (requestUri) {
      navigate(routes.oauthLogin, { params: { request_uri: requestUri } })
    } else {
      navigate(routes.login)
    }
  }
</script>

<div class="oauth-register-container">
  {#if loadingServerInfo}
    <div class="loading">
      <div class="spinner"></div>
      <p>{$_('common.loading')}</p>
    </div>
  {:else if flow}
    <header class="page-header">
      <h1>{$_('oauth.register.title')}</h1>
      <p class="subtitle">
        {#if clientName}
          {$_('oauth.register.subtitle')} <strong>{clientName}</strong>
        {:else}
          {$_('oauth.register.subtitleGeneric')}
        {/if}
      </p>
    </header>

    {#if flow.state.error}
      <div class="error">{flow.state.error}</div>
    {/if}

    {#if flow.state.step === 'info'}
      <div class="migrate-callout">
        <div class="migrate-icon">↗</div>
        <div class="migrate-content">
          <strong>{$_('register.migrateTitle')}</strong>
          <p>{$_('register.migrateDescription')}</p>
          <a href={getFullUrl(routes.migrate)} class="migrate-link">
            {$_('register.migrateLink')} →
          </a>
        </div>
      </div>

      <AccountTypeSwitcher active="passkey" {ssoAvailable} oauthRequestUri={getRequestUri()} />

      <div class="split-layout">
        <div class="form-section">
          <form onsubmit={handleInfoSubmit}>
        <div class="field">
          <label for="handle">{$_('register.handle')}</label>
          <HandleInput
            value={flow.info.handle}
            domains={serverInfo?.availableUserDomains ?? []}
            {selectedDomain}
            placeholder={$_('register.handlePlaceholder')}
            disabled={flow.state.submitting}
            onInput={(v) => { flow!.info.handle = v }}
            onDomainChange={(d) => { selectedDomain = d }}
          />
          {#if fullHandle()}
            <p class="hint">{$_('register.handleHint', { values: { handle: fullHandle() } })}</p>
          {/if}
        </div>

        <fieldset>
          <legend>{$_('register.contactMethod')}</legend>
          <div class="contact-fields">
            <div class="field">
              <label for="verification-channel">{$_('register.verificationMethod')}</label>
              <select id="verification-channel" bind:value={flow.info.verificationChannel} disabled={flow.state.submitting}>
                <option value="email">{channelLabel('email')}</option>
                {#if isChannelAvailable('discord')}
                  <option value="discord">{channelLabel('discord')}</option>
                {/if}
                {#if isChannelAvailable('telegram')}
                  <option value="telegram">{channelLabel('telegram')}</option>
                {/if}
                {#if isChannelAvailable('signal')}
                  <option value="signal">{channelLabel('signal')}</option>
                {/if}
              </select>
            </div>

            {#if flow.info.verificationChannel === 'email'}
              <div class="field">
                <label for="email">{$_('register.emailAddress')}</label>
                <input
                  id="email"
                  type="email"
                  bind:value={flow.info.email}
                  placeholder={$_('register.emailPlaceholder')}
                  disabled={flow.state.submitting}
                  required
                />
              </div>
            {:else if flow.info.verificationChannel === 'discord'}
              <div class="field">
                <label for="discord-username">{$_('register.discordUsername')}</label>
                <input
                  id="discord-username"
                  type="text"
                  bind:value={flow.info.discordUsername}
                  placeholder={$_('register.discordUsernamePlaceholder')}
                  disabled={flow.state.submitting}
                  required
                />
              </div>
            {:else if flow.info.verificationChannel === 'telegram'}
              <div class="field">
                <label for="telegram-username">{$_('register.telegramUsername')}</label>
                <input
                  id="telegram-username"
                  type="text"
                  bind:value={flow.info.telegramUsername}
                  placeholder={$_('register.telegramUsernamePlaceholder')}
                  disabled={flow.state.submitting}
                  required
                />
              </div>
            {:else if flow.info.verificationChannel === 'signal'}
              <div class="field">
                <label for="signal-number">{$_('register.signalUsername')}</label>
                <input
                  id="signal-number"
                  type="tel"
                  bind:value={flow.info.signalUsername}
                  placeholder={$_('register.signalUsernamePlaceholder')}
                  disabled={flow.state.submitting}
                  required
                />
                <p class="hint">{$_('register.signalUsernameHint')}</p>
              </div>
            {/if}
          </div>
        </fieldset>

        <fieldset>
          <legend>{$_('registerPasskey.identityType')}</legend>
          <p class="section-hint">{$_('registerPasskey.identityTypeHint')}</p>
          <div class="radio-group">
            <label class="radio-label">
              <input type="radio" name="didType" value="plc" bind:group={flow.info.didType} disabled={flow.state.submitting} />
              <span class="radio-content">
                <strong>{$_('registerPasskey.didPlcRecommended')}</strong>
                <span class="radio-hint">{$_('registerPasskey.didPlcHint')}</span>
              </span>
            </label>
            <label class="radio-label" class:disabled={serverInfo?.selfHostedDidWebEnabled === false}>
              <input type="radio" name="didType" value="web" bind:group={flow.info.didType} disabled={flow.state.submitting || serverInfo?.selfHostedDidWebEnabled === false} />
              <span class="radio-content">
                <strong>{$_('registerPasskey.didWeb')}</strong>
                {#if serverInfo?.selfHostedDidWebEnabled === false}
                  <span class="radio-hint disabled-hint">{$_('registerPasskey.didWebDisabledHint')}</span>
                {:else}
                  <span class="radio-hint">{$_('registerPasskey.didWebHint')}</span>
                {/if}
              </span>
            </label>
            <label class="radio-label">
              <input type="radio" name="didType" value="web-external" bind:group={flow.info.didType} disabled={flow.state.submitting} />
              <span class="radio-content">
                <strong>{$_('registerPasskey.didWebBYOD')}</strong>
                <span class="radio-hint">{$_('registerPasskey.didWebBYODHint')}</span>
              </span>
            </label>
          </div>
          {#if flow.info.didType === 'web'}
            <div class="warning-box">
              <strong>{$_('registerPasskey.didWebWarningTitle')}</strong>
              <ul>
                <li><strong>{$_('registerPasskey.didWebWarning1')}</strong> {@html $_('registerPasskey.didWebWarning1Detail', { values: { did: `<code>did:web:yourhandle.${serverInfo?.availableUserDomains?.[0] || 'this-pds.com'}</code>` } })}</li>
                <li><strong>{$_('registerPasskey.didWebWarning2')}</strong> {$_('registerPasskey.didWebWarning2Detail')}</li>
                <li><strong>{$_('registerPasskey.didWebWarning3')}</strong> {$_('registerPasskey.didWebWarning3Detail')}</li>
                <li><strong>{$_('registerPasskey.didWebWarning4')}</strong> {$_('registerPasskey.didWebWarning4Detail')}</li>
              </ul>
            </div>
          {/if}
          {#if flow.info.didType === 'web-external'}
            <div class="field">
              <label for="external-did">{$_('registerPasskey.externalDid')}</label>
              <input id="external-did" type="text" bind:value={flow.info.externalDid} placeholder={$_('registerPasskey.externalDidPlaceholder')} disabled={flow.state.submitting} required />
              <p class="hint">{$_('registerPasskey.externalDidHint')} <code>https://{flow.info.externalDid ? flow.extractDomain(flow.info.externalDid) : 'yourdomain.com'}/.well-known/did.json</code></p>
            </div>
          {/if}
        </fieldset>

        {#if serverInfo?.inviteCodeRequired}
          <div class="field">
            <label for="invite-code">{$_('register.inviteCode')} <span class="required">*</span></label>
            <input
              id="invite-code"
              type="text"
              bind:value={flow.info.inviteCode}
              placeholder={$_('register.inviteCodePlaceholder')}
              disabled={flow.state.submitting}
              required
            />
          </div>
        {/if}

        <div class="actions">
          <button type="submit" class="primary" disabled={flow.state.submitting}>
            {flow.state.submitting ? $_('common.loading') : $_('common.continue')}
          </button>
        </div>

        <div class="secondary-actions">
          <button type="button" class="link-btn" onclick={goToLogin}>
            {$_('oauth.register.haveAccount')}
          </button>
          <button type="button" class="link-btn" onclick={handleCancel}>
            {$_('common.cancel')}
          </button>
        </div>
          </form>

          <div class="form-links">
            <p class="link-text">
              {$_('register.alreadyHaveAccount')} <a href="/app/login">{$_('register.signIn')}</a>
            </p>
          </div>
        </div>

        <aside class="info-panel">
          <h3>{$_('registerPasskey.infoWhyPasskey')}</h3>
          <p>{$_('registerPasskey.infoWhyPasskeyDesc')}</p>

          <h3>{$_('registerPasskey.infoHowItWorks')}</h3>
          <p>{$_('registerPasskey.infoHowItWorksDesc')}</p>

          <h3>{$_('registerPasskey.infoAppAccess')}</h3>
          <p>{$_('registerPasskey.infoAppAccessDesc')}</p>
        </aside>
      </div>

    {:else if flow.state.step === 'key-choice'}
      <KeyChoiceStep {flow} />

    {:else if flow.state.step === 'initial-did-doc'}
      <DidDocStep {flow} type="initial" onConfirm={() => flow?.createPasskeyAccount()} onBack={() => flow?.goBack()} />

    {:else if flow.state.step === 'creating'}
      <div class="creating">
        <div class="spinner"></div>
        <p>{$_('registerPasskey.creatingAccount')}</p>
      </div>

    {:else if flow.state.step === 'passkey'}
      <div class="passkey-step">
        <h2>{$_('registerPasskey.setupPasskey')}</h2>
        <p>{$_('registerPasskey.passkeyDescription')}</p>

        <div class="field">
          <label for="passkey-name">{$_('registerPasskey.passkeyName')}</label>
          <input
            id="passkey-name"
            type="text"
            bind:value={passkeyName}
            placeholder={$_('registerPasskey.passkeyNamePlaceholder')}
            disabled={flow.state.submitting}
          />
          <p class="hint">{$_('registerPasskey.passkeyNameHint')}</p>
        </div>

        <button
          type="button"
          class="primary"
          onclick={handlePasskeyRegistration}
          disabled={flow.state.submitting}
        >
          {flow.state.submitting ? $_('common.loading') : $_('registerPasskey.registerPasskey')}
        </button>
      </div>

    {:else if flow.state.step === 'app-password'}
      <AppPasswordStep {flow} />

    {:else if flow.state.step === 'verify'}
      <VerificationStep {flow} />

    {:else if flow.state.step === 'updated-did-doc'}
      <DidDocStep {flow} type="updated" onConfirm={() => flow?.activateAccount()} />

    {:else if flow.state.step === 'activating'}
      <div class="creating">
        <div class="spinner"></div>
        <p>{$_('registerPasskey.activatingAccount')}</p>
      </div>
    {/if}
  {/if}
</div>

<style>
  .oauth-register-container {
    max-width: var(--width-lg);
    margin: var(--space-9) auto;
    padding: var(--space-7);
  }

  .loading, .creating {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-4);
    padding: var(--space-8);
  }

  .loading p, .creating p {
    color: var(--text-secondary);
  }

  .page-header {
    margin-bottom: var(--space-6);
  }

  .page-header h1 {
    margin: 0 0 var(--space-2) 0;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0;
  }

  .form-section {
    min-width: 0;
  }

  .form-links {
    margin-top: var(--space-6);
  }

  .link-text {
    text-align: center;
    color: var(--text-secondary);
  }

  .link-text a {
    color: var(--accent);
  }

  form {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
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

  input, select {
    padding: var(--space-3);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-size: var(--text-base);
    background: var(--bg-input);
    color: var(--text-primary);
  }

  input:focus, select:focus {
    outline: none;
    border-color: var(--accent);
  }

  .hint {
    font-size: var(--text-xs);
    color: var(--text-muted);
    margin: var(--space-1) 0 0 0;
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

  button.primary {
    flex: 1;
    padding: var(--space-3);
    background: var(--accent);
    color: var(--text-inverse);
    border: none;
    border-radius: var(--radius-md);
    font-size: var(--text-base);
    cursor: pointer;
    transition: background-color var(--transition-fast);
  }

  button.primary:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  button.primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .secondary-actions {
    display: flex;
    justify-content: center;
    gap: var(--space-4);
    margin-top: var(--space-4);
  }

  .link-btn {
    background: none;
    border: none;
    color: var(--accent);
    cursor: pointer;
    font-size: var(--text-sm);
    padding: var(--space-2);
  }

  .link-btn:hover {
    text-decoration: underline;
  }

  .contact-fields {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .required {
    color: var(--error-text);
  }

  .passkey-step {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .passkey-step h2 {
    margin: 0;
  }

  .passkey-step p {
    color: var(--text-secondary);
    margin: 0;
  }

  fieldset {
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: var(--space-4);
  }

  legend {
    padding: 0 var(--space-2);
    font-weight: var(--font-medium);
  }

  .spinner {
    width: 32px;
    height: 32px;
    border: 3px solid var(--border-color);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
