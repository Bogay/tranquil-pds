<script lang="ts">
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import {
    createRegistrationFlow,
    restoreRegistrationFlow,
    VerificationStep,
    KeyChoiceStep,
    DidDocStep,
  } from '../lib/registration'
  import AccountTypeSwitcher from '../components/AccountTypeSwitcher.svelte'
  import { ensureRequestUri, getRequestUriFromUrl } from '../lib/oauth'

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
  let confirmPassword = $state('')
  let clientName = $state<string | null>(null)

  $effect(() => {
    if (!serverInfoLoaded) {
      serverInfoLoaded = true
      ensureRequestUri().then((requestUri) => {
        if (!requestUri) return
        loadServerInfo()
        checkSsoAvailable()
        fetchClientName()
      }).catch((err) => {
        console.error('Failed to ensure OAuth request URI:', err)
      })
    }
  })

  async function fetchClientName() {
    const requestUri = getRequestUriFromUrl()
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

  $effect(() => {
    if (flow?.state.step === 'redirect-to-dashboard') {
      completeOAuthRegistration()
    }
  })

  let creatingStarted = false
  $effect(() => {
    if (flow?.state.step === 'creating' && !creatingStarted) {
      creatingStarted = true
      flow.createPasswordAccount()
    }
  })

  async function loadServerInfo() {
    try {
      const restored = restoreRegistrationFlow()
      if (restored && restored.state.mode === 'password') {
        flow = restored
        serverInfo = await api.describeServer()
      } else {
        serverInfo = await api.describeServer()
        const hostname = serverInfo?.availableUserDomains?.[0] || window.location.hostname
        flow = createRegistrationFlow('password', hostname)
      }
    } catch (e) {
      console.error('Failed to load server info:', e)
    } finally {
      loadingServerInfo = false
    }
  }

  function validateInfoStep(): string | null {
    if (!flow) return 'Flow not initialized'
    const info = flow.info
    if (!info.handle.trim()) return $_('register.validation.handleRequired')
    if (info.handle.includes('.')) return $_('register.validation.handleNoDots')
    if (!info.password) return $_('register.validation.passwordRequired')
    if (info.password.length < 8) return $_('register.validation.passwordLength')
    if (info.password !== confirmPassword) return $_('register.validation.passwordsMismatch')
    if (serverInfo?.inviteCodeRequired && !info.inviteCode?.trim()) {
      return $_('register.validation.inviteCodeRequired')
    }
    if (info.didType === 'web-external') {
      if (!info.externalDid?.trim()) return $_('register.validation.externalDidRequired')
      if (!info.externalDid.trim().startsWith('did:web:')) return $_('register.validation.externalDidFormat')
    }
    switch (info.verificationChannel) {
      case 'email':
        if (!info.email.trim()) return $_('register.validation.emailRequired')
        break
      case 'discord':
        if (!info.discordId?.trim()) return $_('register.validation.discordIdRequired')
        break
      case 'telegram':
        if (!info.telegramUsername?.trim()) return $_('register.validation.telegramRequired')
        break
      case 'signal':
        if (!info.signalNumber?.trim()) return $_('register.validation.signalRequired')
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

    flow.clearError()
    flow.proceedFromInfo()
  }

  async function handleCreateAccount() {
    if (!flow) return
    await flow.createPasswordAccount()
  }

  async function handleComplete() {
    if (flow) {
      await flow.finalizeSession()
    }
    navigate(routes.dashboard)
  }

  async function completeOAuthRegistration() {
    const requestUri = getRequestUriFromUrl()
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
    } catch (err) {
      console.error('OAuth registration completion failed:', err)
      flow.setError(err instanceof Error ? err.message : $_('common.error'))
    }
  }

  function isChannelAvailable(ch: string): boolean {
    const available = serverInfo?.availableCommsChannels ?? ['email']
    return available.includes(ch)
  }

  function channelLabel(ch: string): string {
    switch (ch) {
      case 'email': return $_('register.email')
      case 'discord': return $_('register.discord')
      case 'telegram': return $_('register.telegram')
      case 'signal': return $_('register.signal')
      default: return ch
    }
  }

  let fullHandle = $derived(() => {
    if (!flow?.info.handle.trim()) return ''
    if (flow.info.handle.includes('.')) return flow.info.handle.trim()
    const domain = serverInfo?.availableUserDomains?.[0]
    if (domain) return `${flow.info.handle.trim()}.${domain}`
    return flow.info.handle.trim()
  })

  function extractDomain(did: string): string {
    return did.replace('did:web:', '').replace(/%3A/g, ':')
  }

  function getSubtitle(): string {
    if (!flow) return ''
    switch (flow.state.step) {
      case 'info': return $_('register.subtitle')
      case 'key-choice': return $_('register.subtitleKeyChoice')
      case 'initial-did-doc': return $_('register.subtitleInitialDidDoc')
      case 'creating': return $_('common.creating')
      case 'verify': return $_('register.subtitleVerify', { values: { channel: channelLabel(flow.info.verificationChannel) } })
      case 'updated-did-doc': return $_('register.subtitleUpdatedDidDoc')
      case 'activating': return $_('register.subtitleActivating')
      case 'redirect-to-dashboard': return $_('register.subtitleComplete')
      default: return ''
    }
  }
</script>

<div class="page">
  <header class="page-header">
    <h1>{$_('register.title')}</h1>
    <p class="subtitle">{getSubtitle()}</p>
    {#if clientName}
      <p class="client-name">{$_('oauth.login.subtitle')} <strong>{clientName}</strong></p>
    {/if}
  </header>

  {#if flow?.state.error}
    <div class="message error">{flow.state.error}</div>
  {/if}

  {#if loadingServerInfo || !flow}
    <div class="loading">
      <div class="spinner md"></div>
    </div>
  {:else if flow.state.step === 'info'}
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

    <AccountTypeSwitcher active="password" {ssoAvailable} oauthRequestUri={getRequestUriFromUrl()} />

    <div class="split-layout sidebar-right">
      <div class="form-section">
        <form onsubmit={handleInfoSubmit}>
          <div class="field">
            <label for="handle">{$_('register.handle')}</label>
            <input
              id="handle"
              type="text"
              bind:value={flow.info.handle}
              placeholder={$_('register.handlePlaceholder')}
              disabled={flow.state.submitting}
              required
            />
            {#if flow.info.handle.includes('.')}
              <p class="hint warning">{$_('register.handleDotWarning')}</p>
            {:else if fullHandle()}
              <p class="hint">{$_('register.handleHint', { values: { handle: fullHandle() } })}</p>
            {/if}
          </div>

          <div class="form-row">
            <div class="field">
              <label for="password">{$_('register.password')}</label>
              <input
                id="password"
                type="password"
                bind:value={flow.info.password}
                placeholder={$_('register.passwordPlaceholder')}
                disabled={flow.state.submitting}
                required
                minlength="8"
              />
            </div>

            <div class="field">
              <label for="confirm-password">{$_('register.confirmPassword')}</label>
              <input
                id="confirm-password"
                type="password"
                bind:value={confirmPassword}
                placeholder={$_('register.confirmPasswordPlaceholder')}
                disabled={flow.state.submitting}
                required
              />
            </div>
          </div>

          <fieldset class="section-fieldset">
            <legend>{$_('register.identityType')}</legend>
            <div class="radio-group">
              <label class="radio-label">
                <input type="radio" name="didType" value="plc" bind:group={flow.info.didType} disabled={flow.state.submitting} />
                <span class="radio-content">
                  <strong>{$_('register.didPlc')}</strong> {$_('register.didPlcRecommended')}
                  <span class="radio-hint">{$_('register.didPlcHint')}</span>
                </span>
              </label>

              <label class="radio-label" class:disabled={serverInfo?.selfHostedDidWebEnabled === false}>
                <input type="radio" name="didType" value="web" bind:group={flow.info.didType} disabled={flow.state.submitting || serverInfo?.selfHostedDidWebEnabled === false} />
                <span class="radio-content">
                  <strong>{$_('register.didWeb')}</strong>
                  {#if serverInfo?.selfHostedDidWebEnabled === false}
                    <span class="radio-hint disabled-hint">{$_('register.didWebDisabledHint')}</span>
                  {:else}
                    <span class="radio-hint">{$_('register.didWebHint')}</span>
                  {/if}
                </span>
              </label>

              <label class="radio-label">
                <input type="radio" name="didType" value="web-external" bind:group={flow.info.didType} disabled={flow.state.submitting} />
                <span class="radio-content">
                  <strong>{$_('register.didWebBYOD')}</strong>
                  <span class="radio-hint">{$_('register.didWebBYODHint')}</span>
                </span>
              </label>
            </div>

            {#if flow.info.didType === 'web'}
              <div class="warning-box">
                <strong>{$_('register.didWebWarningTitle')}</strong>
                <ul>
                  <li><strong>{$_('register.didWebWarning1')}</strong> {$_('register.didWebWarning1Detail', { values: { did: `did:web:yourhandle.${serverInfo?.availableUserDomains?.[0] || 'this-pds.com'}` } })}</li>
                  <li><strong>{$_('register.didWebWarning2')}</strong> {$_('register.didWebWarning2Detail')}</li>
                  <li><strong>{$_('register.didWebWarning3')}</strong> {$_('register.didWebWarning3Detail')}</li>
                  <li><strong>{$_('register.didWebWarning4')}</strong> {$_('register.didWebWarning4Detail')}</li>
                </ul>
              </div>
            {/if}

            {#if flow.info.didType === 'web-external'}
              <div class="field">
                <label for="external-did">{$_('register.externalDid')}</label>
                <input
                  id="external-did"
                  type="text"
                  bind:value={flow.info.externalDid}
                  placeholder={$_('register.externalDidPlaceholder')}
                  disabled={flow.state.submitting}
                  required
                />
                <p class="hint">{$_('register.externalDidHint')}</p>
              </div>
            {/if}
          </fieldset>

          <fieldset class="section-fieldset">
            <legend>{$_('register.contactMethod')}</legend>
            <div class="contact-fields">
              <div class="field">
                <label for="verification-channel">{$_('register.verificationMethod')}</label>
                <select id="verification-channel" bind:value={flow.info.verificationChannel} disabled={flow.state.submitting}>
                  <option value="email">{$_('register.email')}</option>
                  <option value="discord" disabled={!isChannelAvailable('discord')}>
                    {$_('register.discord')}{isChannelAvailable('discord') ? '' : ` (${$_('register.notConfigured')})`}
                  </option>
                  <option value="telegram" disabled={!isChannelAvailable('telegram')}>
                    {$_('register.telegram')}{isChannelAvailable('telegram') ? '' : ` (${$_('register.notConfigured')})`}
                  </option>
                  <option value="signal" disabled={!isChannelAvailable('signal')}>
                    {$_('register.signal')}{isChannelAvailable('signal') ? '' : ` (${$_('register.notConfigured')})`}
                  </option>
                </select>
              </div>

              {#if flow.info.verificationChannel === 'email'}
                <div class="field">
                  <label for="email">{$_('register.emailAddress')}</label>
                  <input
                    id="email"
                    type="email"
                    bind:value={flow.info.email}
                    onblur={() => flow?.checkEmailInUse(flow.info.email)}
                    placeholder={$_('register.emailPlaceholder')}
                    disabled={flow.state.submitting}
                    required
                  />
                  {#if flow.state.emailInUse}
                    <p class="hint warning">{$_('register.emailInUseWarning')}</p>
                  {/if}
                </div>
              {:else if flow.info.verificationChannel === 'discord'}
                <div class="field">
                  <label for="discord-id">{$_('register.discordId')}</label>
                  <input
                    id="discord-id"
                    type="text"
                    bind:value={flow.info.discordId}
                    onblur={() => flow?.checkCommsChannelInUse('discord', flow.info.discordId ?? '')}
                    placeholder={$_('register.discordIdPlaceholder')}
                    disabled={flow.state.submitting}
                    required
                  />
                  <p class="hint">{$_('register.discordIdHint')}</p>
                  {#if flow.state.discordInUse}
                    <p class="hint warning">{$_('register.discordInUseWarning')}</p>
                  {/if}
                </div>
              {:else if flow.info.verificationChannel === 'telegram'}
                <div class="field">
                  <label for="telegram-username">{$_('register.telegramUsername')}</label>
                  <input
                    id="telegram-username"
                    type="text"
                    bind:value={flow.info.telegramUsername}
                    onblur={() => flow?.checkCommsChannelInUse('telegram', flow.info.telegramUsername ?? '')}
                    placeholder={$_('register.telegramUsernamePlaceholder')}
                    disabled={flow.state.submitting}
                    required
                  />
                  {#if flow.state.telegramInUse}
                    <p class="hint warning">{$_('register.telegramInUseWarning')}</p>
                  {/if}
                </div>
              {:else if flow.info.verificationChannel === 'signal'}
                <div class="field">
                  <label for="signal-number">{$_('register.signalNumber')}</label>
                  <input
                    id="signal-number"
                    type="tel"
                    bind:value={flow.info.signalNumber}
                    onblur={() => flow?.checkCommsChannelInUse('signal', flow.info.signalNumber ?? '')}
                    placeholder={$_('register.signalNumberPlaceholder')}
                    disabled={flow.state.submitting}
                    required
                  />
                  <p class="hint">{$_('register.signalNumberHint')}</p>
                  {#if flow.state.signalInUse}
                    <p class="hint warning">{$_('register.signalInUseWarning')}</p>
                  {/if}
                </div>
              {/if}
            </div>
          </fieldset>

          {#if serverInfo?.inviteCodeRequired}
            <div class="field">
              <label for="invite-code">{$_('register.inviteCode')} <span class="required">{$_('register.inviteCodeRequired')}</span></label>
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

          <button type="submit" disabled={flow.state.submitting}>
            {flow.state.submitting ? $_('common.creating') : $_('register.createButton')}
          </button>
        </form>

        <div class="form-links">
          <p class="link-text">
            {$_('register.alreadyHaveAccount')} <a href={getFullUrl(routes.login)}>{$_('register.signIn')}</a>
          </p>
        </div>
      </div>

      <aside class="info-panel">
        <h3>{$_('register.identityHint')}</h3>
        <p>{$_('register.infoIdentityDesc')}</p>

        <h3>{$_('register.contactMethodHint')}</h3>
        <p>{$_('register.infoContactDesc')}</p>

        <h3>{$_('register.infoNextTitle')}</h3>
        <p>{$_('register.infoNextDesc')}</p>
      </aside>
    </div>

  {:else if flow.state.step === 'key-choice'}
    <KeyChoiceStep {flow} />

  {:else if flow.state.step === 'initial-did-doc'}
    <DidDocStep
      {flow}
      type="initial"
      onConfirm={handleCreateAccount}
      onBack={() => flow?.goBack()}
    />

  {:else if flow.state.step === 'creating'}
    <div class="loading">
      <div class="spinner md"></div>
      <p>{$_('common.creating')}</p>
    </div>

  {:else if flow.state.step === 'verify'}
    <VerificationStep {flow} />

  {:else if flow.state.step === 'updated-did-doc'}
    <DidDocStep
      {flow}
      type="updated"
      onConfirm={() => flow?.activateAccount()}
    />

  {:else if flow.state.step === 'redirect-to-dashboard'}
    <div class="loading">
      <div class="spinner md"></div>
      <p>{$_('register.redirecting')}</p>
    </div>
  {/if}
</div>

<style>
  .client-name {
    color: var(--text-secondary);
    margin-top: var(--space-2);
  }

  form {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }

  button[type="submit"] {
    margin-top: var(--space-3);
  }
</style>
