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
  import HandleInput from '../components/HandleInput.svelte'
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
  let selectedDomain = $state('')
  let checkHandleTimeout: ReturnType<typeof setTimeout> | null = null

  $effect(() => {
    if (!flow) return
    const handle = flow.info.handle
    if (checkHandleTimeout) {
      clearTimeout(checkHandleTimeout)
    }
    if (handle.length >= 3 && !handle.includes('.')) {
      checkHandleTimeout = setTimeout(() => flow?.checkHandleAvailability(handle), 400)
    }
  })

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
      selectedDomain = serverInfo?.availableUserDomains?.[0] || window.location.hostname
      if (flow) flow.setSelectedDomain(selectedDomain)
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
        if (!info.discordUsername?.trim()) return $_('register.validation.discordUsernameRequired')
        break
      case 'telegram':
        if (!info.telegramUsername?.trim()) return $_('register.validation.telegramRequired')
        break
      case 'signal':
        if (!info.signalUsername?.trim()) return $_('register.validation.signalRequired')
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
          app_password: flow.account.appPassword || flow.info.password,
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
    return selectedDomain ? `${flow.info.handle.trim()}.${selectedDomain}` : flow.info.handle.trim()
  })

  function extractDomain(did: string): string {
    return did.replace('did:web:', '').replace(/%3A/g, ':')
  }

  async function handleCancel() {
    const requestUri = getRequestUriFromUrl()
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

      if (!response.ok) {
        window.history.back()
        return
      }

      const data = await response.json()
      if (data.redirect_uri) {
        window.location.href = data.redirect_uri
      } else {
        window.history.back()
      }
    } catch {
      window.history.back()
    }
  }
</script>

<div class="page">
  <header class="page-header">
    <h1>{$_('register.title')}</h1>
    {#if clientName}
      <p class="subtitle">{$_('oauth.register.subtitle')} <strong>{clientName}</strong></p>
    {/if}
  </header>

  {#if flow?.state.error}
    <div class="message error">{flow.state.error}</div>
  {/if}

  {#if loadingServerInfo || !flow}
    <div class="loading"></div>
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

    <form class="register-form" onsubmit={handleInfoSubmit}>
      <div>
        <label for="handle">{$_('register.handle')}</label>
        <HandleInput
          value={flow.info.handle}
          domains={serverInfo?.availableUserDomains ?? []}
          {selectedDomain}
          placeholder={$_('register.handlePlaceholder')}
          disabled={flow.state.submitting}
          onInput={(v) => { flow!.info.handle = v }}
          onDomainChange={(d) => { selectedDomain = d; flow!.setSelectedDomain(d) }}
        />
        {#if flow.info.handle.includes('.')}
          <p class="hint warning">{$_('register.handleDotWarning')}</p>
        {:else if flow.state.checkingHandle}
          <p class="hint">{$_('common.checking')}</p>
        {:else if flow.state.handleAvailable === false}
          <p class="hint warning">{$_('register.handleTaken')}</p>
        {:else if flow.state.handleAvailable === true && fullHandle()}
          <p class="hint success">{$_('register.handleHint', { values: { handle: fullHandle() } })}</p>
        {:else if fullHandle()}
          <p class="hint">{$_('register.handleHint', { values: { handle: fullHandle() } })}</p>
        {/if}
      </div>

      <div>
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

      <div>
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

      <div>
        <label for="verification-channel">{$_('register.verificationMethod')}</label>
        <select id="verification-channel" bind:value={flow.info.verificationChannel} disabled={flow.state.submitting}>
          <option value="email">{$_('register.email')}</option>
          {#if isChannelAvailable('discord')}
            <option value="discord">{$_('register.discord')}</option>
          {/if}
          {#if isChannelAvailable('telegram')}
            <option value="telegram">{$_('register.telegram')}</option>
          {/if}
          {#if isChannelAvailable('signal')}
            <option value="signal">{$_('register.signal')}</option>
          {/if}
        </select>
      </div>

      {#if flow.info.verificationChannel === 'email'}
        <div>
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
        <div>
          <label for="discord-username">{$_('register.discordUsername')}</label>
          <input
            id="discord-username"
            type="text"
            bind:value={flow.info.discordUsername}
            onblur={() => flow?.checkCommsChannelInUse('discord', flow.info.discordUsername ?? '')}
            placeholder={$_('register.discordUsernamePlaceholder')}
            disabled={flow.state.submitting}
            required
          />
          {#if flow.state.discordInUse}
            <p class="hint warning">{$_('register.discordInUseWarning')}</p>
          {/if}
        </div>
      {:else if flow.info.verificationChannel === 'telegram'}
        <div>
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
        <div>
          <label for="signal-number">{$_('register.signalUsername')}</label>
          <input
            id="signal-number"
            type="tel"
            bind:value={flow.info.signalUsername}
            onblur={() => flow?.checkCommsChannelInUse('signal', flow.info.signalUsername ?? '')}
            placeholder={$_('register.signalUsernamePlaceholder')}
            disabled={flow.state.submitting}
            required
          />
          <p class="hint">{$_('register.signalUsernameHint')}</p>
          {#if flow.state.signalInUse}
            <p class="hint warning">{$_('register.signalInUseWarning')}</p>
          {/if}
        </div>
      {/if}

      <fieldset class="identity-section">
        <legend>{$_('register.identityType')}</legend>
        <div class="radio-group">
          <label class="radio-label">
            <input type="radio" name="didType" value="plc" bind:group={flow.info.didType} disabled={flow.state.submitting} />
            <span class="radio-content">
              <strong>{$_('register.didPlc')}</strong>
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
      </fieldset>

      {#if flow.info.didType === 'web'}
        <div class="warning-box">
          <strong>{$_('register.didWebWarningTitle')}</strong>
          <ul>
            <li><strong>{$_('register.didWebWarning1')}</strong> {$_('register.didWebWarning1Detail', { values: { did: `did:web:yourhandle.${serverInfo?.availableUserDomains?.[0] || 'this-pds.com'}` } })}</li>
            <li><strong>{$_('register.didWebWarning2')}</strong> {$_('register.didWebWarning2Detail')}</li>
            {#if $_('register.didWebWarning3')}
              <li><strong>{$_('register.didWebWarning3')}</strong> {$_('register.didWebWarning3Detail')}</li>
            {/if}
          </ul>
        </div>
      {/if}

      {#if flow.info.didType === 'web-external'}
        <div>
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

      {#if serverInfo?.inviteCodeRequired}
        <div>
          <label for="invite-code">{$_('register.inviteCode')}</label>
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

      <div class="form-actions">
        <button type="button" class="secondary" onclick={handleCancel} disabled={flow.state.submitting}>
          {$_('common.cancel')}
        </button>
        <button type="submit" class="primary" disabled={flow.state.submitting || flow.state.handleAvailable === false || flow.state.checkingHandle}>
          {flow.state.submitting ? $_('common.loading') : $_('common.continue')}
        </button>
      </div>
    </form>

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
      <p>{$_('register.redirecting')}</p>
    </div>
  {/if}
</div>
