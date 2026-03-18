<script lang="ts">
  import { navigate, routes, getFullUrl, getCurrentPath } from '../lib/router.svelte'
  import { api } from '../lib/api'
  import { _ } from '../lib/i18n'
  import {
    createRegistrationFlow,
    restoreRegistrationFlow,
    VerificationStep,
    KeyChoiceStep,
    DidDocStep,
  } from '../lib/registration'
  import type { RegistrationMode } from '../lib/registration'
  import AppPasswordStep from '../components/migration/AppPasswordStep.svelte'
  import PasskeySetupStep from '../components/migration/PasskeySetupStep.svelte'
  import { performPasskeyRegistration, PasskeyCancelledError } from '../lib/flows/perform-passkey-registration'
  import AccountTypeSwitcher from '../components/AccountTypeSwitcher.svelte'
  import HandleInput from '../components/HandleInput.svelte'
  import IdentityTypeSection from '../components/IdentityTypeSection.svelte'
  import CommsChannelPicker from '../components/CommsChannelPicker.svelte'
  import { ensureRequestUri, getRequestUriFromUrl } from '../lib/oauth'

  const mode: RegistrationMode = getCurrentPath().includes('register-password') ? 'password' : 'passkey'
  const isPasskey = mode === 'passkey'

  let serverInfo = $state<{
    availableUserDomains: string[]
    inviteCodeRequired: boolean
    availableCommsChannels?: import('../lib/types/api').VerificationChannel[]
    selfHostedDidWebEnabled?: boolean
  } | null>(null)
  let loadingServerInfo = $state(true)
  let serverInfoLoaded = false
  let ssoAvailable = $state(false)

  let flow = $state<ReturnType<typeof createRegistrationFlow> | null>(null)
  let passkeyName = $state('')
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
        fetchClientName()
        checkSsoAvailable()
      }).catch((err) => {
        console.error('Failed to ensure OAuth request URI:', err)
      })
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

  $effect(() => {
    if (flow?.state.step === 'redirect-to-dashboard') {
      completeOAuthRegistration()
    }
  })

  let creatingStarted = false
  $effect(() => {
    if (flow?.state.step === 'creating' && !creatingStarted) {
      creatingStarted = true
      if (isPasskey) {
        flow.createPasskeyAccount()
      } else {
        flow.createPasswordAccount()
      }
    }
  })

  async function loadServerInfo() {
    try {
      const restored = restoreRegistrationFlow()
      if (restored && restored.state.mode === mode) {
        flow = restored
        serverInfo = await api.describeServer()
      } else {
        serverInfo = await api.describeServer()
        const hostname = serverInfo?.availableUserDomains?.[0] || window.location.hostname
        flow = createRegistrationFlow(mode, hostname)
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
    if (!info.handle.trim()) return $_('registerPasskey.errors.handleRequired')
    if (info.handle.includes('.')) return $_('registerPasskey.errors.handleNoDots')
    if (!isPasskey) {
      if (!info.password) return $_('register.validation.passwordRequired')
      if (info.password.length < 8) return $_('register.validation.passwordLength')
      if (info.password !== confirmPassword) return $_('register.validation.passwordsMismatch')
    }
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

    if (isPasskey && !window.PublicKeyCredential) {
      flow.setError($_('registerPasskey.errors.passkeysNotSupported'))
      return
    }

    flow.clearError()
    flow.proceedFromInfo()
  }

  async function handlePasskeyRegistration() {
    if (!flow || !flow.account) return

    const { did, setupToken } = flow.account
    if (!setupToken) return

    flow.setSubmitting(true)
    flow.clearError()

    try {
      const result = await performPasskeyRegistration({
        startRegistration: () => api.startPasskeyRegistrationForSetup(
          did, setupToken, passkeyName || undefined,
        ),
        completeSetup: (credential, name) => api.completePasskeySetup(
          did, setupToken, credential, name,
        ),
      }, passkeyName || undefined)

      flow.setPasskeyComplete(result.appPassword, result.appPasswordName)
    } catch (err) {
      if (err instanceof PasskeyCancelledError || (err instanceof DOMException && err.name === 'NotAllowedError')) {
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
    const requestUri = getRequestUriFromUrl()
    if (!requestUri || !flow?.account) {
      if (!isPasskey && flow) {
        await flow.finalizeSession()
      }
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
          app_password: flow.account.appPassword || (isPasskey ? undefined : flow.info.password),
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

  let fullHandle = $derived(() => {
    if (!flow?.info.handle.trim()) return ''
    if (flow.info.handle.includes('.')) return flow.info.handle.trim()
    return selectedDomain ? `${flow.info.handle.trim()}.${selectedDomain}` : flow.info.handle.trim()
  })

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

  function goToLogin() {
    const requestUri = getRequestUriFromUrl()
    if (requestUri) {
      navigate(routes.oauthLogin, { params: { request_uri: requestUri } })
    } else {
      navigate(routes.login)
    }
  }
</script>

<div class="page">
  {#if loadingServerInfo}
    <div class="loading"></div>
  {:else if flow}
    <header class="page-header">
      <h1>{isPasskey ? $_('oauth.register.title') : $_('register.title')}</h1>
      {#if clientName}
        <p class="subtitle">{$_('oauth.register.subtitle')} <strong>{clientName}</strong></p>
      {/if}
    </header>

    {#if flow.state.error}
      <div class="message error">{flow.state.error}</div>
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

      <AccountTypeSwitcher active={mode} {ssoAvailable} oauthRequestUri={getRequestUriFromUrl()} />

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

        {#if !isPasskey}
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
        {/if}

        <CommsChannelPicker
          channel={flow.info.verificationChannel}
          email={flow.info.email}
          discordUsername={flow.info.discordUsername ?? ''}
          telegramUsername={flow.info.telegramUsername ?? ''}
          signalUsername={flow.info.signalUsername ?? ''}
          availableChannels={serverInfo?.availableCommsChannels ?? ['email']}
          disabled={flow.state.submitting}
          onChannelChange={(ch) => { if (flow) flow.info.verificationChannel = ch }}
          onEmailChange={(v) => { if (flow) flow.info.email = v }}
          onDiscordChange={(v) => { if (flow) flow.info.discordUsername = v }}
          onTelegramChange={(v) => { if (flow) flow.info.telegramUsername = v }}
          onSignalChange={(v) => { if (flow) flow.info.signalUsername = v }}
        />

        <IdentityTypeSection
          didType={flow.info.didType}
          externalDid={flow.info.externalDid ?? ''}
          disabled={flow.state.submitting}
          selfHostedDidWebEnabled={serverInfo?.selfHostedDidWebEnabled !== false}
          defaultDomain={serverInfo?.availableUserDomains?.[0] || 'this-pds.com'}
          onDidTypeChange={(v) => { if (flow) flow.info.didType = v }}
          onExternalDidChange={(v) => { if (flow) flow.info.externalDid = v }}
        />

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
        onConfirm={() => isPasskey ? flow?.createPasskeyAccount() : flow?.createPasswordAccount()}
        onBack={() => flow?.goBack()}
      />

    {:else if flow.state.step === 'creating'}
      <div class="loading">
        <p>{isPasskey ? $_('registerPasskey.creatingAccount') : $_('common.creating')}</p>
      </div>

    {:else if isPasskey && flow.state.step === 'passkey'}
      <PasskeySetupStep
        {passkeyName}
        loading={flow.state.submitting}
        error={flow.state.error}
        onPasskeyNameChange={(n) => passkeyName = n}
        onRegister={handlePasskeyRegistration}
      />

    {:else if isPasskey && flow.state.step === 'app-password'}
      <AppPasswordStep
        appPassword={flow.account?.appPassword ?? ''}
        appPasswordName={flow.account?.appPasswordName ?? ''}
        loading={flow.state.submitting}
        onContinue={() => flow!.proceedFromAppPassword()}
      />

    {:else if flow.state.step === 'verify'}
      <VerificationStep {flow} />

    {:else if flow.state.step === 'updated-did-doc'}
      <DidDocStep {flow} type="updated" onConfirm={() => flow?.activateAccount()} />

    {:else if isPasskey && flow.state.step === 'activating'}
      <div class="loading">
        <p>{$_('registerPasskey.activatingAccount')}</p>
      </div>

    {:else if !isPasskey && flow.state.step === 'redirect-to-dashboard'}
      <div class="loading">
        <p>{$_('register.redirecting')}</p>
      </div>
    {/if}
  {/if}
</div>
