<script lang="ts">
  import { onMount } from 'svelte'
  import { _ } from '../lib/i18n'
  import { toast } from '../lib/toast.svelte'
  import SsoIcon from '../components/SsoIcon.svelte'

  interface PendingRegistration {
    request_uri: string
    provider: string
    provider_user_id: string
    provider_username: string | null
    provider_email: string | null
    provider_email_verified: boolean
  }

  interface CommsChannelConfig {
    email: boolean
    discord: boolean
    telegram: boolean
    signal: boolean
  }

  interface RegistrationResult {
    did: string
    handle: string
    redirectUrl: string
    accessJwt?: string
    refreshJwt?: string
    appPassword?: string
    appPasswordName?: string
  }

  let pending = $state<PendingRegistration | null>(null)
  let loading = $state(true)
  let submitting = $state(false)
  let error = $state<string | null>(null)

  let handle = $state('')
  let email = $state('')
  let providerEmailOriginal = $state<string | null>(null)
  let inviteCode = $state('')
  let verificationChannel = $state('email')
  let discordUsername = $state('')
  let telegramUsername = $state('')
  let signalUsername = $state('')

  let handleAvailable = $state<boolean | null>(null)
  let checkingHandle = $state(false)
  let handleError = $state<string | null>(null)

  let didType = $state<'plc' | 'web' | 'web-external'>('plc')
  let externalDid = $state('')

  let serverInfo = $state<{
    availableUserDomains: string[]
    inviteCodeRequired: boolean
    selfHostedDidWebEnabled: boolean
  } | null>(null)

  let commsChannels = $state<CommsChannelConfig>({
    email: true,
    discord: false,
    telegram: false,
    signal: false,
  })

  let showAppPassword = $state(false)
  let registrationResult = $state<RegistrationResult | null>(null)
  let appPasswordCopied = $state(false)
  let appPasswordAcknowledged = $state(false)

  function getToken(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('token')
  }

  function getProviderDisplayName(provider: string): string {
    const names: Record<string, string> = {
      github: 'GitHub',
      discord: 'Discord',
      google: 'Google',
      gitlab: 'GitLab',
      oidc: 'SSO',
    }
    return names[provider] || provider
  }

  function isChannelAvailable(ch: string): boolean {
    return commsChannels[ch as keyof CommsChannelConfig] ?? false
  }

  function extractDomain(did: string): string {
    return did.replace('did:web:', '').replace(/%3A/g, ':')
  }

  let fullHandle = $derived(() => {
    if (!handle.trim()) return ''
    const domain = serverInfo?.availableUserDomains?.[0]
    return domain ? `${handle.trim()}.${domain}` : handle.trim()
  })

  onMount(() => {
    loadPendingRegistration()
    loadServerInfo()
  })

  async function loadServerInfo() {
    try {
      const response = await fetch('/xrpc/com.atproto.server.describeServer')
      if (response.ok) {
        const data = await response.json()
        serverInfo = {
          availableUserDomains: data.availableUserDomains || [],
          inviteCodeRequired: data.inviteCodeRequired ?? false,
          selfHostedDidWebEnabled: data.selfHostedDidWebEnabled ?? false,
        }
        const available: string[] = data.availableCommsChannels ?? ['email']
        commsChannels = {
          email: available.includes('email'),
          discord: available.includes('discord'),
          telegram: available.includes('telegram'),
          signal: available.includes('signal'),
        }
      }
    } catch {
      serverInfo = null
    }
  }

  async function loadPendingRegistration() {
    const token = getToken()
    if (!token) {
      error = $_('sso_register.error_expired')
      loading = false
      return
    }

    try {
      const response = await fetch(`/oauth/sso/pending-registration?token=${encodeURIComponent(token)}`)
      if (!response.ok) {
        const data = await response.json()
        error = data.message || $_('sso_register.error_expired')
        loading = false
        return
      }

      pending = await response.json()
      if (pending?.provider_email) {
        email = pending.provider_email
        providerEmailOriginal = pending.provider_email
      }
      if (pending?.provider_username) {
        handle = pending.provider_username.toLowerCase().replace(/[^a-z0-9-]/g, '')
      }
    } catch {
      error = $_('sso_register.error_expired')
    } finally {
      loading = false
    }
  }

  let checkHandleTimeout: ReturnType<typeof setTimeout> | null = null

  $effect(() => {
    if (checkHandleTimeout) {
      clearTimeout(checkHandleTimeout)
    }
    handleAvailable = null
    handleError = null
    if (handle.length >= 3) {
      checkHandleTimeout = setTimeout(() => checkHandleAvailability(), 400)
    }
  })

  async function checkHandleAvailability() {
    if (!handle || handle.length < 3) return

    checkingHandle = true
    handleError = null

    try {
      const response = await fetch(`/oauth/sso/check-handle-available?handle=${encodeURIComponent(handle)}`)
      const data = await response.json()
      handleAvailable = data.available
      if (!data.available && data.reason) {
        handleError = data.reason
      }
    } catch {
      handleAvailable = null
      handleError = $_('common.error')
    } finally {
      checkingHandle = false
    }
  }

  let usingVerifiedProviderEmail = $derived(
    pending?.provider_email_verified &&
    verificationChannel === 'email' &&
    email.trim().toLowerCase() === providerEmailOriginal?.toLowerCase()
  )

  function isChannelValid(): boolean {
    switch (verificationChannel) {
      case 'email':
        return !!email.trim()
      case 'discord':
        return !!discordUsername.trim()
      case 'telegram':
        return !!telegramUsername.trim()
      case 'signal':
        return !!signalUsername.trim()
      default:
        return false
    }
  }

  function copyAppPassword() {
    if (registrationResult?.appPassword) {
      navigator.clipboard.writeText(registrationResult.appPassword)
      appPasswordCopied = true
    }
  }

  function proceedFromAppPassword() {
    if (!registrationResult) return

    if (registrationResult.accessJwt && registrationResult.refreshJwt) {
      localStorage.setItem('accessJwt', registrationResult.accessJwt)
      localStorage.setItem('refreshJwt', registrationResult.refreshJwt)
    }

    if (registrationResult.redirectUrl) {
      if (registrationResult.redirectUrl.startsWith('/app/verify')) {
        localStorage.setItem('tranquil_pds_pending_verification', JSON.stringify({
          did: registrationResult.did,
          handle: registrationResult.handle,
          channel: verificationChannel,
        }))
        const url = new URL(registrationResult.redirectUrl, window.location.origin)
        url.searchParams.set('handle', registrationResult.handle)
        url.searchParams.set('channel', verificationChannel)
        window.location.href = url.pathname + url.search
        return
      }
      window.location.href = registrationResult.redirectUrl
    }
  }

  async function handleSubmit(e: Event) {
    e.preventDefault()
    const token = getToken()
    if (!token || !pending) return

    if (!handle || handle.length < 3) {
      handleError = $_('sso_register.error_handle_required')
      return
    }

    if (handleAvailable === false) {
      handleError = $_('sso_register.handle_taken')
      return
    }

    if (!isChannelValid()) {
      toast.error($_(`register.validation.${verificationChannel === 'email' ? 'emailRequired' : verificationChannel + 'Required'}`))
      return
    }

    submitting = true

    try {
      const response = await fetch('/oauth/sso/complete-registration', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          token,
          handle,
          email: email || null,
          invite_code: inviteCode || null,
          verification_channel: verificationChannel,
          discord_username: discordUsername || null,
          telegram_username: telegramUsername || null,
          signal_username: signalUsername || null,
          did_type: didType,
          did: didType === 'web-external' ? externalDid.trim() : null,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        toast.error(data.message || data.error_description || data.error || $_('common.error'))
        submitting = false
        return
      }

      registrationResult = {
        did: data.did,
        handle: data.handle,
        redirectUrl: data.redirectUrl,
        accessJwt: data.accessJwt,
        refreshJwt: data.refreshJwt,
        appPassword: data.appPassword,
        appPasswordName: data.appPasswordName,
      }

      if (registrationResult.appPassword) {
        showAppPassword = true
        submitting = false
      } else {
        proceedFromAppPassword()
      }
    } catch (err) {
      console.error('SSO registration failed:', err)
      toast.error(err instanceof Error ? err.message : $_('common.error'))
      submitting = false
    }
  }
</script>

<div class="page">
  {#if loading}
    <div class="loading">
      <div class="spinner md"></div>
      <p>{$_('common.loading')}</p>
    </div>
  {:else if error && !pending}
    <div class="error-container">
      <div class="error-icon">!</div>
      <h2>{$_('common.error')}</h2>
      <p>{error}</p>
      <a href="/app/oauth/register-sso" class="back-link">{$_('sso_register.tryAgain')}</a>
    </div>
  {:else if showAppPassword && registrationResult}
    <header class="page-header">
      <h1>{$_('appPasswords.created')}</h1>
      <p class="subtitle">{$_('appPasswords.createdMessage')}</p>
    </header>

    <div class="app-password-step">
      <div class="warning-box">
        <strong>{$_('appPasswords.saveWarningTitle')}</strong>
        <p>{$_('appPasswords.saveWarningMessage')}</p>
      </div>

      <div class="app-password-display">
        <div class="app-password-label">
          App Password for: <strong>{registrationResult.appPasswordName}</strong>
        </div>
        <code class="app-password-code">{registrationResult.appPassword}</code>
        <button type="button" class="copy-btn" onclick={copyAppPassword}>
          {appPasswordCopied ? $_('common.copied') : $_('common.copyToClipboard')}
        </button>
      </div>

      <div class="field">
        <label class="checkbox-label">
          <input type="checkbox" bind:checked={appPasswordAcknowledged} />
          <span>{$_('appPasswords.acknowledgeLabel')}</span>
        </label>
      </div>

      <button onclick={proceedFromAppPassword} disabled={!appPasswordAcknowledged}>
        {$_('common.continue')}
      </button>
    </div>
  {:else if pending}
    <header class="page-header">
      <h1>{$_('sso_register.title')}</h1>
      <p class="subtitle">{$_('sso_register.subtitle', { values: { provider: getProviderDisplayName(pending.provider) } })}</p>
    </header>

    <div class="provider-info">
      <div class="provider-badge">
        <SsoIcon provider={pending.provider} size={32} />
        <div class="provider-details">
          <span class="provider-name">{getProviderDisplayName(pending.provider)}</span>
          {#if pending.provider_username}
            <span class="provider-username">@{pending.provider_username}</span>
          {/if}
        </div>
      </div>
    </div>

    <div class="split-layout sidebar-right">
      <div class="form-section">
        <form onsubmit={handleSubmit}>
          <div class="field">
            <label for="handle">{$_('sso_register.handle_label')}</label>
            <input
              id="handle"
              type="text"
              bind:value={handle}
              placeholder={$_('register.handlePlaceholder')}
              disabled={submitting}
              required
              autocomplete="off"
            />
            {#if checkingHandle}
              <p class="hint">{$_('common.checking')}</p>
            {:else if handleError}
              <p class="hint error">{handleError}</p>
            {:else if handleAvailable === false}
              <p class="hint error">{$_('sso_register.handle_taken')}</p>
            {:else if handleAvailable === true}
              <p class="hint success">{$_('sso_register.handle_available')}</p>
            {:else if fullHandle()}
              <p class="hint">{$_('register.handleHint', { values: { handle: fullHandle() } })}</p>
            {/if}
          </div>

          <fieldset>
            <legend>{$_('register.contactMethod')}</legend>
            <div class="contact-fields">
              <div class="field">
                <label for="verification-channel">{$_('register.verificationMethod')}</label>
                <select id="verification-channel" bind:value={verificationChannel} disabled={submitting}>
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

              {#if verificationChannel === 'email'}
                <div class="field">
                  <label for="email">{$_('register.emailAddress')}</label>
                  <input
                    id="email"
                    type="email"
                    bind:value={email}
                    placeholder={$_('register.emailPlaceholder')}
                    disabled={submitting}
                    required
                  />
                  {#if pending?.provider_email && pending?.provider_email_verified}
                    {#if usingVerifiedProviderEmail}
                      <p class="hint success">{$_('sso_register.emailVerifiedByProvider', { values: { provider: getProviderDisplayName(pending.provider) } })}</p>
                    {:else}
                      <p class="hint">{$_('sso_register.emailChangedNeedsVerification')}</p>
                    {/if}
                  {/if}
                </div>
              {:else if verificationChannel === 'discord'}
                <div class="field">
                  <label for="discord-username">{$_('register.discordUsername')}</label>
                  <input
                    id="discord-username"
                    type="text"
                    bind:value={discordUsername}
                    placeholder={$_('register.discordUsernamePlaceholder')}
                    disabled={submitting}
                    required
                  />
                </div>
              {:else if verificationChannel === 'telegram'}
                <div class="field">
                  <label for="telegram-username">{$_('register.telegramUsername')}</label>
                  <input
                    id="telegram-username"
                    type="text"
                    bind:value={telegramUsername}
                    placeholder={$_('register.telegramUsernamePlaceholder')}
                    disabled={submitting}
                    required
                  />
                </div>
              {:else if verificationChannel === 'signal'}
                <div class="field">
                  <label for="signal-number">{$_('register.signalUsername')}</label>
                  <input
                    id="signal-number"
                    type="tel"
                    bind:value={signalUsername}
                    placeholder={$_('register.signalUsernamePlaceholder')}
                    disabled={submitting}
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
                <input type="radio" name="didType" value="plc" bind:group={didType} disabled={submitting} />
                <span class="radio-content">
                  <strong>{$_('registerPasskey.didPlcRecommended')}</strong>
                  <span class="radio-hint">{$_('registerPasskey.didPlcHint')}</span>
                </span>
              </label>
              <label class="radio-label" class:disabled={serverInfo?.selfHostedDidWebEnabled === false}>
                <input type="radio" name="didType" value="web" bind:group={didType} disabled={submitting || serverInfo?.selfHostedDidWebEnabled === false} />
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
                <input type="radio" name="didType" value="web-external" bind:group={didType} disabled={submitting} />
                <span class="radio-content">
                  <strong>{$_('registerPasskey.didWebBYOD')}</strong>
                  <span class="radio-hint">{$_('registerPasskey.didWebBYODHint')}</span>
                </span>
              </label>
            </div>
            {#if didType === 'web'}
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
            {#if didType === 'web-external'}
              <div class="field">
                <label for="external-did">{$_('registerPasskey.externalDid')}</label>
                <input id="external-did" type="text" bind:value={externalDid} placeholder={$_('registerPasskey.externalDidPlaceholder')} disabled={submitting} required />
                <p class="hint">{$_('registerPasskey.externalDidHint')} <code>https://{externalDid ? extractDomain(externalDid) : 'yourdomain.com'}/.well-known/did.json</code></p>
              </div>
            {/if}
          </fieldset>

          {#if serverInfo?.inviteCodeRequired}
            <div class="field">
              <label for="invite-code">{$_('register.inviteCode')} <span class="required">{$_('register.inviteCodeRequired')}</span></label>
              <input
                id="invite-code"
                type="text"
                bind:value={inviteCode}
                placeholder={$_('register.inviteCodePlaceholder')}
                disabled={submitting}
                required
              />
            </div>
          {/if}

          <button type="submit" disabled={submitting || !handle || handle.length < 3 || handleAvailable === false || checkingHandle || !isChannelValid()}>
            {submitting ? $_('common.creating') : $_('sso_register.submit')}
          </button>
        </form>
      </div>

      <aside class="info-panel">
        <h3>{$_('sso_register.infoAfterTitle')}</h3>
        <ul class="info-list">
          <li>{$_('sso_register.infoAddPassword')}</li>
          <li>{$_('sso_register.infoAddPasskey')}</li>
          <li>{$_('sso_register.infoLinkProviders')}</li>
          <li>{$_('sso_register.infoChangeHandle')}</li>
        </ul>
      </aside>
    </div>
  {/if}
</div>

<style>
  form {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }

  .provider-info {
    margin-bottom: var(--space-6);
  }

  button[type="submit"] {
    margin-top: var(--space-3);
  }
</style>
