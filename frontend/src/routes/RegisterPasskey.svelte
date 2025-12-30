<script lang="ts">
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import {
    createRegistrationFlow,
    VerificationStep,
    KeyChoiceStep,
    DidDocStep,
    AppPasswordStep,
  } from '../lib/registration'

  let serverInfo = $state<{
    availableUserDomains: string[]
    inviteCodeRequired: boolean
    availableCommsChannels?: string[]
    selfHostedDidWebEnabled?: boolean
  } | null>(null)
  let loadingServerInfo = $state(true)
  let serverInfoLoaded = false

  let flow = $state<ReturnType<typeof createRegistrationFlow> | null>(null)
  let passkeyName = $state('')

  $effect(() => {
    if (!serverInfoLoaded) {
      serverInfoLoaded = true
      loadServerInfo()
    }
  })

  $effect(() => {
    if (flow?.state.step === 'redirect-to-dashboard') {
      navigate('/dashboard')
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
      serverInfo = await api.describeServer()
      const hostname = serverInfo?.availableUserDomains?.[0] || window.location.hostname
      flow = createRegistrationFlow('passkey', hostname)
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
        if (!info.discordId?.trim()) return $_('registerPasskey.errors.discordRequired')
        break
      case 'telegram':
        if (!info.telegramUsername?.trim()) return $_('registerPasskey.errors.telegramRequired')
        break
      case 'signal':
        if (!info.signalNumber?.trim()) return $_('registerPasskey.errors.signalRequired')
        break
    }
    return null
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

  function preparePublicKeyOptions(options: any): PublicKeyCredentialCreationOptions {
    return {
      ...options.publicKey,
      challenge: base64UrlToArrayBuffer(options.publicKey.challenge),
      user: {
        ...options.publicKey.user,
        id: base64UrlToArrayBuffer(options.publicKey.user.id)
      },
      excludeCredentials: options.publicKey.excludeCredentials?.map((cred: any) => ({
        ...cred,
        id: base64UrlToArrayBuffer(cred.id)
      })) || []
    }
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

  async function handleCreateAccount() {
    if (!flow) return
    await flow.createPasskeyAccount()
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

      const publicKeyOptions = preparePublicKeyOptions(options)
      const credential = await navigator.credentials.create({
        publicKey: publicKeyOptions
      })

      if (!credential) {
        flow.setError($_('registerPasskey.errors.passkeyCancelled'))
        flow.setSubmitting(false)
        return
      }

      const pkCredential = credential as PublicKeyCredential
      const response = pkCredential.response as AuthenticatorAttestationResponse
      const credentialResponse = {
        id: pkCredential.id,
        type: pkCredential.type,
        rawId: arrayBufferToBase64Url(pkCredential.rawId),
        response: {
          clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
          attestationObject: arrayBufferToBase64Url(response.attestationObject),
        },
      }

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
      } else if (err instanceof ApiError) {
        flow.setError(err.message || $_('registerPasskey.errors.passkeyFailed'))
      } else if (err instanceof Error) {
        flow.setError(err.message || $_('registerPasskey.errors.passkeyFailed'))
      } else {
        flow.setError($_('registerPasskey.errors.passkeyFailed'))
      }
    } finally {
      flow.setSubmitting(false)
    }
  }

  async function handleComplete() {
    if (flow) {
      await flow.finalizeSession()
    }
    navigate('/dashboard')
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
      case 'info': return $_('registerPasskey.subtitle')
      case 'key-choice': return $_('registerPasskey.subtitleKeyChoice')
      case 'initial-did-doc': return $_('registerPasskey.subtitleInitialDidDoc')
      case 'creating': return $_('registerPasskey.subtitleCreating')
      case 'passkey': return $_('registerPasskey.subtitlePasskey')
      case 'app-password': return $_('registerPasskey.subtitleAppPassword')
      case 'verify': return $_('registerPasskey.subtitleVerify', { values: { channel: channelLabel(flow.info.verificationChannel) } })
      case 'updated-did-doc': return $_('registerPasskey.subtitleUpdatedDidDoc')
      case 'activating': return $_('registerPasskey.subtitleActivating')
      case 'redirect-to-dashboard': return $_('registerPasskey.subtitleComplete')
      default: return ''
    }
  }
</script>

<div class="register-page">
  {#if flow?.state.step === 'info'}
    <div class="migrate-callout">
      <div class="migrate-icon">↗</div>
      <div class="migrate-content">
        <strong>{$_('register.migrateTitle')}</strong>
        <p>{$_('register.migrateDescription')}</p>
        <a href="https://pdsmoover.com/moover" target="_blank" rel="noopener" class="migrate-link">
          {$_('register.migrateLink')} →
        </a>
      </div>
    </div>
  {/if}

  <h1>{$_('registerPasskey.title')}</h1>
  <p class="subtitle">{getSubtitle()}</p>

  {#if flow?.state.error}
    <div class="message error">{flow.state.error}</div>
  {/if}

  {#if loadingServerInfo || !flow}
    <p class="loading">{$_('registerPasskey.loading')}</p>

  {:else if flow.state.step === 'info'}
    <form onsubmit={handleInfoSubmit}>
      <div class="field">
        <label for="handle">{$_('registerPasskey.handle')}</label>
        <input
          id="handle"
          type="text"
          bind:value={flow.info.handle}
          placeholder={$_('registerPasskey.handlePlaceholder')}
          disabled={flow.state.submitting}
          required
        />
        {#if flow.info.handle.includes('.')}
          <p class="hint warning">{$_('registerPasskey.handleDotWarning')}</p>
        {:else if fullHandle()}
          <p class="hint">{$_('registerPasskey.handleHint', { values: { handle: fullHandle() } })}</p>
        {/if}
      </div>

      <fieldset class="section-fieldset">
        <legend>{$_('registerPasskey.contactMethod')}</legend>
        <p class="section-hint">{$_('registerPasskey.contactMethodHint')}</p>
        <div class="field">
          <label for="verification-channel">{$_('registerPasskey.verificationMethod')}</label>
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
            <label for="email">{$_('registerPasskey.email')}</label>
            <input id="email" type="email" bind:value={flow.info.email} placeholder={$_('registerPasskey.emailPlaceholder')} disabled={flow.state.submitting} required />
          </div>
        {:else if flow.info.verificationChannel === 'discord'}
          <div class="field">
            <label for="discord-id">{$_('register.discordId')}</label>
            <input id="discord-id" type="text" bind:value={flow.info.discordId} placeholder={$_('register.discordIdPlaceholder')} disabled={flow.state.submitting} required />
            <p class="hint">{$_('register.discordIdHint')}</p>
          </div>
        {:else if flow.info.verificationChannel === 'telegram'}
          <div class="field">
            <label for="telegram-username">{$_('register.telegramUsername')}</label>
            <input id="telegram-username" type="text" bind:value={flow.info.telegramUsername} placeholder={$_('register.telegramUsernamePlaceholder')} disabled={flow.state.submitting} required />
          </div>
        {:else if flow.info.verificationChannel === 'signal'}
          <div class="field">
            <label for="signal-number">{$_('register.signalNumber')}</label>
            <input id="signal-number" type="tel" bind:value={flow.info.signalNumber} placeholder={$_('register.signalNumberPlaceholder')} disabled={flow.state.submitting} required />
            <p class="hint">{$_('register.signalNumberHint')}</p>
          </div>
        {/if}
      </fieldset>

      <fieldset class="section-fieldset">
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
            <p class="hint">{$_('registerPasskey.externalDidHint')} <code>https://{flow.info.externalDid ? extractDomain(flow.info.externalDid) : 'yourdomain.com'}/.well-known/did.json</code></p>
          </div>
        {/if}
      </fieldset>

      {#if serverInfo?.inviteCodeRequired}
        <div class="field">
          <label for="invite-code">{$_('registerPasskey.inviteCode')} <span class="required">*</span></label>
          <input id="invite-code" type="text" bind:value={flow.info.inviteCode} placeholder={$_('registerPasskey.inviteCodePlaceholder')} disabled={flow.state.submitting} required />
        </div>
      {/if}

      <div class="info-box">
        <strong>{$_('registerPasskey.whyPasskeyOnly')}</strong>
        <p>{$_('registerPasskey.whyPasskeyOnlyDesc')}</p>
        <ul>
          <li>{$_('registerPasskey.whyPasskeyBullet1')}</li>
          <li>{$_('registerPasskey.whyPasskeyBullet2')}</li>
          <li>{$_('registerPasskey.whyPasskeyBullet3')}</li>
        </ul>
      </div>

      <button type="submit" disabled={flow.state.submitting}>
        {flow.state.submitting ? $_('registerPasskey.creating') : $_('registerPasskey.continue')}
      </button>
    </form>

    <p class="link-text">
      {$_('registerPasskey.wantTraditional')} <a href="#/register">{$_('registerPasskey.registerWithPassword')}</a>
    </p>

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
    <p class="loading">{$_('registerPasskey.subtitleCreating')}</p>

  {:else if flow.state.step === 'passkey'}
    <div class="step-content">
      <div class="field">
        <label for="passkey-name">{$_('registerPasskey.passkeyNameLabel')}</label>
        <input id="passkey-name" type="text" bind:value={passkeyName} placeholder={$_('registerPasskey.passkeyNamePlaceholder')} disabled={flow.state.submitting} />
        <p class="hint">{$_('registerPasskey.passkeyNameHint')}</p>
      </div>

      <div class="info-box">
        <p>{$_('registerPasskey.passkeyPrompt')}</p>
        <ul>
          <li>{$_('registerPasskey.passkeyPromptBullet1')}</li>
          <li>{$_('registerPasskey.passkeyPromptBullet2')}</li>
          <li>{$_('registerPasskey.passkeyPromptBullet3')}</li>
        </ul>
      </div>

      <button onclick={handlePasskeyRegistration} disabled={flow.state.submitting} class="passkey-btn">
        {flow.state.submitting ? $_('registerPasskey.creatingPasskey') : $_('registerPasskey.createPasskey')}
      </button>

      <button type="button" class="secondary" onclick={() => flow?.goBack()} disabled={flow.state.submitting}>
        {$_('registerPasskey.back')}
      </button>
    </div>

  {:else if flow.state.step === 'app-password'}
    <AppPasswordStep {flow} />

  {:else if flow.state.step === 'verify'}
    <VerificationStep {flow} />

  {:else if flow.state.step === 'updated-did-doc'}
    <DidDocStep
      {flow}
      type="updated"
      onConfirm={() => flow?.activateAccount()}
    />

  {:else if flow.state.step === 'redirect-to-dashboard'}
    <p class="loading">{$_('registerPasskey.redirecting')}</p>
  {/if}
</div>

<style>
  .register-page {
    max-width: var(--width-sm);
    margin: var(--space-9) auto;
    padding: var(--space-7);
  }

  .migrate-callout {
    display: flex;
    gap: var(--space-4);
    padding: var(--space-5);
    background: var(--accent-muted);
    border: 1px solid var(--accent);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-6);
  }

  .migrate-icon {
    font-size: var(--text-2xl);
    line-height: 1;
    color: var(--accent);
  }

  .migrate-content {
    flex: 1;
  }

  .migrate-content strong {
    display: block;
    color: var(--text-primary);
    margin-bottom: var(--space-2);
  }

  .migrate-content p {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-sm);
    color: var(--text-secondary);
    line-height: var(--leading-relaxed);
  }

  .migrate-link {
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
    color: var(--accent);
    text-decoration: none;
  }

  .migrate-link:hover {
    text-decoration: underline;
  }

  h1 {
    margin: 0 0 var(--space-3) 0;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0 0 var(--space-7) 0;
  }

  .loading {
    text-align: center;
    color: var(--text-secondary);
  }

  form, .step-content {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .required {
    color: var(--error-text);
  }

  .section-hint {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin: 0 0 var(--space-5) 0;
  }

  .radio-group {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .radio-label {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    cursor: pointer;
    font-size: var(--text-base);
    font-weight: var(--font-normal);
    margin-bottom: 0;
  }

  .radio-label input[type="radio"] {
    margin-top: var(--space-1);
    width: auto;
  }

  .radio-content {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .radio-hint {
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .radio-label.disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .radio-hint.disabled-hint {
    color: var(--warning-text);
  }

  .warning-box {
    margin-top: var(--space-5);
    padding: var(--space-5);
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius-lg);
    font-size: var(--text-sm);
  }

  .warning-box strong {
    display: block;
    margin-bottom: var(--space-3);
    color: var(--warning-text);
  }

  .warning-box ul {
    margin: var(--space-4) 0 0 0;
    padding-left: var(--space-5);
  }

  .warning-box li {
    margin-bottom: var(--space-3);
    line-height: var(--leading-normal);
  }

  .warning-box li:last-child {
    margin-bottom: 0;
  }

  .info-box {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
    font-size: var(--text-sm);
  }

  .info-box strong {
    display: block;
    margin-bottom: var(--space-3);
  }

  .info-box p {
    margin: 0 0 var(--space-3) 0;
    color: var(--text-secondary);
  }

  .info-box ul {
    margin: 0;
    padding-left: var(--space-5);
    color: var(--text-secondary);
  }

  .info-box li {
    margin-bottom: var(--space-2);
  }

  .passkey-btn {
    padding: var(--space-5);
    font-size: var(--text-lg);
  }

  .link-text {
    text-align: center;
    margin-top: var(--space-6);
    color: var(--text-secondary);
  }

  .link-text a {
    color: var(--accent);
  }
</style>
