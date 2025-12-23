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
    if (!info.handle.trim()) return 'Handle is required'
    if (info.handle.includes('.')) return 'Handle cannot contain dots. You can set up a custom domain handle after creating your account.'
    if (serverInfo?.inviteCodeRequired && !info.inviteCode?.trim()) {
      return 'Invite code is required'
    }
    if (info.didType === 'web-external') {
      if (!info.externalDid?.trim()) return 'External did:web is required'
      if (!info.externalDid.trim().startsWith('did:web:')) return 'External DID must start with did:web:'
    }
    switch (info.verificationChannel) {
      case 'email':
        if (!info.email.trim()) return 'Email is required for email verification'
        break
      case 'discord':
        if (!info.discordId?.trim()) return 'Discord ID is required for Discord verification'
        break
      case 'telegram':
        if (!info.telegramUsername?.trim()) return 'Telegram username is required for Telegram verification'
        break
      case 'signal':
        if (!info.signalNumber?.trim()) return 'Phone number is required for Signal verification'
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
      flow.setError('Passkeys are not supported in this browser. Please use a different browser or register with a password instead.')
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
        flow.setError('Passkey creation was cancelled')
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
        flow.setError('Passkey creation was cancelled')
      } else if (err instanceof ApiError) {
        flow.setError(err.message || 'Passkey registration failed')
      } else if (err instanceof Error) {
        flow.setError(err.message || 'Passkey registration failed')
      } else {
        flow.setError('Passkey registration failed')
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
      case 'email': return 'Email'
      case 'discord': return 'Discord'
      case 'telegram': return 'Telegram'
      case 'signal': return 'Signal'
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
      case 'info': return 'Create an ultra-secure account using a passkey instead of a password.'
      case 'key-choice': return 'Choose how to set up your external did:web identity.'
      case 'initial-did-doc': return 'Upload your DID document to continue.'
      case 'creating': return 'Creating your account...'
      case 'passkey': return 'Register your passkey to secure your account.'
      case 'app-password': return 'Save your app password for third-party apps.'
      case 'verify': return `Verify your ${channelLabel(flow.info.verificationChannel)} to continue.`
      case 'updated-did-doc': return 'Update your DID document with the PDS signing key.'
      case 'activating': return 'Activating your account...'
      case 'complete': return 'Your account has been created successfully!'
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

  <h1>Create Passkey Account</h1>
  <p class="subtitle">{getSubtitle()}</p>

  {#if flow?.state.error}
    <div class="message error">{flow.state.error}</div>
  {/if}

  {#if loadingServerInfo || !flow}
    <p class="loading">Loading...</p>

  {:else if flow.state.step === 'info'}
    <form onsubmit={handleInfoSubmit}>
      <div class="field">
        <label for="handle">Handle</label>
        <input
          id="handle"
          type="text"
          bind:value={flow.info.handle}
          placeholder="yourname"
          disabled={flow.state.submitting}
          required
        />
        {#if flow.info.handle.includes('.')}
          <p class="hint warning">Custom domain handles can be set up after account creation.</p>
        {:else if fullHandle()}
          <p class="hint">Your full handle will be: @{fullHandle()}</p>
        {/if}
      </div>

      <fieldset class="section-fieldset">
        <legend>Contact Method</legend>
        <p class="section-hint">Choose how you'd like to verify your account and receive notifications.</p>
        <div class="field">
          <label for="verification-channel">Verification Method</label>
          <select id="verification-channel" bind:value={flow.info.verificationChannel} disabled={flow.state.submitting}>
            <option value="email">Email</option>
            <option value="discord" disabled={!isChannelAvailable('discord')}>
              Discord{isChannelAvailable('discord') ? '' : ` (${$_('register.notConfigured')})`}
            </option>
            <option value="telegram" disabled={!isChannelAvailable('telegram')}>
              Telegram{isChannelAvailable('telegram') ? '' : ` (${$_('register.notConfigured')})`}
            </option>
            <option value="signal" disabled={!isChannelAvailable('signal')}>
              Signal{isChannelAvailable('signal') ? '' : ` (${$_('register.notConfigured')})`}
            </option>
          </select>
        </div>
        {#if flow.info.verificationChannel === 'email'}
          <div class="field">
            <label for="email">Email Address</label>
            <input id="email" type="email" bind:value={flow.info.email} placeholder="you@example.com" disabled={flow.state.submitting} required />
          </div>
        {:else if flow.info.verificationChannel === 'discord'}
          <div class="field">
            <label for="discord-id">Discord User ID</label>
            <input id="discord-id" type="text" bind:value={flow.info.discordId} placeholder="Your Discord user ID" disabled={flow.state.submitting} required />
            <p class="hint">Your numeric Discord user ID (enable Developer Mode to find it)</p>
          </div>
        {:else if flow.info.verificationChannel === 'telegram'}
          <div class="field">
            <label for="telegram-username">Telegram Username</label>
            <input id="telegram-username" type="text" bind:value={flow.info.telegramUsername} placeholder="@yourusername" disabled={flow.state.submitting} required />
          </div>
        {:else if flow.info.verificationChannel === 'signal'}
          <div class="field">
            <label for="signal-number">Signal Phone Number</label>
            <input id="signal-number" type="tel" bind:value={flow.info.signalNumber} placeholder="+1234567890" disabled={flow.state.submitting} required />
            <p class="hint">Include country code (e.g., +1 for US)</p>
          </div>
        {/if}
      </fieldset>

      <fieldset class="section-fieldset">
        <legend>Identity Type</legend>
        <p class="section-hint">Choose how your decentralized identity will be managed.</p>
        <div class="radio-group">
          <label class="radio-label">
            <input type="radio" name="didType" value="plc" bind:group={flow.info.didType} disabled={flow.state.submitting} />
            <span class="radio-content">
              <strong>did:plc</strong> (Recommended)
              <span class="radio-hint">Portable identity managed by PLC Directory</span>
            </span>
          </label>
          <label class="radio-label">
            <input type="radio" name="didType" value="web" bind:group={flow.info.didType} disabled={flow.state.submitting} />
            <span class="radio-content">
              <strong>did:web</strong>
              <span class="radio-hint">Identity hosted on this PDS (read warning below)</span>
            </span>
          </label>
          <label class="radio-label">
            <input type="radio" name="didType" value="web-external" bind:group={flow.info.didType} disabled={flow.state.submitting} />
            <span class="radio-content">
              <strong>did:web (BYOD)</strong>
              <span class="radio-hint">Bring your own domain</span>
            </span>
          </label>
        </div>
        {#if flow.info.didType === 'web'}
          <div class="warning-box">
            <strong>Important: Understand the trade-offs</strong>
            <ul>
              <li><strong>Permanent tie to this PDS:</strong> Your identity will be <code>did:web:yourhandle.{serverInfo?.availableUserDomains?.[0] || 'this-pds.com'}</code>.</li>
              <li><strong>No recovery mechanism:</strong> Unlike did:plc, did:web has no rotation keys.</li>
              <li><strong>We commit to you:</strong> If you migrate away, we will continue serving a minimal DID document.</li>
              <li><strong>Recommendation:</strong> Choose did:plc unless you have a specific reason to prefer did:web.</li>
            </ul>
          </div>
        {/if}
        {#if flow.info.didType === 'web-external'}
          <div class="field">
            <label for="external-did">Your did:web</label>
            <input id="external-did" type="text" bind:value={flow.info.externalDid} placeholder="did:web:yourdomain.com" disabled={flow.state.submitting} required />
            <p class="hint">You'll need to serve a DID document at <code>https://{flow.info.externalDid ? extractDomain(flow.info.externalDid) : 'yourdomain.com'}/.well-known/did.json</code></p>
          </div>
        {/if}
      </fieldset>

      {#if serverInfo?.inviteCodeRequired}
        <div class="field">
          <label for="invite-code">Invite Code <span class="required">*</span></label>
          <input id="invite-code" type="text" bind:value={flow.info.inviteCode} placeholder="Enter your invite code" disabled={flow.state.submitting} required />
        </div>
      {/if}

      <div class="info-box">
        <strong>Why passkey-only?</strong>
        <p>Passkey accounts are more secure than password-based accounts because they:</p>
        <ul>
          <li>Cannot be phished or stolen in data breaches</li>
          <li>Use hardware-backed cryptographic keys</li>
          <li>Require your biometric or device PIN to use</li>
        </ul>
      </div>

      <button type="submit" disabled={flow.state.submitting}>
        {flow.state.submitting ? 'Creating account...' : 'Continue'}
      </button>
    </form>

    <p class="link-text">
      Want a traditional password? <a href="#/register">Register with password</a>
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
    {#await flow.createPasskeyAccount()}
      <p class="loading">Creating your account...</p>
    {/await}

  {:else if flow.state.step === 'passkey'}
    <div class="step-content">
      <div class="field">
        <label for="passkey-name">Passkey Name (optional)</label>
        <input id="passkey-name" type="text" bind:value={passkeyName} placeholder="e.g., MacBook Touch ID" disabled={flow.state.submitting} />
        <p class="hint">A friendly name to identify this passkey</p>
      </div>

      <div class="info-box">
        <p>Click the button below to create your passkey. You'll be prompted to use:</p>
        <ul>
          <li>Touch ID or Face ID</li>
          <li>Your device PIN or password</li>
          <li>A security key (if you have one)</li>
        </ul>
      </div>

      <button onclick={handlePasskeyRegistration} disabled={flow.state.submitting} class="passkey-btn">
        {flow.state.submitting ? 'Creating Passkey...' : 'Create Passkey'}
      </button>

      <button type="button" class="secondary" onclick={() => flow?.goBack()} disabled={flow.state.submitting}>
        Back
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
    <p class="loading">Redirecting to dashboard...</p>
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

  .section-fieldset {
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
  }

  .section-fieldset legend {
    font-weight: var(--font-semibold);
    padding: 0 var(--space-3);
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
