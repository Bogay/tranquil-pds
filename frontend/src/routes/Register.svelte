<script lang="ts">
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import {
    createRegistrationFlow,
    VerificationStep,
    KeyChoiceStep,
    DidDocStep,
  } from '../lib/registration'

  let serverInfo = $state<{
    availableUserDomains: string[]
    inviteCodeRequired: boolean
    availableCommsChannels?: string[]
  } | null>(null)
  let loadingServerInfo = $state(true)
  let serverInfoLoaded = false

  let flow = $state<ReturnType<typeof createRegistrationFlow> | null>(null)
  let confirmPassword = $state('')

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
      flow = createRegistrationFlow('password', hostname)
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
      case 'info': return $_('register.subtitle')
      case 'key-choice': return 'Choose how to set up your external did:web identity.'
      case 'initial-did-doc': return 'Upload your DID document to continue.'
      case 'creating': return $_('register.creating')
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

  <h1>{$_('register.title')}</h1>
  <p class="subtitle">{getSubtitle()}</p>

  {#if flow?.state.error}
    <div class="message error">{flow.state.error}</div>
  {/if}

  {#if loadingServerInfo || !flow}
    <p class="loading">{$_('common.loading')}</p>

  {:else if flow.state.step === 'info'}
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

      <fieldset class="section-fieldset">
        <legend>{$_('register.identityType')}</legend>
        <p class="section-hint">{$_('register.identityHint')}</p>

        <div class="radio-group">
          <label class="radio-label">
            <input type="radio" name="didType" value="plc" bind:group={flow.info.didType} disabled={flow.state.submitting} />
            <span class="radio-content">
              <strong>{$_('register.didPlc')}</strong> {$_('register.didPlcRecommended')}
              <span class="radio-hint">{$_('register.didPlcHint')}</span>
            </span>
          </label>

          <label class="radio-label">
            <input type="radio" name="didType" value="web" bind:group={flow.info.didType} disabled={flow.state.submitting} />
            <span class="radio-content">
              <strong>{$_('register.didWeb')}</strong>
              <span class="radio-hint">{$_('register.didWebHint')}</span>
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
        <p class="section-hint">{$_('register.contactMethodHint')}</p>

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
              placeholder={$_('register.emailPlaceholder')}
              disabled={flow.state.submitting}
              required
            />
          </div>
        {:else if flow.info.verificationChannel === 'discord'}
          <div class="field">
            <label for="discord-id">{$_('register.discordId')}</label>
            <input
              id="discord-id"
              type="text"
              bind:value={flow.info.discordId}
              placeholder={$_('register.discordIdPlaceholder')}
              disabled={flow.state.submitting}
              required
            />
            <p class="hint">{$_('register.discordIdHint')}</p>
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
            <label for="signal-number">{$_('register.signalNumber')}</label>
            <input
              id="signal-number"
              type="tel"
              bind:value={flow.info.signalNumber}
              placeholder={$_('register.signalNumberPlaceholder')}
              disabled={flow.state.submitting}
              required
            />
            <p class="hint">{$_('register.signalNumberHint')}</p>
          </div>
        {/if}
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
        {flow.state.submitting ? $_('register.creating') : $_('register.createButton')}
      </button>
    </form>

    <p class="link-text">
      {$_('register.alreadyHaveAccount')} <a href="#/login">{$_('register.signIn')}</a>
    </p>
    <p class="link-text">
      {$_('register.wantPasswordless')} <a href="#/register-passkey">{$_('register.createPasskeyAccount')}</a>
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
    {#await flow.createPasswordAccount()}
      <p class="loading">{$_('register.creating')}</p>
    {/await}

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

  form {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
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

  button[type="submit"] {
    margin-top: var(--space-3);
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
