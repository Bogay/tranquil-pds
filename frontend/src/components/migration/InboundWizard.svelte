<script lang="ts">
  import type { InboundMigrationFlow } from '../../lib/migration'
  import type { AuthMethod, ServerDescription } from '../../lib/migration/types'
  import { getErrorMessage } from '../../lib/migration/types'
  import { base64UrlEncode, prepareWebAuthnCreationOptions } from '../../lib/migration/atproto-client'
  import { _ } from '../../lib/i18n'
  import '../../styles/migration.css'

  interface ResumeInfo {
    direction: 'inbound' | 'outbound'
    sourceHandle: string
    targetHandle: string
    sourcePdsUrl: string
    targetPdsUrl: string
    targetEmail: string
    authMethod?: AuthMethod
    progressSummary: string
    step: string
  }

  interface Props {
    flow: InboundMigrationFlow
    resumeInfo?: ResumeInfo | null
    onBack: () => void
    onComplete: () => void
  }

  let { flow, resumeInfo = null, onBack, onComplete }: Props = $props()

  let serverInfo = $state<ServerDescription | null>(null)
  let loading = $state(false)
  let handleInput = $state('')
  let localPasswordInput = $state('')
  let understood = $state(false)
  let selectedDomain = $state('')
  let handleAvailable = $state<boolean | null>(null)
  let checkingHandle = $state(false)
  let selectedAuthMethod = $state<AuthMethod>('password')
  let passkeyName = $state('')
  let appPasswordCopied = $state(false)
  let appPasswordAcknowledged = $state(false)

  const isResuming = $derived(flow.state.needsReauth === true)
  const isDidWeb = $derived(flow.state.sourceDid.startsWith("did:web:"))

  $effect(() => {
    if (flow.state.step === 'welcome' || flow.state.step === 'choose-handle') {
      loadServerInfo()
    }
    if (flow.state.step === 'choose-handle') {
      handleInput = ''
      handleAvailable = null
    }
    if (flow.state.step === 'source-handle' && resumeInfo) {
      handleInput = resumeInfo.sourceHandle
      selectedAuthMethod = resumeInfo.authMethod ?? 'password'
    }
  })


  let redirectTriggered = $state(false)

  $effect(() => {
    if (flow.state.step === 'success' && !redirectTriggered) {
      redirectTriggered = true
      setTimeout(() => {
        onComplete()
      }, 2000)
    }
  })

  $effect(() => {
    if (flow.state.step === 'email-verify') {
      const interval = setInterval(async () => {
        if (flow.state.emailVerifyToken.trim()) return
        await flow.checkEmailVerifiedAndProceed()
      }, 3000)
      return () => clearInterval(interval)
    }
  })

  async function loadServerInfo() {
    if (!serverInfo) {
      serverInfo = await flow.loadLocalServerInfo()
      if (serverInfo.availableUserDomains.length > 0) {
        selectedDomain = serverInfo.availableUserDomains[0]
      }
    }
  }

  async function checkHandle() {
    if (!handleInput.trim()) return

    const fullHandle = handleInput.includes('.')
      ? handleInput
      : `${handleInput}.${selectedDomain}`

    checkingHandle = true
    handleAvailable = null

    try {
      handleAvailable = await flow.checkHandleAvailability(fullHandle)
    } catch {
      handleAvailable = true
    } finally {
      checkingHandle = false
    }
  }

  function proceedToReview() {
    const fullHandle = handleInput.includes('.')
      ? handleInput
      : `${handleInput}.${selectedDomain}`

    flow.updateField('targetHandle', fullHandle)
    flow.setStep('review')
  }

  async function startMigration() {
    loading = true
    try {
      await flow.startMigration()
    } catch (err) {
      flow.setError(getErrorMessage(err))
    } finally {
      loading = false
    }
  }

  async function submitEmailVerify(e: Event) {
    e.preventDefault()
    loading = true
    try {
      await flow.submitEmailVerifyToken(flow.state.emailVerifyToken, localPasswordInput || undefined)
    } catch (err) {
      flow.setError(getErrorMessage(err))
    } finally {
      loading = false
    }
  }

  async function resendEmailVerify() {
    loading = true
    try {
      await flow.resendEmailVerification()
      flow.setError(null)
    } catch (err) {
      flow.setError(getErrorMessage(err))
    } finally {
      loading = false
    }
  }

  async function submitPlcToken(e: Event) {
    e.preventDefault()
    loading = true
    try {
      await flow.submitPlcToken(flow.state.plcToken)
    } catch (err) {
      flow.setError(getErrorMessage(err))
    } finally {
      loading = false
    }
  }

  async function resendToken() {
    loading = true
    try {
      await flow.resendPlcToken()
      flow.setError(null)
    } catch (err) {
      flow.setError(getErrorMessage(err))
    } finally {
      loading = false
    }
  }

  async function completeDidWeb() {
    loading = true
    try {
      await flow.completeDidWebMigration()
    } catch (err) {
      flow.setError(getErrorMessage(err))
    } finally {
      loading = false
    }
  }

  async function registerPasskey() {
    loading = true
    flow.setError(null)

    try {
      if (!window.PublicKeyCredential) {
        throw new Error('Passkeys are not supported in this browser. Please use a modern browser with WebAuthn support.')
      }

      const { options } = await flow.startPasskeyRegistration()

      const publicKeyOptions = prepareWebAuthnCreationOptions(
        options as { publicKey: Record<string, unknown> }
      )
      const credential = await navigator.credentials.create({
        publicKey: publicKeyOptions,
      })

      if (!credential) {
        throw new Error('Passkey creation was cancelled')
      }

      const publicKeyCredential = credential as PublicKeyCredential
      const response = publicKeyCredential.response as AuthenticatorAttestationResponse

      const credentialData = {
        id: publicKeyCredential.id,
        rawId: base64UrlEncode(publicKeyCredential.rawId),
        type: publicKeyCredential.type,
        response: {
          clientDataJSON: base64UrlEncode(response.clientDataJSON),
          attestationObject: base64UrlEncode(response.attestationObject),
        },
      }

      await flow.completePasskeyRegistration(credentialData, passkeyName || undefined)
    } catch (err) {
      const message = getErrorMessage(err)
      if (message.includes('cancelled') || message.includes('AbortError')) {
        flow.setError('Passkey registration was cancelled. Please try again.')
      } else {
        flow.setError(message)
      }
    } finally {
      loading = false
    }
  }

  function copyAppPassword() {
    if (flow.state.generatedAppPassword) {
      navigator.clipboard.writeText(flow.state.generatedAppPassword)
      appPasswordCopied = true
    }
  }

  async function handleProceedFromAppPassword() {
    loading = true
    try {
      await flow.proceedFromAppPassword()
    } catch (err) {
      flow.setError(getErrorMessage(err))
    } finally {
      loading = false
    }
  }

  async function handleSourceHandleSubmit(e: Event) {
    e.preventDefault()
    loading = true
    flow.updateField('error', null)

    try {
      await flow.initiateOAuthLogin(handleInput)
    } catch (err) {
      flow.setError(getErrorMessage(err))
    } finally {
      loading = false
    }
  }

  function proceedToReviewWithAuth() {
    const fullHandle = handleInput.includes('.')
      ? handleInput
      : `${handleInput}.${selectedDomain}`

    flow.updateField('targetHandle', fullHandle)
    flow.updateField('authMethod', selectedAuthMethod)
    flow.setStep('review')
  }

  const steps = $derived(isDidWeb
    ? ['Authenticate', 'Handle', 'Review', 'Transfer', 'Verify Email', 'Update DID', 'Complete']
    : flow.state.authMethod === 'passkey'
      ? ['Authenticate', 'Handle', 'Review', 'Transfer', 'Verify Email', 'Passkey', 'App Password', 'Verify PLC', 'Complete']
      : ['Authenticate', 'Handle', 'Review', 'Transfer', 'Verify Email', 'Verify PLC', 'Complete'])

  function getCurrentStepIndex(): number {
    const isPasskey = flow.state.authMethod === 'passkey'
    switch (flow.state.step) {
      case 'welcome':
      case 'source-handle': return 0
      case 'choose-handle': return 1
      case 'review': return 2
      case 'migrating': return 3
      case 'email-verify': return 4
      case 'passkey-setup': return isPasskey ? 5 : 4
      case 'app-password': return 6
      case 'plc-token':
      case 'did-web-update':
      case 'finalizing': return isPasskey ? 7 : 5
      case 'success': return isPasskey ? 8 : 6
      default: return 0
    }
  }
</script>

<div class="migration-wizard">
  <div class="step-indicator">
    {#each steps as _, i}
      <div class="step" class:active={i === getCurrentStepIndex()} class:completed={i < getCurrentStepIndex()}>
        <div class="step-dot">{i < getCurrentStepIndex() ? '✓' : i + 1}</div>
      </div>
      {#if i < steps.length - 1}
        <div class="step-line" class:completed={i < getCurrentStepIndex()}></div>
      {/if}
    {/each}
  </div>
  <div class="current-step-label">
    <strong>{steps[getCurrentStepIndex()]}</strong> · Step {getCurrentStepIndex() + 1} of {steps.length}
  </div>

  {#if flow.state.error}
    <div class="message error">{flow.state.error}</div>
  {/if}

  {#if flow.state.step === 'welcome'}
    <div class="step-content">
      <h2>{$_('migration.inbound.welcome.title')}</h2>
      <p>{$_('migration.inbound.welcome.desc')}</p>

      <div class="info-box">
        <h3>{$_('migration.inbound.common.whatWillHappen')}</h3>
        <ol>
          <li>{$_('migration.inbound.common.step1')}</li>
          <li>{$_('migration.inbound.common.step2')}</li>
          <li>{$_('migration.inbound.common.step3')}</li>
          <li>{$_('migration.inbound.common.step4')}</li>
          <li>{$_('migration.inbound.common.step5')}</li>
        </ol>
      </div>

      <div class="warning-box">
        <strong>{$_('migration.inbound.common.beforeProceed')}</strong>
        <ul>
          <li>{$_('migration.inbound.common.warning1')}</li>
          <li>{$_('migration.inbound.common.warning2')}</li>
          <li>{$_('migration.inbound.common.warning3')}</li>
        </ul>
      </div>

      <label class="checkbox-label">
        <input type="checkbox" bind:checked={understood} />
        <span>{$_('migration.inbound.welcome.understand')}</span>
      </label>

      <div class="button-row">
        <button class="ghost" onclick={onBack}>{$_('migration.inbound.common.cancel')}</button>
        <button disabled={!understood} onclick={() => flow.setStep('source-handle')}>
          {$_('migration.inbound.common.continue')}
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'source-handle'}
    <div class="step-content">
      <h2>{isResuming ? $_('migration.inbound.sourceAuth.titleResume') : $_('migration.inbound.sourceAuth.title')}</h2>
      <p>{isResuming ? $_('migration.inbound.sourceAuth.descResume') : $_('migration.inbound.sourceAuth.desc')}</p>

      {#if isResuming && resumeInfo}
        <div class="info-box resume-info">
          <h3>{$_('migration.inbound.sourceAuth.resumeTitle')}</h3>
          <div class="resume-details">
            <div class="resume-row">
              <span class="label">{$_('migration.inbound.sourceAuth.resumeFrom')}:</span>
              <span class="value">@{resumeInfo.sourceHandle}</span>
            </div>
            <div class="resume-row">
              <span class="label">{$_('migration.inbound.sourceAuth.resumeTo')}:</span>
              <span class="value">@{resumeInfo.targetHandle}</span>
            </div>
            <div class="resume-row">
              <span class="label">{$_('migration.inbound.sourceAuth.resumeProgress')}:</span>
              <span class="value">{resumeInfo.progressSummary}</span>
            </div>
          </div>
          <p class="resume-note">{$_('migration.inbound.sourceAuth.resumeOAuthNote')}</p>
        </div>
      {/if}

      <form onsubmit={handleSourceHandleSubmit}>
        <div class="field">
          <label for="source-handle">{$_('migration.inbound.sourceAuth.handle')}</label>
          <input
            id="source-handle"
            type="text"
            placeholder={$_('migration.inbound.sourceAuth.handlePlaceholder')}
            bind:value={handleInput}
            disabled={loading || isResuming}
            required
          />
          <p class="hint">{$_('migration.inbound.sourceAuth.handleHint')}</p>
        </div>

        <div class="button-row">
          <button type="button" class="ghost" onclick={() => flow.setStep('welcome')} disabled={loading}>{$_('migration.inbound.common.back')}</button>
          <button type="submit" disabled={loading || !handleInput.trim()}>
            {loading ? $_('migration.inbound.sourceAuth.connecting') : (isResuming ? $_('migration.inbound.sourceAuth.reauthenticate') : $_('migration.inbound.sourceAuth.continue'))}
          </button>
        </div>
      </form>
    </div>

  {:else if flow.state.step === 'choose-handle'}
    <div class="step-content">
      <h2>{$_('migration.inbound.chooseHandle.title')}</h2>
      <p>{$_('migration.inbound.chooseHandle.desc')}</p>

      <div class="current-info">
        <span class="label">{$_('migration.inbound.chooseHandle.migratingFrom')}:</span>
        <span class="value">{flow.state.sourceHandle}</span>
      </div>

      <div class="field">
        <label for="new-handle">{$_('migration.inbound.chooseHandle.newHandle')}</label>
        <div class="handle-input-group">
          <input
            id="new-handle"
            type="text"
            placeholder="username"
            bind:value={handleInput}
            onblur={checkHandle}
          />
          {#if serverInfo && serverInfo.availableUserDomains.length > 0 && !handleInput.includes('.')}
            <select bind:value={selectedDomain}>
              {#each serverInfo.availableUserDomains as domain}
                <option value={domain}>.{domain}</option>
              {/each}
            </select>
          {/if}
        </div>

        {#if checkingHandle}
          <p class="hint">{$_('migration.inbound.chooseHandle.checkingAvailability')}</p>
        {:else if handleAvailable === true}
          <p class="hint" style="color: var(--success-text)">{$_('migration.inbound.chooseHandle.handleAvailable')}</p>
        {:else if handleAvailable === false}
          <p class="hint error">{$_('migration.inbound.chooseHandle.handleTaken')}</p>
        {:else}
          <p class="hint">{$_('migration.inbound.chooseHandle.handleHint')}</p>
        {/if}
      </div>

      <div class="field">
        <label for="email">{$_('migration.inbound.chooseHandle.email')}</label>
        <input
          id="email"
          type="email"
          placeholder="you@example.com"
          bind:value={flow.state.targetEmail}
          oninput={(e) => flow.updateField('targetEmail', (e.target as HTMLInputElement).value)}
          required
        />
      </div>

      <div class="field">
        <label>{$_('migration.inbound.chooseHandle.authMethod')}</label>
        <div class="auth-method-options">
          <label class="auth-option" class:selected={selectedAuthMethod === 'password'}>
            <input
              type="radio"
              name="auth-method"
              value="password"
              bind:group={selectedAuthMethod}
            />
            <div class="auth-option-content">
              <strong>{$_('migration.inbound.chooseHandle.authPassword')}</strong>
              <span>{$_('migration.inbound.chooseHandle.authPasswordDesc')}</span>
            </div>
          </label>
          <label class="auth-option" class:selected={selectedAuthMethod === 'passkey'}>
            <input
              type="radio"
              name="auth-method"
              value="passkey"
              bind:group={selectedAuthMethod}
            />
            <div class="auth-option-content">
              <strong>{$_('migration.inbound.chooseHandle.authPasskey')}</strong>
              <span>{$_('migration.inbound.chooseHandle.authPasskeyDesc')}</span>
            </div>
          </label>
        </div>
      </div>

      {#if selectedAuthMethod === 'password'}
        <div class="field">
          <label for="new-password">{$_('migration.inbound.chooseHandle.password')}</label>
          <input
            id="new-password"
            type="password"
            placeholder="Password for your new account"
            bind:value={flow.state.targetPassword}
            oninput={(e) => flow.updateField('targetPassword', (e.target as HTMLInputElement).value)}
            required
            minlength="8"
          />
          <p class="hint">{$_('migration.inbound.chooseHandle.passwordHint')}</p>
        </div>
      {:else}
        <div class="info-box">
          <p>{$_('migration.inbound.chooseHandle.passkeyInfo')}</p>
        </div>
      {/if}

      {#if serverInfo?.inviteCodeRequired}
        <div class="field">
          <label for="invite">{$_('migration.inbound.chooseHandle.inviteCode')}</label>
          <input
            id="invite"
            type="text"
            placeholder="Enter invite code"
            bind:value={flow.state.inviteCode}
            oninput={(e) => flow.updateField('inviteCode', (e.target as HTMLInputElement).value)}
            required
          />
        </div>
      {/if}

      <div class="button-row">
        <button class="ghost" onclick={() => flow.setStep('source-handle')}>{$_('migration.inbound.common.back')}</button>
        <button
          disabled={!handleInput.trim() || !flow.state.targetEmail || (selectedAuthMethod === 'password' && !flow.state.targetPassword) || handleAvailable === false}
          onclick={proceedToReviewWithAuth}
        >
          {$_('migration.inbound.common.continue')}
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'review'}
    <div class="step-content">
      <h2>{$_('migration.inbound.review.title')}</h2>
      <p>{$_('migration.inbound.review.desc')}</p>

      <div class="review-card">
        <div class="review-row">
          <span class="label">{$_('migration.inbound.review.currentHandle')}:</span>
          <span class="value">{flow.state.sourceHandle}</span>
        </div>
        <div class="review-row">
          <span class="label">{$_('migration.inbound.review.newHandle')}:</span>
          <span class="value">{flow.state.targetHandle}</span>
        </div>
        <div class="review-row">
          <span class="label">{$_('migration.inbound.review.did')}:</span>
          <span class="value mono">{flow.state.sourceDid}</span>
        </div>
        <div class="review-row">
          <span class="label">{$_('migration.inbound.review.sourcePds')}:</span>
          <span class="value">{flow.state.sourcePdsUrl}</span>
        </div>
        <div class="review-row">
          <span class="label">{$_('migration.inbound.review.targetPds')}:</span>
          <span class="value">{window.location.origin}</span>
        </div>
        <div class="review-row">
          <span class="label">{$_('migration.inbound.review.email')}:</span>
          <span class="value">{flow.state.targetEmail}</span>
        </div>
        <div class="review-row">
          <span class="label">{$_('migration.inbound.review.authentication')}:</span>
          <span class="value">{flow.state.authMethod === 'passkey' ? $_('migration.inbound.review.authPasskey') : $_('migration.inbound.review.authPassword')}</span>
        </div>
      </div>

      <div class="warning-box">
        {$_('migration.inbound.review.warning')}
      </div>

      <div class="button-row">
        <button class="ghost" onclick={() => flow.setStep('choose-handle')} disabled={loading}>{$_('migration.inbound.common.back')}</button>
        <button onclick={startMigration} disabled={loading}>
          {loading ? $_('migration.inbound.review.starting') : $_('migration.inbound.review.startMigration')}
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'migrating'}
    <div class="step-content">
      <h2>{$_('migration.inbound.migrating.title')}</h2>
      <p>{$_('migration.inbound.migrating.desc')}</p>

      <div class="progress-section">
        <div class="progress-item" class:completed={flow.state.progress.repoExported}>
          <span class="icon">{flow.state.progress.repoExported ? '✓' : '○'}</span>
          <span>{$_('migration.inbound.migrating.exportRepo')}</span>
        </div>
        <div class="progress-item" class:completed={flow.state.progress.repoImported}>
          <span class="icon">{flow.state.progress.repoImported ? '✓' : '○'}</span>
          <span>{$_('migration.inbound.migrating.importRepo')}</span>
        </div>
        <div class="progress-item" class:active={flow.state.progress.repoImported && !flow.state.progress.prefsMigrated}>
          <span class="icon">{flow.state.progress.blobsMigrated === flow.state.progress.blobsTotal && flow.state.progress.blobsTotal > 0 ? '✓' : '○'}</span>
          <span>{$_('migration.inbound.migrating.migrateBlobs')} ({flow.state.progress.blobsMigrated}/{flow.state.progress.blobsTotal})</span>
        </div>
        <div class="progress-item" class:completed={flow.state.progress.prefsMigrated}>
          <span class="icon">{flow.state.progress.prefsMigrated ? '✓' : '○'}</span>
          <span>{$_('migration.inbound.migrating.migratePrefs')}</span>
        </div>
      </div>

      {#if flow.state.progress.blobsTotal > 0}
        <div class="progress-bar">
          <div
            class="progress-fill"
            style="width: {(flow.state.progress.blobsMigrated / flow.state.progress.blobsTotal) * 100}%"
          ></div>
        </div>
      {/if}

      <p class="status-text">{flow.state.progress.currentOperation}</p>
    </div>

  {:else if flow.state.step === 'passkey-setup'}
    <div class="step-content">
      <h2>{$_('migration.inbound.passkeySetup.title')}</h2>
      <p>{$_('migration.inbound.passkeySetup.desc')}</p>

      {#if flow.state.error}
        <div class="message error">
          {flow.state.error}
        </div>
      {/if}

      <div class="field">
        <label for="passkey-name">{$_('migration.inbound.passkeySetup.nameLabel')}</label>
        <input
          id="passkey-name"
          type="text"
          placeholder={$_('migration.inbound.passkeySetup.namePlaceholder')}
          bind:value={passkeyName}
          disabled={loading}
        />
        <p class="hint">{$_('migration.inbound.passkeySetup.nameHint')}</p>
      </div>

      <div class="passkey-section">
        <p>{$_('migration.inbound.passkeySetup.instructions')}</p>
        <button class="primary" onclick={registerPasskey} disabled={loading}>
          {loading ? $_('migration.inbound.passkeySetup.registering') : $_('migration.inbound.passkeySetup.register')}
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'app-password'}
    <div class="step-content">
      <h2>{$_('migration.inbound.appPassword.title')}</h2>
      <p>{$_('migration.inbound.appPassword.desc')}</p>

      <div class="warning-box">
        <strong>{$_('migration.inbound.appPassword.warning')}</strong>
      </div>

      <div class="app-password-display">
        <div class="app-password-label">
          {$_('migration.inbound.appPassword.label')}: <strong>{flow.state.generatedAppPasswordName}</strong>
        </div>
        <code class="app-password-code">{flow.state.generatedAppPassword}</code>
        <button type="button" class="copy-btn" onclick={copyAppPassword}>
          {appPasswordCopied ? $_('common.copied') : $_('common.copyToClipboard')}
        </button>
      </div>

      <label class="checkbox-label">
        <input type="checkbox" bind:checked={appPasswordAcknowledged} />
        <span>{$_('migration.inbound.appPassword.saved')}</span>
      </label>

      <div class="button-row">
        <button onclick={handleProceedFromAppPassword} disabled={!appPasswordAcknowledged || loading}>
          {loading ? $_('migration.inbound.common.continue') : $_('migration.inbound.appPassword.continue')}
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'email-verify'}
    <div class="step-content">
      <h2>{$_('migration.inbound.emailVerify.title')}</h2>
      <p>{@html $_('migration.inbound.emailVerify.desc', { values: { email: `<strong>${flow.state.targetEmail}</strong>` } })}</p>

      <div class="info-box">
        <p>
          {$_('migration.inbound.emailVerify.hint')}
        </p>
      </div>

      {#if flow.state.error}
        <div class="message error">
          {flow.state.error}
        </div>
      {/if}

      <form onsubmit={submitEmailVerify}>
        <div class="field">
          <label for="email-verify-token">{$_('migration.inbound.emailVerify.tokenLabel')}</label>
          <input
            id="email-verify-token"
            type="text"
            placeholder={$_('migration.inbound.emailVerify.tokenPlaceholder')}
            bind:value={flow.state.emailVerifyToken}
            oninput={(e) => flow.updateField('emailVerifyToken', (e.target as HTMLInputElement).value)}
            disabled={loading}
            required
          />
        </div>

        <div class="button-row">
          <button type="button" class="ghost" onclick={resendEmailVerify} disabled={loading}>
            {$_('migration.inbound.emailVerify.resend')}
          </button>
          <button type="submit" disabled={loading || !flow.state.emailVerifyToken}>
            {loading ? $_('migration.inbound.emailVerify.verifying') : $_('migration.inbound.emailVerify.verify')}
          </button>
        </div>
      </form>
    </div>

  {:else if flow.state.step === 'plc-token'}
    <div class="step-content">
      <h2>{$_('migration.inbound.plcToken.title')}</h2>
      <p>{$_('migration.inbound.plcToken.desc')}</p>

      <div class="info-box">
        <p>{$_('migration.inbound.plcToken.info')}</p>
      </div>

      <form onsubmit={submitPlcToken}>
        <div class="field">
          <label for="plc-token">{$_('migration.inbound.plcToken.tokenLabel')}</label>
          <input
            id="plc-token"
            type="text"
            placeholder={$_('migration.inbound.plcToken.tokenPlaceholder')}
            bind:value={flow.state.plcToken}
            oninput={(e) => flow.updateField('plcToken', (e.target as HTMLInputElement).value)}
            disabled={loading}
            required
          />
        </div>

        <div class="button-row">
          <button type="button" class="ghost" onclick={resendToken} disabled={loading}>
            {$_('migration.inbound.plcToken.resend')}
          </button>
          <button type="submit" disabled={loading || !flow.state.plcToken}>
            {loading ? $_('migration.inbound.plcToken.completing') : $_('migration.inbound.plcToken.complete')}
          </button>
        </div>
      </form>
    </div>

  {:else if flow.state.step === 'did-web-update'}
    <div class="step-content">
      <h2>{$_('migration.inbound.didWebUpdate.title')}</h2>
      <p>{$_('migration.inbound.didWebUpdate.desc')}</p>

      <div class="info-box">
        <p>
          {$_('migration.inbound.didWebUpdate.yourDid')} <code>{flow.state.sourceDid}</code>
        </p>
        <p style="margin-top: 12px;">
          {$_('migration.inbound.didWebUpdate.updateInstructions')}
        </p>
      </div>

      <div class="code-block">
        <pre>{`{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1",
    "https://w3id.org/security/suites/secp256k1-2019/v1"
  ],
  "id": "${flow.state.sourceDid}",
  "alsoKnownAs": [
    "at://${flow.state.targetHandle || '...'}"
  ],
  "verificationMethod": [
    {
      "id": "${flow.state.sourceDid}#atproto",
      "type": "Multikey",
      "controller": "${flow.state.sourceDid}",
      "publicKeyMultibase": "${flow.state.targetVerificationMethod?.replace('did:key:', '') || '...'}"
    }
  ],
  "service": [
    {
      "id": "#atproto_pds",
      "type": "AtprotoPersonalDataServer",
      "serviceEndpoint": "${window.location.origin}"
    }
  ]
}`}</pre>
      </div>

      <div class="warning-box">
        <strong>{$_('migration.inbound.didWebUpdate.important')}</strong> {$_('migration.inbound.didWebUpdate.verifyFirst')}
        {$_('migration.inbound.didWebUpdate.fileLocation')} <code>https://{flow.state.sourceDid.replace('did:web:', '')}/.well-known/did.json</code>
      </div>

      <div class="button-row">
        <button class="ghost" onclick={() => flow.setStep('email-verify')} disabled={loading}>{$_('migration.inbound.common.back')}</button>
        <button onclick={completeDidWeb} disabled={loading}>
          {loading ? $_('migration.inbound.didWebUpdate.completing') : $_('migration.inbound.didWebUpdate.complete')}
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'finalizing'}
    <div class="step-content">
      <h2>{$_('migration.inbound.finalizing.title')}</h2>
      <p>{$_('migration.inbound.finalizing.desc')}</p>

      <div class="progress-section">
        <div class="progress-item" class:completed={flow.state.progress.plcSigned}>
          <span class="icon">{flow.state.progress.plcSigned ? '✓' : '○'}</span>
          <span>{$_('migration.inbound.finalizing.signingPlc')}</span>
        </div>
        <div class="progress-item" class:completed={flow.state.progress.activated}>
          <span class="icon">{flow.state.progress.activated ? '✓' : '○'}</span>
          <span>{$_('migration.inbound.finalizing.activating')}</span>
        </div>
        <div class="progress-item" class:completed={flow.state.progress.deactivated}>
          <span class="icon">{flow.state.progress.deactivated ? '✓' : '○'}</span>
          <span>{$_('migration.inbound.finalizing.deactivating')}</span>
        </div>
      </div>

      <p class="status-text">{flow.state.progress.currentOperation}</p>
    </div>

  {:else if flow.state.step === 'success'}
    <div class="step-content success-content">
      <div class="success-icon">✓</div>
      <h2>{$_('migration.inbound.success.title')}</h2>
      <p>{$_('migration.inbound.success.desc')}</p>

      <div class="success-details">
        <div class="detail-row">
          <span class="label">{$_('migration.inbound.success.yourNewHandle')}:</span>
          <span class="value">{flow.state.targetHandle}</span>
        </div>
        <div class="detail-row">
          <span class="label">{$_('migration.inbound.success.did')}:</span>
          <span class="value mono">{flow.state.sourceDid}</span>
        </div>
      </div>

      {#if flow.state.progress.blobsFailed.length > 0}
        <div class="message warning">
          {$_('migration.inbound.success.blobsWarning', { values: { count: flow.state.progress.blobsFailed.length } })}
        </div>
      {/if}

      <p class="redirect-text">{$_('migration.inbound.success.redirecting')}</p>
    </div>

  {:else if flow.state.step === 'error'}
    <div class="step-content">
      <h2>{$_('migration.inbound.error.title')}</h2>
      <p>{$_('migration.inbound.error.desc')}</p>

      <div class="message error">
        {flow.state.error || 'An unknown error occurred. Please check the browser console for details.'}
      </div>

      <div class="button-row">
        <button class="ghost" onclick={onBack}>{$_('migration.inbound.error.startOver')}</button>
      </div>
    </div>
  {/if}
</div>

<style>
  .passkey-section {
    margin-top: 16px;
  }
  .passkey-section button {
    width: 100%;
    margin-top: 12px;
  }
  .app-password-display {
    background: var(--bg-card);
    border: 2px solid var(--accent);
    border-radius: var(--radius-xl);
    padding: var(--space-6);
    text-align: center;
    margin: var(--space-4) 0;
  }
  .app-password-label {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin-bottom: var(--space-4);
  }
  .app-password-code {
    display: block;
    font-size: var(--text-xl);
    font-family: ui-monospace, monospace;
    letter-spacing: 0.1em;
    padding: var(--space-5);
    background: var(--bg-input);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-4);
    user-select: all;
  }
  .copy-btn {
    padding: var(--space-3) var(--space-5);
    font-size: var(--text-sm);
  }
  .resume-info {
    margin-bottom: var(--space-5);
  }
  .resume-info h3 {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-base);
  }
  .resume-details {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .resume-row {
    display: flex;
    justify-content: space-between;
    font-size: var(--text-sm);
  }
  .resume-row .label {
    color: var(--text-secondary);
  }
  .resume-row .value {
    font-weight: var(--font-medium);
  }
  .resume-note {
    margin-top: var(--space-3);
    font-size: var(--text-sm);
    font-style: italic;
  }
</style>
