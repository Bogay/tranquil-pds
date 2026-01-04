<script lang="ts">
  import type { OfflineInboundMigrationFlow } from '../../lib/migration'
  import type { AuthMethod, ServerDescription } from '../../lib/migration/types'
  import { getErrorMessage } from '../../lib/migration/types'
  import { base64UrlEncode, prepareWebAuthnCreationOptions } from '../../lib/migration/atproto-client'
  import { _ } from '../../lib/i18n'
  import '../../styles/migration.css'
  import ErrorStep from './ErrorStep.svelte'
  import SuccessStep from './SuccessStep.svelte'
  import ChooseHandleStep from './ChooseHandleStep.svelte'
  import EmailVerifyStep from './EmailVerifyStep.svelte'
  import PasskeySetupStep from './PasskeySetupStep.svelte'
  import AppPasswordStep from './AppPasswordStep.svelte'

  interface Props {
    flow: OfflineInboundMigrationFlow
    onBack: () => void
    onComplete: () => void
  }

  let { flow, onBack, onComplete }: Props = $props()

  let serverInfo = $state<ServerDescription | null>(null)
  let loading = $state(false)
  let understood = $state(false)
  let handleInput = $state('')
  let selectedDomain = $state('')
  let handleAvailable = $state<boolean | null>(null)
  let checkingHandle = $state(false)
  let validatingKey = $state(false)
  let keyValid = $state<boolean | null>(null)
  let fileInputRef = $state<HTMLInputElement | null>(null)
  let selectedAuthMethod = $state<AuthMethod>('password')
  let passkeyName = $state('')

  let redirectTriggered = $state(false)

  $effect(() => {
    if (flow.state.step === 'welcome' || flow.state.step === 'choose-handle') {
      loadServerInfo()
    }
    if (flow.state.step === 'choose-handle') {
      handleInput = ''
      handleAvailable = null
    }
  })

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
    return undefined
  })

  async function loadServerInfo() {
    if (!serverInfo) {
      serverInfo = await flow.loadLocalServerInfo()
      if (serverInfo.availableUserDomains.length > 0) {
        selectedDomain = serverInfo.availableUserDomains[0]
      }
    }
  }

  function handleFileSelect(e: Event) {
    const input = e.target as HTMLInputElement
    const file = input.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = () => {
      const arrayBuffer = reader.result as ArrayBuffer
      flow.setCarFile(new Uint8Array(arrayBuffer), file.name)
    }
    reader.readAsArrayBuffer(file)
  }

  async function validateRotationKey() {
    if (!flow.state.rotationKey || !flow.state.userDid) return

    validatingKey = true
    keyValid = null

    try {
      const isValid = await flow.validateRotationKey()
      keyValid = isValid
      if (isValid) {
        flow.setStep('choose-handle')
      }
    } catch (err) {
      flow.setError(getErrorMessage(err))
      keyValid = false
    } finally {
      validatingKey = false
    }
  }

  async function startMigration() {
    loading = true
    try {
      await flow.runMigration()
    } catch (err) {
      flow.setError(getErrorMessage(err))
    } finally {
      loading = false
    }
  }

  const steps = $derived(
    flow.state.authMethod === 'passkey'
      ? ['Enter DID', 'Upload CAR', 'Rotation Key', 'Handle', 'Review', 'Import', 'Blobs', 'Verify Email', 'Passkey', 'App Password', 'Complete']
      : ['Enter DID', 'Upload CAR', 'Rotation Key', 'Handle', 'Review', 'Import', 'Blobs', 'Verify Email', 'Complete']
  )

  function getCurrentStepIndex(): number {
    const isPasskey = flow.state.authMethod === 'passkey'
    switch (flow.state.step) {
      case 'welcome': return 0
      case 'provide-did': return 0
      case 'upload-car': return 1
      case 'provide-rotation-key': return 2
      case 'choose-handle': return 3
      case 'review': return 4
      case 'creating':
      case 'importing': return 5
      case 'migrating-blobs': return 6
      case 'email-verify': return 7
      case 'passkey-setup': return isPasskey ? 8 : 7
      case 'app-password': return 9
      case 'plc-signing':
      case 'finalizing': return isPasskey ? 10 : 8
      case 'success': return isPasskey ? 10 : 8
      default: return 0
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

    flow.setTargetHandle(fullHandle)
    flow.setAuthMethod(selectedAuthMethod)
    flow.setStep('review')
  }

  async function submitEmailVerify(e: Event) {
    e.preventDefault()
    loading = true
    try {
      await flow.submitEmailVerifyToken(flow.state.emailVerifyToken)
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

  async function registerPasskey() {
    loading = true
    flow.setError(null)

    try {
      if (!window.PublicKeyCredential) {
        throw new Error('Passkeys are not supported in this browser. Please use a modern browser with WebAuthn support.')
      }

      await flow.registerPasskey(passkeyName || undefined)
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
      <h2>{$_('migration.offline.welcome.title')}</h2>
      <p>{$_('migration.offline.welcome.desc')}</p>

      <div class="warning-box">
        <strong>{$_('migration.offline.welcome.warningTitle')}</strong>
        <p>{$_('migration.offline.welcome.warningDesc')}</p>
      </div>

      <div class="info-box">
        <h3>{$_('migration.offline.welcome.requirementsTitle')}</h3>
        <ul>
          <li>{$_('migration.offline.welcome.requirement1')}</li>
          <li>{$_('migration.offline.welcome.requirement2')}</li>
          <li>{$_('migration.offline.welcome.requirement3')}</li>
        </ul>
      </div>

      <label class="checkbox-label">
        <input type="checkbox" bind:checked={understood} />
        <span>{$_('migration.offline.welcome.understand')}</span>
      </label>

      <div class="button-row">
        <button class="ghost" onclick={onBack}>{$_('migration.inbound.common.cancel')}</button>
        <button disabled={!understood} onclick={() => flow.setStep('provide-did')}>
          {$_('migration.inbound.common.continue')}
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'provide-did'}
    <div class="step-content">
      <h2>{$_('migration.offline.provideDid.title')}</h2>
      <p>{$_('migration.offline.provideDid.desc')}</p>

      <div class="field">
        <label for="user-did">{$_('migration.offline.provideDid.label')}</label>
        <input
          id="user-did"
          type="text"
          placeholder="did:plc:abc123..."
          value={flow.state.userDid}
          oninput={(e) => flow.setUserDid((e.target as HTMLInputElement).value)}
        />
        <p class="hint">{$_('migration.offline.provideDid.hint')}</p>
      </div>

      <div class="button-row">
        <button class="ghost" onclick={() => flow.setStep('welcome')}>{$_('migration.inbound.common.back')}</button>
        <button disabled={!flow.state.userDid.startsWith('did:')} onclick={() => flow.setStep('upload-car')}>
          {$_('migration.inbound.common.continue')}
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'upload-car'}
    <div class="step-content">
      <h2>{$_('migration.offline.uploadCar.title')}</h2>
      <p>{$_('migration.offline.uploadCar.desc')}</p>

      {#if flow.state.carNeedsReupload}
        <div class="warning-box">
          <strong>{$_('migration.offline.uploadCar.reuploadWarningTitle')}</strong>
          <p>{$_('migration.offline.uploadCar.reuploadWarning')}</p>
          {#if flow.state.carFileName}
            <p><strong>Previous file:</strong> {flow.state.carFileName} ({(flow.state.carSizeBytes / 1024 / 1024).toFixed(2)} MB)</p>
          {/if}
        </div>
      {/if}

      <div class="field">
        <label for="car-file">{$_('migration.offline.uploadCar.label')}</label>
        <div class="file-input-container">
          <input
            id="car-file"
            type="file"
            accept=".car"
            onchange={handleFileSelect}
            bind:this={fileInputRef}
          />
          {#if flow.state.carFile && flow.state.carFileName}
            <div class="file-info">
              <span class="file-name">{flow.state.carFileName}</span>
              <span class="file-size">({(flow.state.carSizeBytes / 1024 / 1024).toFixed(2)} MB)</span>
            </div>
          {/if}
        </div>
        <p class="hint">{$_('migration.offline.uploadCar.hint')}</p>
      </div>

      <div class="button-row">
        <button class="ghost" onclick={() => flow.setStep('provide-did')}>{$_('migration.inbound.common.back')}</button>
        <button disabled={!flow.state.carFile} onclick={() => flow.setStep('provide-rotation-key')}>
          {$_('migration.inbound.common.continue')}
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'provide-rotation-key'}
    <div class="step-content">
      <h2>{$_('migration.offline.rotationKey.title')}</h2>
      <p>{$_('migration.offline.rotationKey.desc')}</p>

      <div class="warning-box">
        <strong>{$_('migration.offline.rotationKey.securityWarningTitle')}</strong>
        <ul>
          <li>{$_('migration.offline.rotationKey.securityWarning1')}</li>
          <li>{$_('migration.offline.rotationKey.securityWarning2')}</li>
          <li>{$_('migration.offline.rotationKey.securityWarning3')}</li>
        </ul>
      </div>

      <div class="field">
        <label for="rotation-key">{$_('migration.offline.rotationKey.label')}</label>
        <textarea
          id="rotation-key"
          rows={4}
          placeholder={$_('migration.offline.rotationKey.placeholder')}
          value={flow.state.rotationKey}
          oninput={(e) => {
            flow.setRotationKey((e.target as HTMLTextAreaElement).value)
            keyValid = null
          }}
        ></textarea>
        <p class="hint">{$_('migration.offline.rotationKey.hint')}</p>
      </div>

      {#if keyValid === true}
        <div class="message success">{$_('migration.offline.rotationKey.valid')}</div>
      {:else if keyValid === false}
        <div class="message error">{$_('migration.offline.rotationKey.invalid')}</div>
      {/if}

      <div class="button-row">
        <button class="ghost" onclick={() => flow.setStep('upload-car')}>{$_('migration.inbound.common.back')}</button>
        <button
          disabled={!flow.state.rotationKey || validatingKey}
          onclick={validateRotationKey}
        >
          {validatingKey ? $_('migration.offline.rotationKey.validating') : $_('migration.offline.rotationKey.validate')}
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'choose-handle'}
    <ChooseHandleStep
      {handleInput}
      {selectedDomain}
      {handleAvailable}
      {checkingHandle}
      email={flow.state.targetEmail}
      password={flow.state.targetPassword}
      authMethod={selectedAuthMethod}
      inviteCode={flow.state.inviteCode}
      {serverInfo}
      migratingFromLabel={$_('migration.offline.chooseHandle.migratingDid')}
      migratingFromValue={flow.state.userDid}
      {loading}
      onHandleChange={(h) => handleInput = h}
      onDomainChange={(d) => selectedDomain = d}
      onCheckHandle={checkHandle}
      onEmailChange={(e) => flow.setTargetEmail(e)}
      onPasswordChange={(p) => flow.setTargetPassword(p)}
      onAuthMethodChange={(m) => selectedAuthMethod = m}
      onInviteCodeChange={(c) => flow.setInviteCode(c)}
      onBack={() => flow.setStep('provide-rotation-key')}
      onContinue={proceedToReview}
    />

  {:else if flow.state.step === 'review'}
    <div class="step-content">
      <h2>{$_('migration.inbound.review.title')}</h2>
      <p>{$_('migration.offline.review.desc')}</p>

      <div class="review-card">
        <div class="review-row">
          <span class="label">{$_('migration.inbound.review.did')}:</span>
          <span class="value mono">{flow.state.userDid}</span>
        </div>
        <div class="review-row">
          <span class="label">{$_('migration.inbound.review.newHandle')}:</span>
          <span class="value">{flow.state.targetHandle}</span>
        </div>
        <div class="review-row">
          <span class="label">{$_('migration.offline.review.carFile')}:</span>
          <span class="value">{flow.state.carFileName} ({(flow.state.carSizeBytes / 1024 / 1024).toFixed(2)} MB)</span>
        </div>
        <div class="review-row">
          <span class="label">{$_('migration.offline.review.rotationKey')}:</span>
          <span class="value mono">{flow.state.rotationKeyDidKey}</span>
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
        <strong>{$_('migration.offline.review.plcWarningTitle')}</strong>
        <p>{$_('migration.offline.review.plcWarning')}</p>
      </div>

      <div class="button-row">
        <button class="ghost" onclick={() => flow.setStep('choose-handle')} disabled={loading}>{$_('migration.inbound.common.back')}</button>
        <button onclick={startMigration} disabled={loading}>
          {loading ? $_('migration.inbound.review.starting') : $_('migration.inbound.review.startMigration')}
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'creating' || flow.state.step === 'importing'}
    <div class="step-content">
      <h2>{$_('migration.offline.migrating.title')}</h2>
      <p>{$_('migration.offline.migrating.desc')}</p>

      <div class="progress-section">
        <div class="progress-item" class:completed={flow.state.step !== 'creating'} class:active={flow.state.step === 'creating'}>
          <span class="icon">{flow.state.step !== 'creating' ? '✓' : '○'}</span>
          <span>{$_('migration.offline.migrating.creating')}</span>
        </div>
        <div class="progress-item" class:active={flow.state.step === 'importing'}>
          <span class="icon">○</span>
          <span>{$_('migration.offline.migrating.importing')}</span>
        </div>
      </div>

      <p class="status-text">{flow.state.progress.currentOperation}</p>
    </div>

  {:else if flow.state.step === 'migrating-blobs'}
    <div class="step-content">
      <h2>{$_('migration.offline.blobs.title')}</h2>
      <p>{$_('migration.offline.blobs.desc')}</p>

      <div class="progress-section">
        <div class="progress-item completed">
          <span class="icon">✓</span>
          <span>{$_('migration.offline.migrating.importing')}</span>
        </div>
        <div class="progress-item active">
          <span class="icon">○</span>
          <span>{$_('migration.offline.blobs.migrating')}</span>
        </div>
      </div>

      {#if flow.state.progress.blobsTotal > 0}
        <div class="blob-progress">
          <div class="blob-progress-bar">
            <div
              class="blob-progress-fill"
              style="width: {(flow.state.progress.blobsMigrated / flow.state.progress.blobsTotal) * 100}%"
            ></div>
          </div>
          <p class="blob-progress-text">
            {flow.state.progress.blobsMigrated} / {flow.state.progress.blobsTotal} blobs
          </p>
        </div>
      {/if}

      <p class="status-text">{flow.state.progress.currentOperation}</p>

      {#if flow.state.progress.blobsFailed.length > 0}
        <div class="warning-box">
          <strong>{$_('migration.offline.blobs.failedTitle')}</strong>
          <p>{$_('migration.offline.blobs.failedDesc', { values: { count: flow.state.progress.blobsFailed.length } })}</p>
        </div>
      {/if}
    </div>

  {:else if flow.state.step === 'email-verify'}
    <EmailVerifyStep
      email={flow.state.targetEmail}
      token={flow.state.emailVerifyToken}
      {loading}
      error={flow.state.error}
      onTokenChange={(t) => flow.updateField('emailVerifyToken', t)}
      onSubmit={submitEmailVerify}
      onResend={resendEmailVerify}
    />

  {:else if flow.state.step === 'passkey-setup'}
    <PasskeySetupStep
      {passkeyName}
      {loading}
      error={flow.state.error}
      onPasskeyNameChange={(n) => passkeyName = n}
      onRegister={registerPasskey}
    />

  {:else if flow.state.step === 'app-password'}
    <AppPasswordStep
      appPassword={flow.state.generatedAppPassword || ''}
      appPasswordName={flow.state.generatedAppPasswordName || ''}
      {loading}
      onContinue={handleProceedFromAppPassword}
    />

  {:else if flow.state.step === 'plc-signing' || flow.state.step === 'finalizing'}
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
      </div>

      <p class="status-text">{flow.state.progress.currentOperation}</p>
    </div>

  {:else if flow.state.step === 'success'}
    <SuccessStep
      handle={flow.state.targetHandle}
      did={flow.state.userDid}
      description={$_('migration.offline.success.desc')}
    />

  {:else if flow.state.step === 'error'}
    <ErrorStep error={flow.state.error} onStartOver={onBack} />
  {/if}
</div>

