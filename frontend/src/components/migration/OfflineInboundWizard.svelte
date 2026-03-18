<script lang="ts">
  import type { OfflineInboundMigrationFlow } from '../../lib/migration'
  import type { AuthMethod, ServerDescription } from '../../lib/migration/types'
  import { resolveVerificationIdentifier } from '../../lib/flows/migration-shared'
  import { getErrorMessage } from '../../lib/migration/types'
  import { PasskeyCancelledError } from '../../lib/flows/perform-passkey-registration'
  import { _ } from '../../lib/i18n'
  import ErrorStep from './ErrorStep.svelte'
  import SuccessStep from './SuccessStep.svelte'
  import ChooseHandleStep from './ChooseHandleStep.svelte'
  import EmailVerifyStep from './EmailVerifyStep.svelte'
  import PasskeySetupStep from './PasskeySetupStep.svelte'
  import AppPasswordStep from './AppPasswordStep.svelte'
  import StepIndicator from './StepIndicator.svelte'
  import ProgressStep from './ProgressStep.svelte'
  import ReviewStep from './ReviewStep.svelte'

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
  let validatingKey = $state(false)
  let keyValid = $state<boolean | null>(null)
  let fileInputRef = $state<HTMLInputElement | null>(null)
  let selectedAuthMethod = $state<AuthMethod>('password')
  let passkeyName = $state('')

  function verificationIdentifier(): string {
    return resolveVerificationIdentifier(
      flow.state.verificationChannel,
      flow.state.targetEmail,
      flow.state.discordUsername,
      flow.state.telegramUsername,
      flow.state.signalUsername,
    )
  }

  let redirectTriggered = $state(false)

  $effect(() => {
    if (flow.state.step === 'welcome' || flow.state.step === 'choose-handle') {
      loadServerInfo()
    }
    if (flow.state.step === 'choose-handle') {
      handleInput = ''
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
      const isBotChannel = flow.state.verificationChannel === 'telegram' || flow.state.verificationChannel === 'discord'
      const interval = setInterval(async () => {
        if (!isBotChannel && flow.state.emailVerifyToken.trim()) return
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
      await flow.registerPasskey(passkeyName || undefined)
    } catch (err) {
      if (err instanceof PasskeyCancelledError || (err instanceof DOMException && err.name === 'NotAllowedError')) {
        flow.setError('Passkey registration was cancelled. Please try again.')
      } else {
        flow.setError(getErrorMessage(err))
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
  <StepIndicator steps={steps} currentIndex={getCurrentStepIndex()} />

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
      email={flow.state.targetEmail}
      password={flow.state.targetPassword}
      authMethod={selectedAuthMethod}
      inviteCode={flow.state.inviteCode}
      {serverInfo}
      availableCommsChannels={serverInfo?.availableCommsChannels ?? ['email']}
      verificationChannel={flow.state.verificationChannel}
      discordUsername={flow.state.discordUsername}
      telegramUsername={flow.state.telegramUsername}
      signalUsername={flow.state.signalUsername}
      migratingFromLabel={$_('migration.offline.chooseHandle.migratingDid')}
      migratingFromValue={flow.state.userDid}
      {loading}
      sourceHandle=""
      sourceDid={flow.state.userDid}
      handlePreservation="new"
      existingHandleVerified={false}
      verifyingExistingHandle={false}
      existingHandleError={null}
      checkAvailability={(h) => flow.checkHandleAvailability(h)}
      onHandleChange={(h) => handleInput = h}
      onDomainChange={(d) => selectedDomain = d}
      onEmailChange={(e) => flow.setTargetEmail(e)}
      onPasswordChange={(p) => flow.setTargetPassword(p)}
      onAuthMethodChange={(m) => selectedAuthMethod = m}
      onInviteCodeChange={(c) => flow.setInviteCode(c)}
      onVerificationChannelChange={(ch) => flow.updateField('verificationChannel', ch)}
      onDiscordChange={(v) => flow.updateField('discordUsername', v)}
      onTelegramChange={(v) => flow.updateField('telegramUsername', v)}
      onSignalChange={(v) => flow.updateField('signalUsername', v)}
      onBack={() => flow.setStep('provide-rotation-key')}
      onContinue={proceedToReview}
    />

  {:else if flow.state.step === 'review'}
    <ReviewStep
      description={$_('migration.offline.review.desc')}
      rows={[
        { label: $_('migration.inbound.review.did'), value: flow.state.userDid, mono: true },
        { label: $_('migration.inbound.review.newHandle'), value: flow.state.targetHandle },
        { label: $_('migration.offline.review.carFile'), value: `${flow.state.carFileName} (${(flow.state.carSizeBytes / 1024 / 1024).toFixed(2)} MB)` },
        { label: $_('migration.offline.review.rotationKey'), value: flow.state.rotationKeyDidKey, mono: true },
        { label: $_('migration.inbound.review.targetPds'), value: window.location.origin },
        { label: $_(`register.${flow.state.verificationChannel}`), value: verificationIdentifier() },
        { label: $_('migration.inbound.review.authentication'), value: flow.state.authMethod === 'passkey' ? $_('migration.inbound.review.authPasskey') : $_('migration.inbound.review.authPassword') },
      ]}
      {loading}
      onBack={() => flow.setStep('choose-handle')}
      onContinue={startMigration}
    >
      {#snippet warning()}
        <strong>{$_('migration.offline.review.plcWarningTitle')}</strong>
        <p>{$_('migration.offline.review.plcWarning')}</p>
      {/snippet}
    </ReviewStep>

  {:else if flow.state.step === 'creating' || flow.state.step === 'importing'}
    <ProgressStep
      title={$_('migration.offline.migrating.title')}
      description={$_('migration.offline.migrating.desc')}
      items={[
        { label: $_('migration.offline.migrating.creating'), completed: flow.state.step !== 'creating', active: flow.state.step === 'creating' },
        { label: $_('migration.offline.migrating.importing'), completed: false, active: flow.state.step === 'importing' },
      ]}
      statusText={flow.state.progress.currentOperation}
    />

  {:else if flow.state.step === 'migrating-blobs'}
    <ProgressStep
      title={$_('migration.offline.blobs.title')}
      description={$_('migration.offline.blobs.desc')}
      items={[
        { label: $_('migration.offline.migrating.importing'), completed: true },
        { label: `${$_('migration.offline.blobs.migrating')} (${flow.state.progress.blobsMigrated}/${flow.state.progress.blobsTotal})`, completed: false, active: true },
      ]}
      statusText={flow.state.progress.currentOperation}
      progressBar={flow.state.progress.blobsTotal > 0 ? { current: flow.state.progress.blobsMigrated, total: flow.state.progress.blobsTotal } : undefined}
    >
      {#if flow.state.progress.blobsFailed.length > 0}
        <div class="warning-box">
          <strong>{$_('migration.offline.blobs.failedTitle')}</strong>
          <p>{$_('migration.offline.blobs.failedDesc', { values: { count: flow.state.progress.blobsFailed.length } })}</p>
        </div>
      {/if}
    </ProgressStep>

  {:else if flow.state.step === 'email-verify'}
    <EmailVerifyStep
      channel={flow.state.verificationChannel}
      identifier={verificationIdentifier()}
      handle={flow.state.targetHandle}
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
    <ProgressStep
      title={$_('migration.inbound.finalizing.title')}
      description={$_('migration.inbound.finalizing.desc')}
      items={[
        { label: $_('migration.inbound.finalizing.signingPlc'), completed: flow.state.progress.plcSigned },
        { label: $_('migration.inbound.finalizing.activating'), completed: flow.state.progress.activated },
      ]}
      statusText={flow.state.progress.currentOperation}
    />

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

