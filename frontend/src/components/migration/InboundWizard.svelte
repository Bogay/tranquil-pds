<script lang="ts">
  import type { InboundMigrationFlow } from '../../lib/migration'
  import type { AuthMethod, HandlePreservation, ServerDescription } from '../../lib/migration/types'
  import { resolveVerificationIdentifier } from '../../lib/flows/migration-shared'
  import { getErrorMessage } from '../../lib/migration/types'
  import { createPasskeyCredential, PasskeyCancelledError } from '../../lib/flows/perform-passkey-registration'
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

  interface ResumeInfo {
    direction: 'inbound'
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
  let selectedAuthMethod = $state<AuthMethod>('password')
  let passkeyName = $state('')
  let verifyingExistingHandle = $state(false)
  let existingHandleError = $state<string | null>(null)
  let sourcePdsDomains = $state<string[]>([])

  const isResuming = $derived(flow.state.needsReauth === true)
  const isDidWeb = $derived(flow.state.sourceDid.startsWith("did:web:"))

  function verificationIdentifier(): string {
    return resolveVerificationIdentifier(
      flow.state.verificationChannel,
      flow.state.targetEmail,
      flow.state.discordUsername,
      flow.state.telegramUsername,
      flow.state.signalUsername,
    )
  }

  $effect(() => {
    if (flow.state.step === 'welcome' || flow.state.step === 'choose-handle') {
      loadServerInfo()
    }
    if (flow.state.step === 'choose-handle') {
      handleInput = ''
      existingHandleError = null
      flow.updateField('handlePreservation', 'new')
      flow.updateField('existingHandleVerified', false)
      flow.loadSourcePdsDomains().then((d) => { sourcePdsDomains = d })
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

  function handlePreservationChange(preservation: HandlePreservation) {
    flow.updateField('handlePreservation', preservation)
    existingHandleError = null
    if (preservation === 'existing') {
      flow.updateField('existingHandleVerified', false)
    }
  }

  async function verifyExistingHandle() {
    verifyingExistingHandle = true
    existingHandleError = null

    try {
      const result = await flow.verifyExistingHandle()
      if (!result.verified && result.error) {
        existingHandleError = result.error
      }
    } catch (err) {
      existingHandleError = getErrorMessage(err)
    } finally {
      verifyingExistingHandle = false
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
      const credential = await createPasskeyCredential(
        () => flow.startPasskeyRegistration(),
      )
      await flow.completePasskeyRegistration(credential, passkeyName || undefined)
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
    let targetHandle: string
    if (flow.state.handlePreservation === 'existing' && flow.state.existingHandleVerified) {
      targetHandle = flow.state.sourceHandle
    } else {
      targetHandle = handleInput.includes('.')
        ? handleInput
        : `${handleInput}.${selectedDomain}`
    }

    flow.updateField('targetHandle', targetHandle)
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
  <StepIndicator steps={steps} currentIndex={getCurrentStepIndex()} />

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
        <button type="button" class="ghost" onclick={onBack}>{$_('migration.inbound.common.cancel')}</button>
        <button type="button" disabled={!understood} onclick={() => flow.setStep('source-handle')}>
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
        <div>
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
      migratingFromLabel={$_('migration.inbound.chooseHandle.migratingFrom')}
      migratingFromValue={flow.state.sourceHandle}
      {loading}
      sourceHandle={flow.state.sourceHandle}
      sourceDid={flow.state.sourceDid}
      {sourcePdsDomains}
      handlePreservation={flow.state.handlePreservation}
      existingHandleVerified={flow.state.existingHandleVerified}
      {verifyingExistingHandle}
      {existingHandleError}
      checkAvailability={(h) => flow.checkHandleAvailability(h)}
      onHandleChange={(h) => handleInput = h}
      onDomainChange={(d) => selectedDomain = d}
      onEmailChange={(e) => flow.updateField('targetEmail', e)}
      onPasswordChange={(p) => flow.updateField('targetPassword', p)}
      onAuthMethodChange={(m) => selectedAuthMethod = m}
      onInviteCodeChange={(c) => flow.updateField('inviteCode', c)}
      onVerificationChannelChange={(ch) => flow.updateField('verificationChannel', ch)}
      onDiscordChange={(v) => flow.updateField('discordUsername', v)}
      onTelegramChange={(v) => flow.updateField('telegramUsername', v)}
      onSignalChange={(v) => flow.updateField('signalUsername', v)}
      onHandlePreservationChange={handlePreservationChange}
      onVerifyExistingHandle={verifyExistingHandle}
      onBack={() => flow.setStep('source-handle')}
      onContinue={proceedToReviewWithAuth}
    />

  {:else if flow.state.step === 'review'}
    <ReviewStep
      description={$_('migration.inbound.review.desc')}
      rows={[
        { label: $_('migration.inbound.review.currentHandle'), value: flow.state.sourceHandle },
        { label: $_('migration.inbound.review.newHandle'), value: flow.state.targetHandle },
        { label: $_('migration.inbound.review.did'), value: flow.state.sourceDid, mono: true },
        { label: $_('migration.inbound.review.sourcePds'), value: flow.state.sourcePdsUrl },
        { label: $_('migration.inbound.review.targetPds'), value: window.location.origin },
        { label: $_(`register.${flow.state.verificationChannel}`), value: verificationIdentifier() },
        { label: $_('migration.inbound.review.authentication'), value: flow.state.authMethod === 'passkey' ? $_('migration.inbound.review.authPasskey') : $_('migration.inbound.review.authPassword') },
      ]}
      {loading}
      onBack={() => flow.setStep('choose-handle')}
      onContinue={startMigration}
    >
      {#snippet warning()}
        {$_('migration.inbound.review.warning')}
      {/snippet}
    </ReviewStep>

  {:else if flow.state.step === 'migrating'}
    <ProgressStep
      title={$_('migration.inbound.migrating.title')}
      description={$_('migration.inbound.migrating.desc')}
      items={[
        { label: $_('migration.inbound.migrating.exportRepo'), completed: flow.state.progress.repoExported },
        { label: $_('migration.inbound.migrating.importRepo'), completed: flow.state.progress.repoImported },
        { label: `${$_('migration.inbound.migrating.migrateBlobs')} (${flow.state.progress.blobsMigrated}/${flow.state.progress.blobsTotal})`, completed: flow.state.progress.blobsMigrated === flow.state.progress.blobsTotal && flow.state.progress.blobsTotal > 0, active: flow.state.progress.repoImported && !flow.state.progress.prefsMigrated },
        { label: $_('migration.inbound.migrating.migratePrefs'), completed: flow.state.progress.prefsMigrated },
      ]}
      statusText={flow.state.progress.currentOperation}
      progressBar={flow.state.progress.blobsTotal > 0 ? { current: flow.state.progress.blobsMigrated, total: flow.state.progress.blobsTotal } : undefined}
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

  {:else if flow.state.step === 'plc-token'}
    <div class="step-content">
      <h2>{$_('migration.inbound.plcToken.title')}</h2>
      <p>{$_('migration.inbound.plcToken.desc')}</p>

      <div class="info-box">
        <p>{$_('migration.inbound.plcToken.info')}</p>
      </div>

      <form onsubmit={submitPlcToken}>
        <div>
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
    <ProgressStep
      title={$_('migration.inbound.finalizing.title')}
      description={$_('migration.inbound.finalizing.desc')}
      items={[
        { label: $_('migration.inbound.finalizing.signingPlc'), completed: flow.state.progress.plcSigned },
        { label: $_('migration.inbound.finalizing.activating'), completed: flow.state.progress.activated },
        { label: $_('migration.inbound.finalizing.deactivating'), completed: flow.state.progress.deactivated },
      ]}
      statusText={flow.state.progress.currentOperation}
    />

  {:else if flow.state.step === 'success'}
    <SuccessStep handle={flow.state.targetHandle} did={flow.state.sourceDid}>
      {#snippet extraContent()}
        {#if flow.state.progress.blobsFailed.length > 0}
          <div class="message warning">
            {$_('migration.inbound.success.blobsWarning', { values: { count: flow.state.progress.blobsFailed.length } })}
          </div>
        {/if}
      {/snippet}
    </SuccessStep>

  {:else if flow.state.step === 'error'}
    <ErrorStep error={flow.state.error} onStartOver={onBack} />
  {/if}
</div>
