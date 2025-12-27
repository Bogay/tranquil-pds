<script lang="ts">
  import type { InboundMigrationFlow } from '../../lib/migration'
  import type { ServerDescription } from '../../lib/migration/types'
  import { _ } from '../../lib/i18n'

  interface Props {
    flow: InboundMigrationFlow
    onBack: () => void
    onComplete: () => void
  }

  let { flow, onBack, onComplete }: Props = $props()

  let serverInfo = $state<ServerDescription | null>(null)
  let loading = $state(false)
  let handleInput = $state('')
  let passwordInput = $state('')
  let localPasswordInput = $state('')
  let understood = $state(false)
  let selectedDomain = $state('')
  let handleAvailable = $state<boolean | null>(null)
  let checkingHandle = $state(false)

  const isResumedMigration = $derived(flow.state.progress.repoImported)

  $effect(() => {
    if (flow.state.step === 'welcome' || flow.state.step === 'choose-handle') {
      loadServerInfo()
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

  async function handleLogin(e: Event) {
    e.preventDefault()
    loading = true
    flow.updateField('error', null)

    try {
      await flow.loginToSource(handleInput, passwordInput, flow.state.twoFactorCode || undefined)
      const username = flow.state.sourceHandle.split('.')[0]
      handleInput = username
      flow.updateField('targetPassword', passwordInput)

      if (flow.state.progress.repoImported) {
        if (!localPasswordInput) {
          flow.setError('Please enter your password for your new account on this PDS')
          return
        }
        await flow.loadLocalServerInfo()

        try {
          await flow.authenticateToLocal(flow.state.targetEmail, localPasswordInput)
          await flow.requestPlcToken()
          flow.setStep('plc-token')
        } catch (err) {
          const error = err as Error & { error?: string }
          if (error.error === 'AccountNotVerified') {
            flow.setStep('email-verify')
          } else {
            throw err
          }
        }
      } else {
        flow.setStep('choose-handle')
      }
    } catch (err) {
      flow.setError((err as Error).message)
    } finally {
      loading = false
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
      flow.setError((err as Error).message)
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
      flow.setError((err as Error).message)
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
      flow.setError((err as Error).message)
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
      flow.setError((err as Error).message)
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
      flow.setError((err as Error).message)
    } finally {
      loading = false
    }
  }

  const steps = ['Login', 'Handle', 'Review', 'Transfer', 'Verify Email', 'Verify PLC', 'Complete']
  function getCurrentStepIndex(): number {
    switch (flow.state.step) {
      case 'welcome':
      case 'source-login': return 0
      case 'choose-handle': return 1
      case 'review': return 2
      case 'migrating': return 3
      case 'email-verify': return 4
      case 'plc-token':
      case 'finalizing': return 5
      case 'success': return 6
      default: return 0
    }
  }
</script>

<div class="inbound-wizard">
  <div class="step-indicator">
    {#each steps as stepName, i}
      <div class="step" class:active={i === getCurrentStepIndex()} class:completed={i < getCurrentStepIndex()}>
        <div class="step-dot">{i < getCurrentStepIndex() ? '✓' : i + 1}</div>
        <span class="step-label">{stepName}</span>
      </div>
      {#if i < steps.length - 1}
        <div class="step-line" class:completed={i < getCurrentStepIndex()}></div>
      {/if}
    {/each}
  </div>

  {#if flow.state.error}
    <div class="message error">{flow.state.error}</div>
  {/if}

  {#if flow.state.step === 'welcome'}
    <div class="step-content">
      <h2>Migrate Your Account Here</h2>
      <p>This wizard will help you move your AT Protocol account from another PDS to this one.</p>

      <div class="info-box">
        <h3>What will happen:</h3>
        <ol>
          <li>Log in to your current PDS</li>
          <li>Choose your new handle on this server</li>
          <li>Your repository and blobs will be transferred</li>
          <li>Verify the migration via email</li>
          <li>Your identity will be updated to point here</li>
        </ol>
      </div>

      <div class="warning-box">
        <strong>Before you proceed:</strong>
        <ul>
          <li>You need access to the email registered with your current account</li>
          <li>Large accounts may take several minutes to transfer</li>
          <li>Your old account will be deactivated after migration</li>
        </ul>
      </div>

      <label class="checkbox-label">
        <input type="checkbox" bind:checked={understood} />
        <span>I understand the risks and want to proceed with migration</span>
      </label>

      <div class="button-row">
        <button class="ghost" onclick={onBack}>Cancel</button>
        <button disabled={!understood} onclick={() => flow.setStep('source-login')}>
          Continue
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'source-login'}
    <div class="step-content">
      <h2>{isResumedMigration ? 'Resume Migration' : 'Log In to Your Current PDS'}</h2>
      <p>{isResumedMigration ? 'Enter your credentials to continue the migration.' : 'Enter your credentials for the account you want to migrate.'}</p>

      {#if isResumedMigration}
        <div class="info-box">
          <p>Your migration was interrupted. Log in to both accounts to resume.</p>
          <p class="hint" style="margin-top: 8px;">Migrating: <strong>{flow.state.sourceHandle}</strong> → <strong>{flow.state.targetHandle}</strong></p>
        </div>
      {/if}

      <form onsubmit={handleLogin}>
        <div class="field">
          <label for="handle">{isResumedMigration ? 'Old Account Handle' : 'Handle'}</label>
          <input
            id="handle"
            type="text"
            placeholder="alice.bsky.social"
            bind:value={handleInput}
            disabled={loading}
            required
          />
          <p class="hint">Your current handle on your existing PDS</p>
        </div>

        <div class="field">
          <label for="password">{isResumedMigration ? 'Old Account Password' : 'Password'}</label>
          <input
            id="password"
            type="password"
            bind:value={passwordInput}
            disabled={loading}
            required
          />
          <p class="hint">Your account password (not an app password)</p>
        </div>

        {#if flow.state.requires2FA}
          <div class="field">
            <label for="2fa">Two-Factor Code</label>
            <input
              id="2fa"
              type="text"
              placeholder="Enter code from email"
              bind:value={flow.state.twoFactorCode}
              disabled={loading}
              required
            />
            <p class="hint">Check your email for the verification code</p>
          </div>
        {/if}

        {#if isResumedMigration}
          <hr style="margin: 24px 0; border: none; border-top: 1px solid var(--border);" />

          <div class="field">
            <label for="local-password">New Account Password</label>
            <input
              id="local-password"
              type="password"
              placeholder="Password for your new account"
              bind:value={localPasswordInput}
              disabled={loading}
              required
            />
            <p class="hint">The password you set for your account on this PDS</p>
          </div>
        {/if}

        <div class="button-row">
          <button type="button" class="ghost" onclick={onBack} disabled={loading}>Back</button>
          <button type="submit" disabled={loading}>
            {loading ? 'Logging in...' : (isResumedMigration ? 'Continue Migration' : 'Log In')}
          </button>
        </div>
      </form>
    </div>

  {:else if flow.state.step === 'choose-handle'}
    <div class="step-content">
      <h2>Choose Your New Handle</h2>
      <p>Select a handle for your account on this PDS.</p>

      <div class="current-info">
        <span class="label">Migrating from:</span>
        <span class="value">{flow.state.sourceHandle}</span>
      </div>

      <div class="field">
        <label for="new-handle">New Handle</label>
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
          <p class="hint">Checking availability...</p>
        {:else if handleAvailable === true}
          <p class="hint success">Handle is available!</p>
        {:else if handleAvailable === false}
          <p class="hint error">Handle is already taken</p>
        {:else}
          <p class="hint">You can also use your own domain by entering the full handle (e.g., alice.mydomain.com)</p>
        {/if}
      </div>

      <div class="field">
        <label for="email">Email Address</label>
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
        <label for="new-password">Password</label>
        <input
          id="new-password"
          type="password"
          placeholder="Password for your new account"
          bind:value={flow.state.targetPassword}
          oninput={(e) => flow.updateField('targetPassword', (e.target as HTMLInputElement).value)}
          required
          minlength="8"
        />
        <p class="hint">At least 8 characters</p>
      </div>

      {#if serverInfo?.inviteCodeRequired}
        <div class="field">
          <label for="invite">Invite Code</label>
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
        <button class="ghost" onclick={() => flow.setStep('source-login')}>Back</button>
        <button
                   disabled={!handleInput.trim() || !flow.state.targetEmail || !flow.state.targetPassword || handleAvailable === false}
          onclick={proceedToReview}
        >
          Continue
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'review'}
    <div class="step-content">
      <h2>Review Migration</h2>
      <p>Please confirm the details of your migration.</p>

      <div class="review-card">
        <div class="review-row">
          <span class="label">Current Handle:</span>
          <span class="value">{flow.state.sourceHandle}</span>
        </div>
        <div class="review-row">
          <span class="label">New Handle:</span>
          <span class="value">{flow.state.targetHandle}</span>
        </div>
        <div class="review-row">
          <span class="label">DID:</span>
          <span class="value mono">{flow.state.sourceDid}</span>
        </div>
        <div class="review-row">
          <span class="label">From PDS:</span>
          <span class="value">{flow.state.sourcePdsUrl}</span>
        </div>
        <div class="review-row">
          <span class="label">To PDS:</span>
          <span class="value">{window.location.origin}</span>
        </div>
        <div class="review-row">
          <span class="label">Email:</span>
          <span class="value">{flow.state.targetEmail}</span>
        </div>
      </div>

      <div class="warning-box">
        <strong>Final confirmation:</strong> After you click "Start Migration", your repository and data will begin
        transferring. This process cannot be easily undone.
      </div>

      <div class="button-row">
        <button class="ghost" onclick={() => flow.setStep('choose-handle')} disabled={loading}>Back</button>
        <button onclick={startMigration} disabled={loading}>
          {loading ? 'Starting...' : 'Start Migration'}
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'migrating'}
    <div class="step-content">
      <h2>Migration in Progress</h2>
      <p>Please wait while your account is being transferred...</p>

      <div class="progress-section">
        <div class="progress-item" class:completed={flow.state.progress.repoExported}>
          <span class="icon">{flow.state.progress.repoExported ? '✓' : '○'}</span>
          <span>Export repository</span>
        </div>
        <div class="progress-item" class:completed={flow.state.progress.repoImported}>
          <span class="icon">{flow.state.progress.repoImported ? '✓' : '○'}</span>
          <span>Import repository</span>
        </div>
        <div class="progress-item" class:active={flow.state.progress.repoImported && !flow.state.progress.prefsMigrated}>
          <span class="icon">{flow.state.progress.blobsMigrated === flow.state.progress.blobsTotal && flow.state.progress.blobsTotal > 0 ? '✓' : '○'}</span>
          <span>Migrate blobs ({flow.state.progress.blobsMigrated}/{flow.state.progress.blobsTotal})</span>
        </div>
        <div class="progress-item" class:completed={flow.state.progress.prefsMigrated}>
          <span class="icon">{flow.state.progress.prefsMigrated ? '✓' : '○'}</span>
          <span>Migrate preferences</span>
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
        <div class="error-box">
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
      <h2>Verify Migration</h2>
      <p>A verification code has been sent to the email registered with your old account.</p>

      <div class="info-box">
        <p>
          This code confirms you have access to the account and authorizes updating your identity
          to point to this PDS.
        </p>
      </div>

      <form onsubmit={submitPlcToken}>
        <div class="field">
          <label for="plc-token">Verification Code</label>
          <input
            id="plc-token"
            type="text"
            placeholder="Enter code from email"
            bind:value={flow.state.plcToken}
            oninput={(e) => flow.updateField('plcToken', (e.target as HTMLInputElement).value)}
            disabled={loading}
            required
          />
        </div>

        <div class="button-row">
          <button type="button" class="ghost" onclick={resendToken} disabled={loading}>
            Resend Code
          </button>
          <button type="submit" disabled={loading || !flow.state.plcToken}>
            {loading ? 'Verifying...' : 'Complete Migration'}
          </button>
        </div>
      </form>
    </div>

  {:else if flow.state.step === 'finalizing'}
    <div class="step-content">
      <h2>Finalizing Migration</h2>
      <p>Please wait while we complete the migration...</p>

      <div class="progress-section">
        <div class="progress-item" class:completed={flow.state.progress.plcSigned}>
          <span class="icon">{flow.state.progress.plcSigned ? '✓' : '○'}</span>
          <span>Sign identity update</span>
        </div>
        <div class="progress-item" class:completed={flow.state.progress.activated}>
          <span class="icon">{flow.state.progress.activated ? '✓' : '○'}</span>
          <span>Activate new account</span>
        </div>
        <div class="progress-item" class:completed={flow.state.progress.deactivated}>
          <span class="icon">{flow.state.progress.deactivated ? '✓' : '○'}</span>
          <span>Deactivate old account</span>
        </div>
      </div>

      <p class="status-text">{flow.state.progress.currentOperation}</p>
    </div>

  {:else if flow.state.step === 'success'}
    <div class="step-content success-content">
      <div class="success-icon">✓</div>
      <h2>Migration Complete!</h2>
      <p>Your account has been successfully migrated to this PDS.</p>

      <div class="success-details">
        <div class="detail-row">
          <span class="label">Your new handle:</span>
          <span class="value">{flow.state.targetHandle}</span>
        </div>
        <div class="detail-row">
          <span class="label">DID:</span>
          <span class="value mono">{flow.state.sourceDid}</span>
        </div>
      </div>

      {#if flow.state.progress.blobsFailed.length > 0}
        <div class="warning-box">
          <strong>Note:</strong> {flow.state.progress.blobsFailed.length} blobs could not be migrated.
          These may be images or other media that are no longer available.
        </div>
      {/if}

      <p class="redirect-text">Redirecting to dashboard...</p>
    </div>

  {:else if flow.state.step === 'error'}
    <div class="step-content">
      <h2>Migration Error</h2>
      <p>An error occurred during migration.</p>

      <div class="error-box">
        {flow.state.error}
      </div>

      <div class="button-row">
        <button class="ghost" onclick={onBack}>Start Over</button>
      </div>
    </div>
  {/if}
</div>

<style>
  .inbound-wizard {
    max-width: 600px;
    margin: 0 auto;
  }

  .step-indicator {
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: var(--space-8);
    padding: 0 var(--space-4);
  }

  .step {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-2);
  }

  .step-dot {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    background: var(--bg-secondary);
    border: 2px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
    color: var(--text-secondary);
  }

  .step.active .step-dot {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--text-inverse);
  }

  .step.completed .step-dot {
    background: var(--success-bg);
    border-color: var(--success-text);
    color: var(--success-text);
  }

  .step-label {
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .step.active .step-label {
    color: var(--accent);
    font-weight: var(--font-medium);
  }

  .step-line {
    flex: 1;
    height: 2px;
    background: var(--border);
    margin: 0 var(--space-2);
    margin-bottom: var(--space-6);
    min-width: 20px;
  }

  .step-line.completed {
    background: var(--success-text);
  }

  .step-content {
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
    padding: var(--space-6);
  }

  .step-content h2 {
    margin: 0 0 var(--space-3) 0;
  }

  .step-content > p {
    color: var(--text-secondary);
    margin: 0 0 var(--space-5) 0;
  }

  .info-box {
    background: var(--accent-muted);
    border: 1px solid var(--accent);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
    margin-bottom: var(--space-5);
  }

  .info-box h3 {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-base);
  }

  .info-box ol, .info-box ul {
    margin: 0;
    padding-left: var(--space-5);
  }

  .info-box li {
    margin-bottom: var(--space-2);
    color: var(--text-secondary);
  }

  .info-box p {
    margin: 0;
    color: var(--text-secondary);
  }

  .warning-box {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
    margin-bottom: var(--space-5);
    font-size: var(--text-sm);
  }

  .warning-box strong {
    color: var(--warning-text);
  }

  .warning-box ul {
    margin: var(--space-3) 0 0 0;
    padding-left: var(--space-5);
  }

  .error-box {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
    margin-bottom: var(--space-5);
    color: var(--error-text);
  }

  .checkbox-label {
    display: inline-flex;
    align-items: flex-start;
    gap: var(--space-3);
    cursor: pointer;
    margin-bottom: var(--space-5);
    text-align: left;
  }

  .checkbox-label input[type="checkbox"] {
    width: 18px;
    height: 18px;
    margin: 0;
    flex-shrink: 0;
  }

  .button-row {
    display: flex;
    gap: var(--space-3);
    justify-content: flex-end;
    margin-top: var(--space-5);
  }

  .field {
    margin-bottom: var(--space-5);
  }

  .field label {
    display: block;
    margin-bottom: var(--space-2);
    font-weight: var(--font-medium);
  }

  .field input, .field select {
    width: 100%;
    padding: var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-primary);
    color: var(--text-primary);
  }

  .field input:focus, .field select:focus {
    outline: none;
    border-color: var(--accent);
  }

  .hint {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin: var(--space-2) 0 0 0;
  }

  .hint.success {
    color: var(--success-text);
  }

  .hint.error {
    color: var(--error-text);
  }

  .handle-input-group {
    display: flex;
    gap: var(--space-2);
  }

  .handle-input-group input {
    flex: 1;
  }

  .handle-input-group select {
    width: auto;
  }

  .current-info {
    background: var(--bg-primary);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    margin-bottom: var(--space-5);
    display: flex;
    justify-content: space-between;
  }

  .current-info .label {
    color: var(--text-secondary);
  }

  .current-info .value {
    font-weight: var(--font-medium);
  }

  .review-card {
    background: var(--bg-primary);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    margin-bottom: var(--space-5);
  }

  .review-row {
    display: flex;
    justify-content: space-between;
    padding: var(--space-3) 0;
    border-bottom: 1px solid var(--border);
  }

  .review-row:last-child {
    border-bottom: none;
  }

  .review-row .label {
    color: var(--text-secondary);
  }

  .review-row .value {
    font-weight: var(--font-medium);
    text-align: right;
    word-break: break-all;
  }

  .review-row .value.mono {
    font-family: var(--font-mono);
    font-size: var(--text-sm);
  }

  .progress-section {
    margin-bottom: var(--space-5);
  }

  .progress-item {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3) 0;
    color: var(--text-secondary);
  }

  .progress-item.completed {
    color: var(--success-text);
  }

  .progress-item.active {
    color: var(--accent);
  }

  .progress-item .icon {
    width: 24px;
    text-align: center;
  }

  .progress-bar {
    height: 8px;
    background: var(--bg-primary);
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: var(--space-4);
  }

  .progress-fill {
    height: 100%;
    background: var(--accent);
    transition: width 0.3s ease;
  }

  .status-text {
    text-align: center;
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  .success-content {
    text-align: center;
  }

  .success-icon {
    width: 64px;
    height: 64px;
    background: var(--success-bg);
    color: var(--success-text);
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: var(--text-2xl);
    margin: 0 auto var(--space-5) auto;
  }

  .success-details {
    background: var(--bg-primary);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    margin: var(--space-5) 0;
    text-align: left;
  }

  .success-details .detail-row {
    display: flex;
    justify-content: space-between;
    padding: var(--space-2) 0;
  }

  .success-details .label {
    color: var(--text-secondary);
  }

  .success-details .value {
    font-weight: var(--font-medium);
  }

  .success-details .value.mono {
    font-family: var(--font-mono);
    font-size: var(--text-sm);
  }

  .redirect-text {
    color: var(--text-secondary);
    font-style: italic;
  }

  .message.error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-text);
    padding: var(--space-4);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-5);
  }
</style>
