<script lang="ts">
  import type { OutboundMigrationFlow } from '../../lib/migration'
  import type { ServerDescription } from '../../lib/migration/types'
  import { getAuthState, logout } from '../../lib/auth.svelte'

  interface Props {
    flow: OutboundMigrationFlow
    onBack: () => void
    onComplete: () => void
  }

  let { flow, onBack, onComplete }: Props = $props()

  const auth = getAuthState()

  let loading = $state(false)
  let understood = $state(false)
  let pdsUrlInput = $state('')
  let handleInput = $state('')
  let selectedDomain = $state('')
  let confirmFinal = $state(false)

  $effect(() => {
    if (flow.state.step === 'success') {
      setTimeout(async () => {
        await logout()
        onComplete()
      }, 3000)
    }
  })

  $effect(() => {
    if (flow.state.targetServerInfo?.availableUserDomains?.length) {
      selectedDomain = flow.state.targetServerInfo.availableUserDomains[0]
    }
  })

  async function validatePds(e: Event) {
    e.preventDefault()
    loading = true
    flow.updateField('error', null)

    try {
      let url = pdsUrlInput.trim()
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = `https://${url}`
      }
      await flow.validateTargetPds(url)
      flow.setStep('new-account')
    } catch (err) {
      flow.setError((err as Error).message)
    } finally {
      loading = false
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
    if (!auth.session) return
    loading = true
    try {
      await flow.startMigration(auth.session.did)
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

  function isDidWeb(): boolean {
    return auth.session?.did?.startsWith('did:web:') ?? false
  }

  const steps = ['Target', 'Setup', 'Review', 'Transfer', 'Verify', 'Complete']
  function getCurrentStepIndex(): number {
    switch (flow.state.step) {
      case 'welcome': return -1
      case 'target-pds': return 0
      case 'new-account': return 1
      case 'review': return 2
      case 'migrating': return 3
      case 'plc-token':
      case 'finalizing': return 4
      case 'success': return 5
      default: return 0
    }
  }
</script>

<div class="outbound-wizard">
  {#if flow.state.step !== 'welcome'}
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
  {/if}

  {#if flow.state.error}
    <div class="message error">{flow.state.error}</div>
  {/if}

  {#if flow.state.step === 'welcome'}
    <div class="step-content">
      <h2>Migrate Your Account Away</h2>
      <p>This wizard will help you move your AT Protocol account from this PDS to another one.</p>

      <div class="current-account">
        <span class="label">Current account:</span>
        <span class="value">@{auth.session?.handle}</span>
      </div>

      {#if isDidWeb()}
        <div class="warning-box">
          <strong>did:web Migration Notice</strong>
          <p>
            Your account uses a did:web identifier ({auth.session?.did}). After migrating, this PDS will
            continue serving your DID document with an updated service endpoint pointing to your new PDS.
          </p>
          <p>
            You can return here anytime to update the forwarding if you migrate again in the future.
          </p>
        </div>
      {/if}

      <div class="info-box">
        <h3>What will happen:</h3>
        <ol>
          <li>Choose your new PDS</li>
          <li>Set up your account on the new server</li>
          <li>Your repository and blobs will be transferred</li>
          <li>Verify the migration via email</li>
          <li>Your identity will be updated to point to the new PDS</li>
          <li>Your account here will be deactivated</li>
        </ol>
      </div>

      <div class="warning-box">
        <strong>Before you proceed:</strong>
        <ul>
          <li>You need access to the email registered with this account</li>
          <li>You will lose access to this account on this PDS</li>
          <li>Make sure you trust the destination PDS</li>
          <li>Large accounts may take several minutes to transfer</li>
        </ul>
      </div>

      <label class="checkbox-label">
        <input type="checkbox" bind:checked={understood} />
        <span>I understand that my account will be moved and deactivated here</span>
      </label>

      <div class="button-row">
        <button class="ghost" onclick={onBack}>Cancel</button>
        <button disabled={!understood} onclick={() => flow.setStep('target-pds')}>
          Continue
        </button>
      </div>
    </div>

  {:else if flow.state.step === 'target-pds'}
    <div class="step-content">
      <h2>Choose Your New PDS</h2>
      <p>Enter the URL of the PDS you want to migrate to.</p>

      <form onsubmit={validatePds}>
        <div class="field">
          <label for="pds-url">PDS URL</label>
          <input
            id="pds-url"
            type="text"
            placeholder="pds.example.com"
            bind:value={pdsUrlInput}
            disabled={loading}
            required
          />
          <p class="hint">The server address of your new PDS (e.g., bsky.social, pds.example.com)</p>
        </div>

        <div class="button-row">
          <button type="button" class="ghost" onclick={() => flow.setStep('welcome')} disabled={loading}>Back</button>
          <button type="submit" disabled={loading || !pdsUrlInput.trim()}>
            {loading ? 'Checking...' : 'Connect'}
          </button>
        </div>
      </form>

      {#if flow.state.targetServerInfo}
        <div class="server-info">
          <h3>Connected to PDS</h3>
          <div class="info-row">
            <span class="label">Server:</span>
            <span class="value">{flow.state.targetPdsUrl}</span>
          </div>
          {#if flow.state.targetServerInfo.availableUserDomains.length > 0}
            <div class="info-row">
              <span class="label">Available domains:</span>
              <span class="value">{flow.state.targetServerInfo.availableUserDomains.join(', ')}</span>
            </div>
          {/if}
          <div class="info-row">
            <span class="label">Invite required:</span>
            <span class="value">{flow.state.targetServerInfo.inviteCodeRequired ? 'Yes' : 'No'}</span>
          </div>
          {#if flow.state.targetServerInfo.links?.termsOfService}
            <a href={flow.state.targetServerInfo.links.termsOfService} target="_blank" rel="noopener">
              Terms of Service
            </a>
          {/if}
          {#if flow.state.targetServerInfo.links?.privacyPolicy}
            <a href={flow.state.targetServerInfo.links.privacyPolicy} target="_blank" rel="noopener">
              Privacy Policy
            </a>
          {/if}
        </div>
      {/if}
    </div>

  {:else if flow.state.step === 'new-account'}
    <div class="step-content">
      <h2>Set Up Your New Account</h2>
      <p>Configure your account details on the new PDS.</p>

      <div class="current-info">
        <span class="label">Migrating to:</span>
        <span class="value">{flow.state.targetPdsUrl}</span>
      </div>

      <div class="field">
        <label for="new-handle">New Handle</label>
        <div class="handle-input-group">
          <input
            id="new-handle"
            type="text"
            placeholder="username"
            bind:value={handleInput}
          />
          {#if flow.state.targetServerInfo && flow.state.targetServerInfo.availableUserDomains.length > 0 && !handleInput.includes('.')}
            <select bind:value={selectedDomain}>
              {#each flow.state.targetServerInfo.availableUserDomains as domain}
                <option value={domain}>.{domain}</option>
              {/each}
            </select>
          {/if}
        </div>
        <p class="hint">You can also use your own domain by entering the full handle (e.g., alice.mydomain.com)</p>
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
        <p class="hint">At least 8 characters. This will be your password on the new PDS.</p>
      </div>

      {#if flow.state.targetServerInfo?.inviteCodeRequired}
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
          <p class="hint">Required by this PDS to create an account</p>
        </div>
      {/if}

      <div class="button-row">
        <button class="ghost" onclick={() => flow.setStep('target-pds')}>Back</button>
        <button
                    disabled={!handleInput.trim() || !flow.state.targetEmail || !flow.state.targetPassword}
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
          <span class="value">@{auth.session?.handle}</span>
        </div>
        <div class="review-row">
          <span class="label">New Handle:</span>
          <span class="value">@{flow.state.targetHandle}</span>
        </div>
        <div class="review-row">
          <span class="label">DID:</span>
          <span class="value mono">{auth.session?.did}</span>
        </div>
        <div class="review-row">
          <span class="label">From PDS:</span>
          <span class="value">{window.location.origin}</span>
        </div>
        <div class="review-row">
          <span class="label">To PDS:</span>
          <span class="value">{flow.state.targetPdsUrl}</span>
        </div>
        <div class="review-row">
          <span class="label">New Email:</span>
          <span class="value">{flow.state.targetEmail}</span>
        </div>
      </div>

      <div class="warning-box final-warning">
        <strong>This action cannot be easily undone!</strong>
        <p>
          After migration completes, your account on this PDS will be deactivated.
          To return, you would need to migrate back from the new PDS.
        </p>
      </div>

      <label class="checkbox-label">
        <input type="checkbox" bind:checked={confirmFinal} />
        <span>I confirm I want to migrate my account to {flow.state.targetPdsUrl}</span>
      </label>

      <div class="button-row">
        <button class="ghost" onclick={() => flow.setStep('new-account')} disabled={loading}>Back</button>
        <button class="danger" onclick={startMigration} disabled={loading || !confirmFinal}>
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
          <span>Import repository to new PDS</span>
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

  {:else if flow.state.step === 'plc-token'}
    <div class="step-content">
      <h2>Verify Migration</h2>
      <p>A verification code has been sent to your email ({auth.session?.email}).</p>

      <div class="info-box">
        <p>
          This code confirms you have access to the account and authorizes updating your identity
          to point to the new PDS.
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
          <span>Activate account on new PDS</span>
        </div>
        <div class="progress-item" class:completed={flow.state.progress.deactivated}>
          <span class="icon">{flow.state.progress.deactivated ? '✓' : '○'}</span>
          <span>Deactivate account here</span>
        </div>
      </div>

      <p class="status-text">{flow.state.progress.currentOperation}</p>
    </div>

  {:else if flow.state.step === 'success'}
    <div class="step-content success-content">
      <div class="success-icon">✓</div>
      <h2>Migration Complete!</h2>
      <p>Your account has been successfully migrated to your new PDS.</p>

      <div class="success-details">
        <div class="detail-row">
          <span class="label">Your new handle:</span>
          <span class="value">@{flow.state.targetHandle}</span>
        </div>
        <div class="detail-row">
          <span class="label">New PDS:</span>
          <span class="value">{flow.state.targetPdsUrl}</span>
        </div>
        <div class="detail-row">
          <span class="label">DID:</span>
          <span class="value mono">{auth.session?.did}</span>
        </div>
      </div>

      {#if flow.state.progress.blobsFailed.length > 0}
        <div class="warning-box">
          <strong>Note:</strong> {flow.state.progress.blobsFailed.length} blobs could not be migrated.
          These may be images or other media that are no longer available.
        </div>
      {/if}

      <div class="next-steps">
        <h3>Next Steps</h3>
        <ol>
          <li>Visit your new PDS at <a href={flow.state.targetPdsUrl} target="_blank" rel="noopener">{flow.state.targetPdsUrl}</a></li>
          <li>Log in with your new credentials</li>
          <li>Your followers and following will continue to work</li>
        </ol>
      </div>

      <p class="redirect-text">Logging out in a moment...</p>
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
  .outbound-wizard {
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

  .current-account {
    background: var(--bg-primary);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    margin-bottom: var(--space-5);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .current-account .label {
    color: var(--text-secondary);
  }

  .current-account .value {
    font-weight: var(--font-medium);
    font-size: var(--text-lg);
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

  .warning-box p {
    margin: var(--space-3) 0 0 0;
    color: var(--text-secondary);
  }

  .warning-box ul {
    margin: var(--space-3) 0 0 0;
    padding-left: var(--space-5);
  }

  .final-warning {
    background: var(--error-bg);
    border-color: var(--error-border);
  }

  .final-warning strong {
    color: var(--error-text);
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

  .server-info {
    background: var(--bg-primary);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    margin-top: var(--space-5);
  }

  .server-info h3 {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-base);
    color: var(--success-text);
  }

  .server-info .info-row {
    display: flex;
    justify-content: space-between;
    padding: var(--space-2) 0;
    font-size: var(--text-sm);
  }

  .server-info .label {
    color: var(--text-secondary);
  }

  .server-info a {
    display: inline-block;
    margin-top: var(--space-2);
    margin-right: var(--space-3);
    color: var(--accent);
    font-size: var(--text-sm);
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

  .next-steps {
    background: var(--accent-muted);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
    margin: var(--space-5) 0;
    text-align: left;
  }

  .next-steps h3 {
    margin: 0 0 var(--space-3) 0;
  }

  .next-steps ol {
    margin: 0;
    padding-left: var(--space-5);
  }

  .next-steps li {
    margin-bottom: var(--space-2);
  }

  .next-steps a {
    color: var(--accent);
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
