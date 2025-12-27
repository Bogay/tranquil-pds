<script lang="ts">
  import { getAuthState, logout, setSession } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import {
    createInboundMigrationFlow,
    createOutboundMigrationFlow,
    hasPendingMigration,
    getResumeInfo,
    clearMigrationState,
    loadMigrationState,
  } from '../lib/migration'
  import InboundWizard from '../components/migration/InboundWizard.svelte'
  import OutboundWizard from '../components/migration/OutboundWizard.svelte'

  const auth = getAuthState()

  type Direction = 'select' | 'inbound' | 'outbound'
  let direction = $state<Direction>('select')
  let showResumeModal = $state(false)
  let resumeInfo = $state<ReturnType<typeof getResumeInfo>>(null)

  let inboundFlow = $state<ReturnType<typeof createInboundMigrationFlow> | null>(null)
  let outboundFlow = $state<ReturnType<typeof createOutboundMigrationFlow> | null>(null)

  if (hasPendingMigration()) {
    resumeInfo = getResumeInfo()
    if (resumeInfo) {
      showResumeModal = true
    }
  }

  function selectInbound() {
    direction = 'inbound'
    inboundFlow = createInboundMigrationFlow()
  }

  function selectOutbound() {
    if (!auth.session) {
      navigate('/login')
      return
    }
    direction = 'outbound'
    outboundFlow = createOutboundMigrationFlow()
    outboundFlow.initLocalClient(auth.session.accessJwt, auth.session.did, auth.session.handle)
  }

  function handleResume() {
    const stored = loadMigrationState()
    if (!stored) return

    showResumeModal = false

    if (stored.direction === 'inbound') {
      direction = 'inbound'
      inboundFlow = createInboundMigrationFlow()
      inboundFlow.resumeFromState(stored)
    } else {
      if (!auth.session) {
        navigate('/login')
        return
      }
      direction = 'outbound'
      outboundFlow = createOutboundMigrationFlow()
      outboundFlow.initLocalClient(auth.session.accessJwt, auth.session.did, auth.session.handle)
    }
  }

  function handleStartOver() {
    showResumeModal = false
    clearMigrationState()
    resumeInfo = null
  }

  function handleBack() {
    if (inboundFlow) {
      inboundFlow.reset()
      inboundFlow = null
    }
    if (outboundFlow) {
      outboundFlow.reset()
      outboundFlow = null
    }
    direction = 'select'
  }

  function handleInboundComplete() {
    const session = inboundFlow?.getLocalSession()
    if (session) {
      setSession({
        did: session.did,
        handle: session.handle,
        accessJwt: session.accessJwt,
        refreshJwt: '',
      })
    }
    navigate('/dashboard')
  }

  async function handleOutboundComplete() {
    await logout()
    navigate('/login')
  }
</script>

<div class="migration-page">
  {#if showResumeModal && resumeInfo}
    <div class="modal-overlay">
      <div class="modal">
        <h2>Resume Migration?</h2>
        <p>You have an incomplete migration in progress:</p>
        <div class="resume-details">
          <div class="detail-row">
            <span class="label">Direction:</span>
            <span class="value">{resumeInfo.direction === 'inbound' ? 'Migrating here' : 'Migrating away'}</span>
          </div>
          {#if resumeInfo.sourceHandle}
            <div class="detail-row">
              <span class="label">From:</span>
              <span class="value">{resumeInfo.sourceHandle}</span>
            </div>
          {/if}
          {#if resumeInfo.targetHandle}
            <div class="detail-row">
              <span class="label">To:</span>
              <span class="value">{resumeInfo.targetHandle}</span>
            </div>
          {/if}
          <div class="detail-row">
            <span class="label">Progress:</span>
            <span class="value">{resumeInfo.progressSummary}</span>
          </div>
        </div>
        <p class="note">You will need to re-enter your credentials to continue.</p>
        <div class="modal-actions">
          <button class="ghost" onclick={handleStartOver}>Start Over</button>
          <button onclick={handleResume}>Resume</button>
        </div>
      </div>
    </div>
  {/if}

  {#if direction === 'select'}
    <header class="page-header">
      <h1>Account Migration</h1>
      <p class="subtitle">Move your AT Protocol identity between servers</p>
    </header>

    <div class="direction-cards">
      <button class="direction-card ghost" onclick={selectInbound}>
        <div class="card-icon">↓</div>
        <h2>Migrate Here</h2>
        <p>Move your existing AT Protocol account to this PDS from another server.</p>
        <ul class="features">
          <li>Bring your DID and identity</li>
          <li>Transfer all your data</li>
          <li>Keep your followers</li>
        </ul>
      </button>

      <button class="direction-card ghost" onclick={selectOutbound} disabled={!auth.session}>
        <div class="card-icon">↑</div>
        <h2>Migrate Away</h2>
        <p>Move your account from this PDS to another server.</p>
        <ul class="features">
          <li>Export your repository</li>
          <li>Transfer to new PDS</li>
          <li>Update your identity</li>
        </ul>
        {#if !auth.session}
          <p class="login-required">Login required</p>
        {/if}
      </button>
    </div>

    <div class="info-section">
      <h3>What is account migration?</h3>
      <p>
        Account migration allows you to move your AT Protocol identity between Personal Data Servers (PDSes).
        Your DID (decentralized identifier) stays the same, so your followers and social connections are preserved.
      </p>

      <h3>Before you migrate</h3>
      <ul>
        <li>You will need your current account credentials</li>
        <li>Migration requires email verification for security</li>
        <li>Large accounts with many images may take several minutes</li>
        <li>Your old PDS will be notified to deactivate your account</li>
      </ul>

      <div class="warning-box">
        <strong>Important:</strong> Account migration is a significant action. Make sure you trust the destination PDS
        and understand that your data will be moved. If something goes wrong, recovery may require manual intervention.
        <a href="https://github.com/bluesky-social/pds/blob/main/ACCOUNT_MIGRATION.md" target="_blank" rel="noopener">
          Learn more about migration risks
        </a>
      </div>
    </div>

  {:else if direction === 'inbound' && inboundFlow}
    <InboundWizard
      flow={inboundFlow}
      onBack={handleBack}
      onComplete={handleInboundComplete}
    />

  {:else if direction === 'outbound' && outboundFlow}
    <OutboundWizard
      flow={outboundFlow}
      onBack={handleBack}
      onComplete={handleOutboundComplete}
    />
  {/if}
</div>

<style>
  .migration-page {
    max-width: var(--width-lg);
    margin: var(--space-9) auto;
    padding: var(--space-7);
  }

  .page-header {
    text-align: center;
    margin-bottom: var(--space-8);
  }

  .page-header h1 {
    margin: 0 0 var(--space-3) 0;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0;
    font-size: var(--text-lg);
  }

  .direction-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: var(--space-6);
    margin-bottom: var(--space-8);
  }

  .direction-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-xl);
    padding: var(--space-6);
    text-align: left;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .direction-card:hover:not(:disabled) {
    border-color: var(--accent);
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
  }

  .direction-card:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .card-icon {
    font-size: var(--text-3xl);
    margin-bottom: var(--space-4);
    color: var(--accent);
  }

  .direction-card h2 {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-xl);
    color: var(--text-primary);
  }

  .direction-card p {
    color: var(--text-secondary);
    margin: 0 0 var(--space-4) 0;
    font-size: var(--text-sm);
  }

  .features {
    margin: 0;
    padding-left: var(--space-5);
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  .features li {
    margin-bottom: var(--space-2);
  }

  .login-required {
    color: var(--warning-text);
    font-weight: var(--font-medium);
    margin-top: var(--space-4);
  }

  .info-section {
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
    padding: var(--space-6);
  }

  .info-section h3 {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-lg);
  }

  .info-section h3:not(:first-child) {
    margin-top: var(--space-6);
  }

  .info-section p {
    color: var(--text-secondary);
    line-height: var(--leading-relaxed);
    margin: 0;
  }

  .info-section ul {
    color: var(--text-secondary);
    padding-left: var(--space-5);
    margin: var(--space-3) 0 0 0;
  }

  .info-section li {
    margin-bottom: var(--space-2);
  }

  .warning-box {
    margin-top: var(--space-6);
    padding: var(--space-5);
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius-lg);
    font-size: var(--text-sm);
  }

  .warning-box strong {
    color: var(--warning-text);
  }

  .warning-box a {
    display: block;
    margin-top: var(--space-3);
    color: var(--accent);
  }

  .modal-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .modal {
    background: var(--bg-primary);
    border-radius: var(--radius-xl);
    padding: var(--space-6);
    max-width: 400px;
    width: 90%;
  }

  .modal h2 {
    margin: 0 0 var(--space-4) 0;
  }

  .modal p {
    color: var(--text-secondary);
    margin: 0 0 var(--space-4) 0;
  }

  .resume-details {
    background: var(--bg-secondary);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    margin-bottom: var(--space-4);
  }

  .detail-row {
    display: flex;
    justify-content: space-between;
    padding: var(--space-2) 0;
    font-size: var(--text-sm);
  }

  .detail-row:not(:last-child) {
    border-bottom: 1px solid var(--border);
  }

  .detail-row .label {
    color: var(--text-secondary);
  }

  .detail-row .value {
    font-weight: var(--font-medium);
  }

  .note {
    font-size: var(--text-sm);
    font-style: italic;
  }

  .modal-actions {
    display: flex;
    gap: var(--space-3);
    justify-content: flex-end;
  }
</style>
