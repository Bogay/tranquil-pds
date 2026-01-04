<script lang="ts">
  import { setSession } from '../lib/auth.svelte'
  import { navigate, routes } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'
  import {
    createInboundMigrationFlow,
    createOfflineInboundMigrationFlow,
    hasPendingMigration,
    hasPendingOfflineMigration,
    getResumeInfo,
    getOfflineResumeInfo,
    clearMigrationState,
    clearOfflineState,
    loadMigrationState,
  } from '../lib/migration'
  import InboundWizard from '../components/migration/InboundWizard.svelte'
  import OfflineInboundWizard from '../components/migration/OfflineInboundWizard.svelte'

  type Direction = 'select' | 'inbound' | 'offline-inbound'
  let direction = $state<Direction>('select')
  let showResumeModal = $state(false)
  let resumeInfo = $state<ReturnType<typeof getResumeInfo>>(null)
  let oauthError = $state<string | null>(null)
  let oauthLoading = $state(false)

  let inboundFlow = $state<ReturnType<typeof createInboundMigrationFlow> | null>(null)
  let offlineFlow = $state<ReturnType<typeof createOfflineInboundMigrationFlow> | null>(null)
  let oauthCallbackProcessed = $state(false)

  $effect(() => {
    if (oauthCallbackProcessed) return

    const url = new URL(window.location.href)
    const code = url.searchParams.get('code')
    const state = url.searchParams.get('state')
    const errorParam = url.searchParams.get('error')
    const errorDescription = url.searchParams.get('error_description')

    if (errorParam) {
      oauthCallbackProcessed = true
      oauthError = errorDescription || errorParam
      window.history.replaceState({}, '', '/app/migrate')
      return
    }

    if (code && state) {
      oauthCallbackProcessed = true
      window.history.replaceState({}, '', '/app/migrate')
      direction = 'inbound'
      oauthLoading = true
      inboundFlow = createInboundMigrationFlow()

      const stored = loadMigrationState()
      if (stored && stored.direction === 'inbound') {
        inboundFlow.resumeFromState(stored)
      }

      inboundFlow.handleOAuthCallback(code, state)
        .then(() => {
          oauthLoading = false
        })
        .catch((e) => {
          oauthLoading = false
          oauthError = e.message || 'OAuth authentication failed'
          inboundFlow = null
          direction = 'select'
        })
      return
    }
  })

  const urlParams = new URLSearchParams(window.location.search)
  const hasOAuthCallback = urlParams.has('code') || urlParams.has('error')

  if (!hasOAuthCallback) {
    if (hasPendingMigration()) {
      resumeInfo = getResumeInfo()
      if (resumeInfo) {
        if (resumeInfo.step === 'success') {
          clearMigrationState()
          resumeInfo = null
        } else {
          const stored = loadMigrationState()
          if (stored && stored.direction === 'inbound') {
            direction = 'inbound'
            inboundFlow = createInboundMigrationFlow()
            inboundFlow.resumeFromState(stored)
          }
        }
      }
    } else if (hasPendingOfflineMigration()) {
      const offlineInfo = getOfflineResumeInfo()
      if (offlineInfo && offlineInfo.step === 'success') {
        clearOfflineState()
      } else {
        direction = 'offline-inbound'
        offlineFlow = createOfflineInboundMigrationFlow()
        offlineFlow.tryResume()
      }
    }
  }

  function selectInbound() {
    direction = 'inbound'
    inboundFlow = createInboundMigrationFlow()
  }

  function selectOfflineInbound() {
    direction = 'offline-inbound'
    offlineFlow = createOfflineInboundMigrationFlow()
  }

  function handleResume() {
    const stored = loadMigrationState()
    if (!stored) return

    showResumeModal = false

    if (stored.direction === 'inbound') {
      direction = 'inbound'
      inboundFlow = createInboundMigrationFlow()
      inboundFlow.resumeFromState(stored)
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
    if (offlineFlow) {
      offlineFlow.reset()
      offlineFlow = null
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
    navigate(routes.dashboard)
  }

  function handleOfflineComplete() {
    const session = offlineFlow?.getLocalSession()
    if (session) {
      setSession({
        did: session.did,
        handle: session.handle,
        accessJwt: session.accessJwt,
        refreshJwt: '',
      })
    }
    navigate(routes.dashboard)
  }
</script>

<div class="migration-page">
  {#if showResumeModal && resumeInfo}
    <div class="modal-overlay">
      <div class="modal">
        <h2>{$_('migration.resume.title')}</h2>
        <p>{$_('migration.resume.incomplete')}</p>
        <div class="resume-details">
          <div class="detail-row">
            <span class="label">{$_('migration.resume.direction')}:</span>
            <span class="value">{$_('migration.resume.migratingHere')}</span>
          </div>
          {#if resumeInfo.sourceHandle}
            <div class="detail-row">
              <span class="label">{$_('migration.resume.from')}:</span>
              <span class="value">{resumeInfo.sourceHandle}</span>
            </div>
          {/if}
          {#if resumeInfo.targetHandle}
            <div class="detail-row">
              <span class="label">{$_('migration.resume.to')}:</span>
              <span class="value">{resumeInfo.targetHandle}</span>
            </div>
          {/if}
          <div class="detail-row">
            <span class="label">{$_('migration.resume.progress')}:</span>
            <span class="value">{resumeInfo.progressSummary}</span>
          </div>
        </div>
        <p class="note">{$_('migration.resume.reenterCredentials')}</p>
        <div class="modal-actions">
          <button class="ghost" onclick={handleStartOver}>{$_('migration.resume.startOver')}</button>
          <button onclick={handleResume}>{$_('migration.resume.resumeButton')}</button>
        </div>
      </div>
    </div>
  {/if}

  {#if oauthLoading}
    <div class="oauth-loading">
      <div class="loading-spinner"></div>
      <p>{$_('migration.oauthCompleting')}</p>
    </div>
  {:else if oauthError}
    <div class="oauth-error">
      <h2>{$_('migration.oauthFailed')}</h2>
      <p>{oauthError}</p>
      <button onclick={() => { oauthError = null; direction = 'select' }}>{$_('migration.tryAgain')}</button>
    </div>
  {:else if direction === 'select'}
    <header class="page-header">
      <h1>{$_('migration.title')}</h1>
      <p class="subtitle">{$_('migration.subtitle')}</p>
    </header>

    <div class="direction-cards">
      <button class="direction-card ghost" onclick={selectInbound}>
        <h2>{$_('migration.migrateHere')}</h2>
        <p>{$_('migration.migrateHereDesc')}</p>
        <ul class="features">
          <li>{$_('migration.bringDid')}</li>
          <li>{$_('migration.transferData')}</li>
          <li>{$_('migration.keepFollowers')}</li>
        </ul>
      </button>

      <button class="direction-card ghost offline-card" onclick={selectOfflineInbound}>
        <h2>{$_('migration.offlineRestore')}</h2>
        <p>{$_('migration.offlineRestoreDesc')}</p>
        <ul class="features">
          <li>{$_('migration.offlineFeature1')}</li>
          <li>{$_('migration.offlineFeature2')}</li>
          <li>{$_('migration.offlineFeature3')}</li>
        </ul>
      </button>
    </div>

    <div class="info-section">
      <h3>{$_('migration.whatIsMigration')}</h3>
      <p>{$_('migration.whatIsMigrationDesc')}</p>

      <h3>{$_('migration.beforeMigrate')}</h3>
      <ul>
        <li>{$_('migration.beforeMigrate1')}</li>
        <li>{$_('migration.beforeMigrate2')}</li>
        <li>{$_('migration.beforeMigrate3')}</li>
        <li>{$_('migration.beforeMigrate4')}</li>
      </ul>

      <div class="warning-box">
        <strong>Important:</strong> {$_('migration.importantWarning')}
        <a href="https://github.com/bluesky-social/pds/blob/main/ACCOUNT_MIGRATION.md" target="_blank" rel="noopener">
          {$_('migration.learnMore')}
        </a>
      </div>
    </div>

  {:else if direction === 'inbound' && inboundFlow}
    <InboundWizard
      flow={inboundFlow}
      {resumeInfo}
      onBack={handleBack}
      onComplete={handleInboundComplete}
    />

  {:else if direction === 'offline-inbound' && offlineFlow}
    <OfflineInboundWizard
      flow={offlineFlow}
      onBack={handleBack}
      onComplete={handleOfflineComplete}
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
    display: flex;
    flex-direction: column;
    align-items: stretch;
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
    display: inline;
    margin-top: var(--space-2);
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

  .oauth-loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: var(--space-12);
    text-align: center;
  }

  .loading-spinner {
    width: 48px;
    height: 48px;
    border: 3px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin-bottom: var(--space-4);
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .oauth-loading p {
    color: var(--text-secondary);
    margin: 0;
  }

  .oauth-error {
    max-width: 500px;
    margin: 0 auto;
    text-align: center;
    padding: var(--space-8);
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: var(--radius-xl);
  }

  .oauth-error h2 {
    margin: 0 0 var(--space-4) 0;
    color: var(--error-text);
  }

  .oauth-error p {
    color: var(--text-secondary);
    margin: 0 0 var(--space-5) 0;
  }
</style>
