<script lang="ts">
  import { setSession } from '../lib/auth.svelte'
  import { navigate, routes } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'
  import { api } from '../lib/api'
  import { startOAuthLogin } from '../lib/oauth'
  import { unsafeAsAccessToken } from '../lib/types/branded'
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
      const info = getResumeInfo()
      if (info) {
        if (info.step === 'success') {
          clearMigrationState()
        } else {
          resumeInfo = info
          const stored = loadMigrationState()
          if (stored && stored.direction === 'inbound') {
            direction = 'inbound'
            const flow = createInboundMigrationFlow()
            flow.resumeFromState(stored)
            inboundFlow = flow
          }
        }
      }
    } else if (hasPendingOfflineMigration()) {
      const offlineInfo = getOfflineResumeInfo()
      if (offlineInfo && offlineInfo.step === 'success') {
        clearOfflineState()
      } else {
        direction = 'offline-inbound'
        const flow = createOfflineInboundMigrationFlow()
        flow.tryResume()
        offlineFlow = flow
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

  async function handleInboundComplete() {
    const session = inboundFlow?.getLocalSession()
    if (session) {
      try {
        await api.establishOAuthSession(unsafeAsAccessToken(session.accessJwt))
        clearMigrationState()
        await startOAuthLogin(session.handle)
      } catch (e) {
        console.error('Failed to establish OAuth session, falling back to direct login:', e)
        setSession({
          did: session.did,
          handle: session.handle,
          accessJwt: session.accessJwt,
          refreshJwt: '',
        })
        navigate(routes.dashboard)
      }
    } else {
      navigate(routes.dashboard)
    }
  }

  async function handleOfflineComplete() {
    const session = offlineFlow?.getLocalSession()
    if (session) {
      try {
        await api.establishOAuthSession(unsafeAsAccessToken(session.accessJwt))
        clearOfflineState()
        await startOAuthLogin(session.handle)
      } catch (e) {
        console.error('Failed to establish OAuth session, falling back to direct login:', e)
        setSession({
          did: session.did,
          handle: session.handle,
          accessJwt: session.accessJwt,
          refreshJwt: '',
        })
        navigate(routes.dashboard)
      }
    } else {
      navigate(routes.dashboard)
    }
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
    <div class="loading">
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

