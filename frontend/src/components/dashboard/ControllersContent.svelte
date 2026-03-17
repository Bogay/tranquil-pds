<script lang="ts">
  import { onMount, onDestroy } from 'svelte'
  import { _ } from '../../lib/i18n'
  import { api } from '../../lib/api'
  import { toast } from '../../lib/toast.svelte'
  import { formatDateTime } from '../../lib/date'
  import type { Session, DelegationController, DelegationControlledAccount, DelegationScopePreset, DelegationAuditEntry } from '../../lib/types/api'
  import { unsafeAsDid, unsafeAsScopeSet, unsafeAsHandle, unsafeAsEmail } from '../../lib/types/branded'
  import type { Did, Handle, ScopeSet } from '../../lib/types/branded'
  import LoadMoreSentinel from '../LoadMoreSentinel.svelte'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  interface Controller {
    did: Did
    handle?: Handle
    grantedScopes: ScopeSet
    grantedAt: string
    isActive: boolean
    isLocal: boolean
  }

  interface ControlledAccount {
    did: Did
    handle: Handle
    grantedScopes: ScopeSet
    grantedAt: string
  }

  interface ScopePreset {
    name: string
    label: string
    description: string
    scopes: ScopeSet
  }

  let loading = $state(true)
  let controllers = $state<Controller[]>([])
  let controlledAccounts = $state<ControlledAccount[]>([])
  let scopePresets = $state<ScopePreset[]>([])

  let hasControllers = $derived(controllers.length > 0)
  let controlsAccounts = $derived(controlledAccounts.length > 0)
  let canAddControllers = $derived(!controlsAccounts)
  let canControlAccounts = $derived(!hasControllers)

  let showAddController = $state(false)
  let addControllerIdentifier = $state('')
  let addControllerScopes = $state('atproto')
  let addingController = $state(false)
  let addControllerConfirmed = $state(false)
  let resolvedController = $state<{ did: string; handle?: string; pdsUrl?: string; isLocal: boolean } | null>(null)
  let resolving = $state(false)
  let resolveError = $state('')

  let typeaheadResults = $state<Array<{ did: string; handle: string; displayName?: string; avatar?: string }>>([])
  let typeaheadTimeout: ReturnType<typeof setTimeout> | null = null
  let showTypeahead = $state(false)

  function onControllerInput(value: string) {
    addControllerIdentifier = value
    resolvedController = null
    resolveError = ''

    if (typeaheadTimeout) clearTimeout(typeaheadTimeout)

    const trimmed = value.trim().replace(/^@/, '')
    if (trimmed.startsWith('did:') || trimmed.length < 2) {
      typeaheadResults = []
      showTypeahead = false
      return
    }

    typeaheadTimeout = setTimeout(async () => {
      const resp = await fetch(
        `https://public.api.bsky.app/xrpc/app.bsky.actor.searchActorsTypeahead?q=${encodeURIComponent(trimmed)}&limit=5`
      )
      if (resp.ok) {
        const data = await resp.json()
        typeaheadResults = (data.actors ?? []).map((a: Record<string, unknown>) => ({
          did: a.did as string,
          handle: a.handle as string,
          displayName: a.displayName as string | undefined,
          avatar: a.avatar as string | undefined,
        }))
        showTypeahead = typeaheadResults.length > 0
      }
    }, 200)
  }

  function selectTypeahead(actor: { did: string; handle: string }) {
    addControllerIdentifier = actor.handle
    showTypeahead = false
    typeaheadResults = []
    resolveControllerIdentifier()
  }

  async function resolveControllerIdentifier() {
    const identifier = addControllerIdentifier.trim().replace(/^@/, '')
    if (!identifier) return

    resolving = true
    resolveError = ''
    resolvedController = null

    const result = await api.resolveController(identifier)
    if (result.ok) {
      resolvedController = result.value
    } else {
      resolveError = $_('delegation.controllerNotFound')
    }
    resolving = false
  }

  let showCreateDelegated = $state(false)
  let newDelegatedHandle = $state('')
  let newDelegatedEmail = $state('')
  let newDelegatedScopes = $state('atproto')
  let creatingDelegated = $state(false)

  onMount(async () => {
    await Promise.all([loadData(), loadAuditLog()])
    pollInterval = setInterval(pollAuditLog, 15_000)
  })

  async function loadData() {
    loading = true
    await Promise.all([loadControllers(), loadControlledAccounts(), loadScopePresets()])
    loading = false
  }

  async function loadControllers() {
    const result = await api.listDelegationControllers(session.accessJwt)
    if (result.ok) {
      controllers = (result.value.controllers ?? []).map((c: DelegationController) => ({
        did: c.did,
        handle: c.handle,
        grantedScopes: c.grantedScopes,
        grantedAt: c.grantedAt,
        isActive: c.isActive,
        isLocal: c.isLocal
      }))
    }
  }

  async function loadControlledAccounts() {
    const result = await api.listDelegationControlledAccounts(session.accessJwt)
    if (result.ok) {
      controlledAccounts = (result.value.accounts ?? []).map((a: DelegationControlledAccount) => ({
        did: a.did,
        handle: a.handle,
        grantedScopes: a.grantedScopes,
        grantedAt: a.grantedAt
      }))
    }
  }

  async function loadScopePresets() {
    const result = await api.getDelegationScopePresets()
    if (result.ok) {
      scopePresets = (result.value.presets ?? []).map((p: DelegationScopePreset) => ({
        name: p.name,
        label: p.name,
        description: p.description,
        scopes: unsafeAsScopeSet(p.scopes)
      }))
    }
  }

  async function addController() {
    if (!resolvedController) return
    addingController = true

    const controllerDid = unsafeAsDid(resolvedController.did)
    const scopes = unsafeAsScopeSet(addControllerScopes)
    const result = await api.addDelegationController(session.accessJwt, controllerDid, scopes)
    if (result.ok) {
      toast.success($_('delegation.controllerAdded'))
      addControllerIdentifier = ''
      addControllerScopes = 'atproto'
      addControllerConfirmed = false
      resolvedController = null
      showAddController = false
      await loadControllers()
    }
    addingController = false
  }

  async function removeController(controllerDid: Did) {
    if (!confirm($_('delegation.removeConfirm'))) return

    const result = await api.removeDelegationController(session.accessJwt, controllerDid)
    if (result.ok) {
      toast.success($_('delegation.controllerRemoved'))
      await loadControllers()
    }
  }

  async function createDelegatedAccount() {
    if (!newDelegatedHandle.trim()) return
    creatingDelegated = true

    const result = await api.createDelegatedAccount(
      session.accessJwt,
      unsafeAsHandle(newDelegatedHandle.trim()),
      newDelegatedEmail.trim() ? unsafeAsEmail(newDelegatedEmail.trim()) : undefined,
      unsafeAsScopeSet(newDelegatedScopes)
    )
    if (result.ok) {
      toast.success($_('delegation.accountCreated', { values: { handle: result.value.handle } }))
      newDelegatedHandle = ''
      newDelegatedEmail = ''
      newDelegatedScopes = 'atproto'
      showCreateDelegated = false
      await loadControlledAccounts()
    }
    creatingDelegated = false
  }

  function getScopeLabel(scopes: ScopeSet): string {
    const preset = scopePresets.find(p => p.scopes === scopes)
    if (preset) return preset.label
    if ((scopes as string) === 'atproto') return $_('delegation.scopeOwner')
    if ((scopes as string) === '') return $_('delegation.scopeViewer')
    return $_('delegation.scopeCustom')
  }

  interface AuditEntry {
    id: string
    delegatedDid: string
    actorDid: string
    actionType: string
    actionDetails: Record<string, unknown> | null
    createdAt: string
  }

  let auditLoading = $state(true)
  let auditLoadingMore = $state(false)
  let auditEntries = $state<AuditEntry[]>([])
  let auditHasMore = $state(true)
  let auditOffset = $state(0)
  const auditLimit = 20
  let pollInterval: ReturnType<typeof setInterval> | null = null

  onDestroy(() => {
    if (pollInterval) clearInterval(pollInterval)
  })

  async function loadAuditLog() {
    auditLoading = true
    auditOffset = 0
    try {
      const result = await api.getDelegationAuditLog(session.accessJwt, auditLimit, 0)
      if (result.ok && result.value) {
        const rawEntries = Array.isArray(result.value.entries) ? result.value.entries : []
        auditEntries = rawEntries.map(mapAuditEntry)
        const total = result.value.total ?? 0
        auditHasMore = auditEntries.length < total
        auditOffset = auditEntries.length
      } else {
        auditEntries = []
        auditHasMore = false
      }
    } catch {
      toast.error($_('delegation.failedToLoadAudit'))
      auditEntries = []
      auditHasMore = false
    } finally {
      auditLoading = false
    }
  }

  async function pollAuditLog() {
    try {
      const result = await api.getDelegationAuditLog(session.accessJwt, auditLimit, 0)
      if (result.ok && result.value) {
        const rawEntries = Array.isArray(result.value.entries) ? result.value.entries : []
        const latest = rawEntries.map(mapAuditEntry)
        if (latest.length > 0 && (auditEntries.length === 0 || latest[0].id !== auditEntries[0].id)) {
          auditEntries = latest
          const total = result.value.total ?? 0
          auditHasMore = auditEntries.length < total
          auditOffset = auditEntries.length
        }
      } else if (result.ok === false) {
        if (pollInterval) { clearInterval(pollInterval); pollInterval = null }
      }
    } catch {
      if (pollInterval) { clearInterval(pollInterval); pollInterval = null }
    }
  }

  async function loadMoreAuditEntries() {
    if (auditLoadingMore || !auditHasMore) return
    auditLoadingMore = true
    try {
      const result = await api.getDelegationAuditLog(session.accessJwt, auditLimit, auditOffset)
      if (result.ok && result.value) {
        const rawEntries = Array.isArray(result.value.entries) ? result.value.entries : []
        const newEntries = rawEntries.map(mapAuditEntry)
        auditEntries = [...auditEntries, ...newEntries]
        const total = result.value.total ?? 0
        auditHasMore = auditEntries.length < total
        auditOffset = auditEntries.length
      }
    } catch {
      toast.error($_('delegation.failedToLoadAudit'))
    } finally {
      auditLoadingMore = false
    }
  }

  function mapAuditEntry(e: DelegationAuditEntry): AuditEntry {
    const parsed: Record<string, unknown> | null = e.details
      ? (() => { try { return JSON.parse(e.details!) as Record<string, unknown> } catch { return null } })()
      : null
    return {
      id: e.id,
      delegatedDid: e.target_did ?? '',
      actorDid: e.actor_did,
      actionType: e.action,
      actionDetails: parsed,
      createdAt: e.created_at,
    }
  }

  function formatActionType(type: string): string {
    const labels: Record<string, string> = {
      'GrantCreated': $_('delegation.actionGrantCreated'),
      'GrantRevoked': $_('delegation.actionGrantRevoked'),
      'ScopesModified': $_('delegation.actionScopesModified'),
      'TokenIssued': $_('delegation.actionTokenIssued'),
      'RepoWrite': $_('delegation.actionRepoWrite'),
      'BlobUpload': $_('delegation.actionBlobUpload'),
      'AccountAction': $_('delegation.actionAccountAction'),
    }
    return labels[type] || type
  }

  function formatActionDetails(details: Record<string, unknown> | null): string {
    if (!details) return ''
    return Object.entries(details)
      .map(([key, value]) => `${key.replace(/_/g, ' ')}: ${JSON.stringify(value)}`)
      .join(', ')
  }

</script>

<div class="controllers">
  {#if loading}
    <div class="loading">{$_('common.loading')}</div>
  {:else}
    <section class="section">
      <div class="section-header">
        <h3>{$_('delegation.controllers')}</h3>
        <p class="section-description">{$_('delegation.controllersDesc')}</p>
      </div>

      {#if controllers.length === 0}
        <p class="empty">{$_('delegation.noControllers')}</p>
      {:else}
        <div class="items-list">
          {#each controllers as controller}
            <div class="item-card" class:inactive={!controller.isActive}>
              <div class="item-info">
                <div class="item-header">
                  <span class="item-handle">{controller.handle ? `@${controller.handle}` : controller.did}</span>
                  <span class="badge scope">{getScopeLabel(controller.grantedScopes)}</span>
                  {#if !controller.isActive}
                    <span class="badge inactive">{$_('delegation.inactive')}</span>
                  {/if}
                </div>
                <div class="item-details">
                  <div class="detail">
                    <span class="label">{$_('delegation.did')}</span>
                    <span class="value did">{controller.did}</span>
                  </div>
                  <div class="detail">
                    <span class="label">{$_('delegation.granted')}</span>
                    <span class="value">{formatDateTime(controller.grantedAt)}</span>
                  </div>
                </div>
              </div>
              <div class="item-actions">
                <button type="button" class="danger-outline" onclick={() => removeController(controller.did)}>
                  {$_('delegation.remove')}
                </button>
              </div>
            </div>
          {/each}
        </div>
      {/if}

      {#if !canAddControllers}
        <div class="constraint-notice">
          <p>{$_('delegation.cannotAddControllers')}</p>
        </div>
      {:else if showAddController}
        <div class="form-card">
          <h4>{$_('delegation.addController')}</h4>

          <div class="warning-box">
            <div class="warning-header">{$_('delegation.addControllerWarningTitle')}</div>
            <p class="warning-text">{$_('delegation.addControllerWarningText')}</p>
            <ul class="warning-bullets">
              <li>{$_('delegation.addControllerWarningBullet1')}</li>
              <li>{$_('delegation.addControllerWarningBullet2')}</li>
              <li>{$_('delegation.addControllerWarningBullet3')}</li>
            </ul>
          </div>

          <div class="field controller-search">
            <label for="controllerIdentifier">{$_('delegation.controllerIdentifier')}</label>
            <div class="search-wrapper">
              <input
                id="controllerIdentifier"
                type="text"
                value={addControllerIdentifier}
                oninput={(e) => onControllerInput((e.target as HTMLInputElement).value)}
                onblur={() => { setTimeout(() => { showTypeahead = false }, 200) }}
                onkeydown={(e) => { if (e.key === 'Enter') { e.preventDefault(); showTypeahead = false; resolveControllerIdentifier() } }}
                placeholder="handle or did:plc:..."
                disabled={addingController}
              />
              {#if showTypeahead && typeaheadResults.length > 0}
                <div class="typeahead-dropdown">
                  {#each typeaheadResults as actor}
                    <button type="button" class="typeahead-item" onmousedown={() => selectTypeahead(actor)}>
                      {#if actor.avatar}
                        <img src={actor.avatar} alt="" class="typeahead-avatar" />
                      {/if}
                      <div class="typeahead-text">
                        {#if actor.displayName}
                          <span class="typeahead-name">{actor.displayName}</span>
                        {/if}
                        <span class="typeahead-handle">@{actor.handle}</span>
                      </div>
                    </button>
                  {/each}
                </div>
              {/if}
            </div>
            {#if resolving}
              <span class="resolve-status">{$_('common.loading')}</span>
            {:else if resolveError}
              <span class="resolve-status error">{resolveError}</span>
            {:else if resolvedController}
              <div class="resolved-info">
                <span class="resolved-did">{resolvedController.did}</span>
                {#if resolvedController.handle}
                  <span class="resolved-handle">@{resolvedController.handle}</span>
                {/if}
                {#if !resolvedController.isLocal && resolvedController.pdsUrl}
                  <span class="badge external">{new URL(resolvedController.pdsUrl).hostname}</span>
                {/if}
              </div>
            {/if}
          </div>
          <div class="field">
            <label for="controllerScopes">{$_('delegation.accessLevel')}</label>
            <select id="controllerScopes" bind:value={addControllerScopes} disabled={addingController}>
              {#each scopePresets as preset}
                <option value={preset.scopes}>{preset.label} - {preset.description}</option>
              {/each}
            </select>
          </div>
          <label class="confirm-checkbox">
            <input type="checkbox" bind:checked={addControllerConfirmed} disabled={addingController} />
            <span>{$_('delegation.addControllerConfirm')}</span>
          </label>
          <div class="form-actions">
            <button type="button" class="ghost" onclick={() => { showAddController = false; addControllerConfirmed = false }} disabled={addingController}>
              {$_('common.cancel')}
            </button>
            <button type="button" onclick={addController} disabled={addingController || !resolvedController || !addControllerConfirmed}>
              {addingController ? $_('delegation.adding') : $_('delegation.addController')}
            </button>
          </div>
        </div>
      {:else}
        <button type="button" class="ghost full-width" onclick={() => showAddController = true}>
          {$_('delegation.addControllerButton')}
        </button>
      {/if}
    </section>

    <section class="section">
      <div class="section-header">
        <h3>{$_('delegation.controlledAccounts')}</h3>
        <p class="section-description">{$_('delegation.controlledAccountsDesc')}</p>
      </div>

      {#if controlledAccounts.length === 0}
        <p class="empty">{$_('delegation.noControlledAccounts')}</p>
      {:else}
        <div class="items-list">
          {#each controlledAccounts as account}
            <div class="item-card">
              <div class="item-info">
                <div class="item-header">
                  <span class="item-handle">@{account.handle}</span>
                  <span class="badge scope">{getScopeLabel(account.grantedScopes)}</span>
                </div>
                <div class="item-details">
                  <div class="detail">
                    <span class="label">{$_('delegation.did')}</span>
                    <span class="value did">{account.did}</span>
                  </div>
                  <div class="detail">
                    <span class="label">{$_('delegation.granted')}</span>
                    <span class="value">{formatDateTime(account.grantedAt)}</span>
                  </div>
                </div>
              </div>
              <div class="item-actions">
                <a href="/app/act-as?did={encodeURIComponent(account.did)}" class="btn-link">
                  {$_('delegation.actAs')}
                </a>
              </div>
            </div>
          {/each}
        </div>
      {/if}

      {#if !canControlAccounts}
        <div class="constraint-notice">
          <p>{$_('delegation.cannotControlAccounts')}</p>
        </div>
      {:else if showCreateDelegated}
        <div class="form-card">
          <h4>{$_('delegation.createDelegatedAccount')}</h4>
          <div class="field">
            <label for="delegatedHandle">{$_('delegation.handle')}</label>
            <input
              id="delegatedHandle"
              type="text"
              bind:value={newDelegatedHandle}
              placeholder="username"
              disabled={creatingDelegated}
            />
          </div>
          <div class="field">
            <label for="delegatedEmail">{$_('delegation.emailOptional')}</label>
            <input
              id="delegatedEmail"
              type="email"
              bind:value={newDelegatedEmail}
              placeholder="email@example.com"
              disabled={creatingDelegated}
            />
          </div>
          <div class="field">
            <label for="delegatedScopes">{$_('delegation.yourAccessLevel')}</label>
            <select id="delegatedScopes" bind:value={newDelegatedScopes} disabled={creatingDelegated}>
              {#each scopePresets as preset}
                <option value={preset.scopes}>{preset.label} - {preset.description}</option>
              {/each}
            </select>
          </div>
          <div class="form-actions">
            <button type="button" class="ghost" onclick={() => showCreateDelegated = false} disabled={creatingDelegated}>
              {$_('common.cancel')}
            </button>
            <button type="button" onclick={createDelegatedAccount} disabled={creatingDelegated || !newDelegatedHandle.trim()}>
              {creatingDelegated ? $_('common.creating') : $_('delegation.createAccount')}
            </button>
          </div>
        </div>
      {:else}
        <button type="button" class="ghost full-width" onclick={() => showCreateDelegated = true}>
          {$_('delegation.createDelegatedAccountButton')}
        </button>
      {/if}

      <div class="constraint-notice">
        <p>{$_('delegation.controlledAccountsLocalOnly')}</p>
      </div>
    </section>

    <section class="section">
      <div class="section-header">
        <h3>{$_('delegation.auditLog')}</h3>
        <p class="section-description">{$_('delegation.auditLogDesc')}</p>
      </div>

      {#if auditLoading}
        <div class="loading">{$_('common.loading')}</div>
      {:else if auditEntries.length === 0}
        <p class="empty">{$_('delegation.noAuditEntries')}</p>
      {:else}
        <div class="audit-entries">
          {#each auditEntries as entry}
            <div class="audit-entry">
              <div class="audit-entry-header">
                <span class="action-type">{formatActionType(entry.actionType)}</span>
                <span class="audit-entry-date">{formatDateTime(entry.createdAt)}</span>
              </div>
              <div class="audit-entry-details">
                <div class="detail">
                  <span class="label">{$_('delegation.actor')}</span>
                  <span class="value did">{entry.actorDid}</span>
                </div>
                {#if entry.delegatedDid}
                  <div class="detail">
                    <span class="label">{$_('delegation.target')}</span>
                    <span class="value did">{entry.delegatedDid}</span>
                  </div>
                {/if}
                {#if entry.actionDetails}
                  <div class="detail">
                    <span class="label">{$_('delegation.details')}</span>
                    <span class="value audit-details-value">{formatActionDetails(entry.actionDetails)}</span>
                  </div>
                {/if}
              </div>
            </div>
          {/each}
        </div>

        <LoadMoreSentinel hasMore={auditHasMore} loading={auditLoadingMore} onLoadMore={loadMoreAuditEntries} />
      {/if}
    </section>
  {/if}
</div>

<style>
  .controllers {
    max-width: var(--width-lg);
  }

  .loading,
  .empty {
    color: var(--text-secondary);
    padding: var(--space-4);
    text-align: center;
  }

  .section {
    background: var(--bg-secondary);
    padding: var(--space-5);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-5);
  }

  .section-header {
    margin-bottom: var(--space-4);
  }

  .section-header h3 {
    margin: 0 0 var(--space-1) 0;
    font-size: var(--text-base);
  }

  .section-description {
    color: var(--text-secondary);
    margin: 0;
    font-size: var(--text-sm);
  }

  .constraint-notice {
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: var(--space-4);
    margin-top: var(--space-4);
  }

  .constraint-notice p {
    margin: 0;
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  .items-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    margin-bottom: var(--space-4);
  }

  .item-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--space-4);
    flex-wrap: wrap;
  }

  .item-card.inactive {
    opacity: 0.6;
  }

  .item-info {
    flex: 1;
    min-width: 200px;
  }

  .item-header {
    margin-bottom: var(--space-2);
    display: flex;
    align-items: center;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  .item-handle {
    font-weight: var(--font-semibold);
    color: var(--text-primary);
  }

  .badge {
    display: inline-block;
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
    font-weight: var(--font-medium);
  }

  .badge.scope {
    background: var(--accent);
    color: var(--text-inverse);
  }

  .badge.inactive {
    background: var(--error-bg);
    color: var(--error-text);
    border: 1px solid var(--error-border);
  }

  .item-details {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .detail {
    font-size: var(--text-sm);
  }

  .detail .label {
    color: var(--text-secondary);
    margin-right: var(--space-2);
  }

  .detail .value {
    color: var(--text-primary);
  }

  .detail .value.did {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    word-break: break-all;
  }

  .item-actions {
    display: flex;
    gap: var(--space-2);
  }

  .btn-link {
    display: inline-block;
    padding: var(--space-2) var(--space-4);
    border: 1px solid var(--accent);
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--accent);
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
    text-decoration: none;
  }

  .btn-link:hover {
    background: var(--accent);
    color: var(--text-inverse);
  }

  .danger-outline {
    padding: var(--space-2) var(--space-4);
    border: 1px solid var(--error-text);
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--error-text);
    font-size: var(--text-sm);
    cursor: pointer;
  }

  .danger-outline:hover {
    background: var(--error-bg);
  }

  .ghost {
    background: transparent;
    border: 1px solid var(--border-color);
    color: var(--text-primary);
  }

  .ghost:hover {
    border-color: var(--accent);
  }

  .full-width {
    width: 100%;
  }

  .form-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
    margin-top: var(--space-4);
  }

  .form-card h4 {
    margin: 0 0 var(--space-4) 0;
    font-size: var(--text-base);
  }

  .warning-box {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius-md);
    padding: var(--space-4);
    margin-bottom: var(--space-5);
  }

  .warning-header {
    font-weight: var(--font-semibold);
    color: var(--warning-text);
    margin-bottom: var(--space-2);
  }

  .warning-text {
    margin: 0 0 var(--space-3) 0;
    color: var(--warning-text);
    font-size: var(--text-sm);
    line-height: 1.5;
  }

  .warning-bullets {
    margin: 0;
    padding-left: var(--space-5);
    color: var(--warning-text);
    font-size: var(--text-sm);
    line-height: 1.6;
  }

  .confirm-checkbox {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    cursor: pointer;
    padding: var(--space-3);
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-4);
  }

  .confirm-checkbox input {
    width: 18px;
    height: 18px;
    flex-shrink: 0;
    margin-top: 2px;
  }

  .confirm-checkbox span {
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
    color: var(--text-primary);
    line-height: 1.4;
  }

  .field {
    margin-bottom: var(--space-4);
  }

  .field label {
    display: block;
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
    margin-bottom: var(--space-1);
  }

  .field input,
  .field select {
    width: 100%;
  }

  .form-actions {
    display: flex;
    gap: var(--space-3);
    justify-content: flex-end;
  }

  .controller-search {
    position: relative;
  }

  .search-wrapper {
    position: relative;
  }

  .typeahead-dropdown {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    z-index: 10;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    max-height: 240px;
    overflow-y: auto;
  }

  .typeahead-item {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    width: 100%;
    padding: var(--space-2) var(--space-3);
    border: none;
    background: transparent;
    cursor: pointer;
    text-align: left;
    color: var(--text-primary);
  }

  .typeahead-item:hover {
    background: var(--bg-tertiary);
  }

  .typeahead-avatar {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .typeahead-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .typeahead-name {
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .typeahead-handle {
    font-size: var(--text-xs);
    color: var(--text-secondary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .resolve-status {
    display: block;
    font-size: var(--text-xs);
    color: var(--text-secondary);
    margin-top: var(--space-1);
  }

  .resolve-status.error {
    color: var(--error-text);
  }

  .resolved-info {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    flex-wrap: wrap;
    margin-top: var(--space-2);
    padding: var(--space-2) var(--space-3);
    background: var(--bg-tertiary);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
  }

  .resolved-did {
    font-family: var(--font-mono);
    color: var(--text-secondary);
    word-break: break-all;
  }

  .resolved-handle {
    color: var(--text-primary);
    font-weight: var(--font-medium);
  }

  .badge.external {
    background: var(--info-bg, var(--bg-tertiary));
    color: var(--info-text, var(--text-secondary));
    border: 1px solid var(--info-border, var(--border-color));
  }

  .audit-entries {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .audit-entry {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
  }

  .audit-entry-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--space-3);
  }

  .action-type {
    font-weight: var(--font-medium);
    padding: var(--space-1) var(--space-2);
    background: var(--accent);
    color: var(--text-inverse);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
  }

  .audit-entry-date {
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .audit-entry-details {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .audit-details-value {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    word-break: break-word;
  }

  @media (max-width: 600px) {
    .item-card {
      flex-direction: column;
      align-items: stretch;
    }

    .item-actions {
      width: 100%;
    }

    .item-actions button,
    .item-actions a {
      width: 100%;
      text-align: center;
    }

    .audit-entry-header {
      flex-direction: column;
      align-items: flex-start;
      gap: var(--space-2);
    }

    .audit-entry-details .value.did {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 60vw;
    }
  }
</style>
