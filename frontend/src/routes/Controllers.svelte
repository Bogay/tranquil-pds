<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'
  import { formatDateTime } from '../lib/date'
  import type { Session } from '../lib/types/api'
  import { toast } from '../lib/toast.svelte'

  interface Controller {
    did: string
    handle: string
    grantedScopes: string
    grantedAt: string
    isActive: boolean
  }

  interface ControlledAccount {
    did: string
    handle: string
    grantedScopes: string
    grantedAt: string
  }

  interface ScopePreset {
    name: string
    label: string
    description: string
    scopes: string
  }

  const auth = $derived(getAuthState())

  function getSession(): Session | null {
    return auth.kind === 'authenticated' ? auth.session : null
  }

  function isLoading(): boolean {
    return auth.kind === 'loading'
  }

  const session = $derived(getSession())
  const authLoading = $derived(isLoading())

  let loading = $state(true)
  let controllers = $state<Controller[]>([])
  let controlledAccounts = $state<ControlledAccount[]>([])
  let scopePresets = $state<ScopePreset[]>([])

  let hasControllers = $derived(controllers.length > 0)
  let controlsAccounts = $derived(controlledAccounts.length > 0)
  let canAddControllers = $derived(!controlsAccounts)
  let canControlAccounts = $derived(!hasControllers)

  let showAddController = $state(false)
  let addControllerDid = $state('')
  let addControllerScopes = $state('atproto')
  let addingController = $state(false)
  let addControllerConfirmed = $state(false)

  let showCreateDelegated = $state(false)
  let newDelegatedHandle = $state('')
  let newDelegatedEmail = $state('')
  let newDelegatedScopes = $state('atproto')
  let creatingDelegated = $state(false)

  $effect(() => {
    if (!authLoading && !session) {
      navigate(routes.login)
    }
  })

  $effect(() => {
    if (session) {
      loadData()
    }
  })

  async function loadData() {
    loading = true
    try {
      await Promise.all([loadControllers(), loadControlledAccounts(), loadScopePresets()])
    } finally {
      loading = false
    }
  }

  async function loadControllers() {
    if (!session) return
    try {
      const response = await fetch('/xrpc/_delegation.listControllers', {
        headers: { 'Authorization': `Bearer ${session.accessJwt}` }
      })
      if (response.ok) {
        const data = await response.json()
        controllers = data.controllers || []
      }
    } catch (e) {
      console.error('Failed to load controllers:', e)
    }
  }

  async function loadControlledAccounts() {
    if (!session) return
    try {
      const response = await fetch('/xrpc/_delegation.listControlledAccounts', {
        headers: { 'Authorization': `Bearer ${session.accessJwt}` }
      })
      if (response.ok) {
        const data = await response.json()
        controlledAccounts = data.accounts || []
      }
    } catch (e) {
      console.error('Failed to load controlled accounts:', e)
    }
  }

  async function loadScopePresets() {
    try {
      const response = await fetch('/xrpc/_delegation.getScopePresets')
      if (response.ok) {
        const data = await response.json()
        scopePresets = data.presets || []
      }
    } catch (e) {
      console.error('Failed to load scope presets:', e)
    }
  }

  async function addController() {
    if (!session || !addControllerDid.trim()) return
    addingController = true

    try {
      const response = await fetch('/xrpc/_delegation.addController', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${session.accessJwt}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          controller_did: addControllerDid.trim(),
          granted_scopes: addControllerScopes
        })
      })

      if (!response.ok) {
        const data = await response.json()
        toast.error(data.message || data.error || $_('delegation.failedToAddController'))
        return
      }

      toast.success($_('delegation.controllerAdded'))
      addControllerDid = ''
      addControllerScopes = 'atproto'
      addControllerConfirmed = false
      showAddController = false
      await loadControllers()
    } catch (e) {
      toast.error($_('delegation.failedToAddController'))
    } finally {
      addingController = false
    }
  }

  async function removeController(controllerDid: string) {
    if (!session) return
    if (!confirm($_('delegation.removeConfirm'))) return

    try {
      const response = await fetch('/xrpc/_delegation.removeController', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${session.accessJwt}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ controller_did: controllerDid })
      })

      if (!response.ok) {
        const data = await response.json()
        toast.error(data.message || data.error || $_('delegation.failedToRemoveController'))
        return
      }

      toast.success($_('delegation.controllerRemoved'))
      await loadControllers()
    } catch (e) {
      toast.error($_('delegation.failedToRemoveController'))
    }
  }

  async function createDelegatedAccount() {
    if (!session || !newDelegatedHandle.trim()) return
    creatingDelegated = true

    try {
      const response = await fetch('/xrpc/_delegation.createDelegatedAccount', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${session.accessJwt}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          handle: newDelegatedHandle.trim(),
          email: newDelegatedEmail.trim() || undefined,
          controllerScopes: newDelegatedScopes
        })
      })

      if (!response.ok) {
        const data = await response.json()
        toast.error(data.message || data.error || $_('delegation.failedToCreateAccount'))
        return
      }

      const data = await response.json()
      toast.success($_('delegation.accountCreated', { values: { handle: data.handle } }))
      newDelegatedHandle = ''
      newDelegatedEmail = ''
      newDelegatedScopes = 'atproto'
      showCreateDelegated = false
      await loadControlledAccounts()
    } catch (e) {
      toast.error($_('delegation.failedToCreateAccount'))
    } finally {
      creatingDelegated = false
    }
  }

  function getScopeLabel(scopes: string): string {
    const preset = scopePresets.find(p => p.scopes === scopes)
    if (preset) return preset.label
    if (scopes === 'atproto') return $_('delegation.scopeOwner')
    if (scopes === '') return $_('delegation.scopeViewer')
    return $_('delegation.scopeCustom')
  }
</script>

<div class="page">
  <header>
    <a href="/app/dashboard" class="back">{$_('common.backToDashboard')}</a>
    <h1>{$_('delegation.title')}</h1>
  </header>

  {#if loading}
    <div class="skeleton-list">
      {#each Array(2) as _}
        <div class="skeleton-card"></div>
      {/each}
    </div>
  {:else}
    <section class="section">
      <div class="section-header">
        <h2>{$_('delegation.controllers')}</h2>
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
                  <span class="item-handle">@{controller.handle}</span>
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
                <button class="danger-outline" onclick={() => removeController(controller.did)}>
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
          <h3>{$_('delegation.addController')}</h3>

          <div class="warning-box">
            <div class="warning-header">
              <svg class="warning-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                <line x1="12" y1="9" x2="12" y2="13"></line>
                <line x1="12" y1="17" x2="12.01" y2="17"></line>
              </svg>
              <span>{$_('delegation.addControllerWarningTitle')}</span>
            </div>
            <p class="warning-text">{$_('delegation.addControllerWarningText')}</p>
            <ul class="warning-bullets">
              <li>{$_('delegation.addControllerWarningBullet1')}</li>
              <li>{$_('delegation.addControllerWarningBullet2')}</li>
              <li>{$_('delegation.addControllerWarningBullet3')}</li>
            </ul>
          </div>

          <div class="field">
            <label for="controllerDid">{$_('delegation.controllerDid')}</label>
            <input
              id="controllerDid"
              type="text"
              bind:value={addControllerDid}
              placeholder="did:plc:..."
              disabled={addingController}
            />
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
            <button class="ghost" onclick={() => { showAddController = false; addControllerConfirmed = false }} disabled={addingController}>
              {$_('common.cancel')}
            </button>
            <button onclick={addController} disabled={addingController || !addControllerDid.trim() || !addControllerConfirmed}>
              {addingController ? $_('delegation.adding') : $_('delegation.addController')}
            </button>
          </div>
        </div>
      {:else}
        <button class="ghost full-width" onclick={() => showAddController = true}>
          {$_('delegation.addControllerButton')}
        </button>
      {/if}
    </section>

    <section class="section">
      <div class="section-header">
        <h2>{$_('delegation.controlledAccounts')}</h2>
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
          <h3>{$_('delegation.createDelegatedAccount')}</h3>
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
            <button class="ghost" onclick={() => showCreateDelegated = false} disabled={creatingDelegated}>
              {$_('common.cancel')}
            </button>
            <button onclick={createDelegatedAccount} disabled={creatingDelegated || !newDelegatedHandle.trim()}>
              {creatingDelegated ? $_('common.creating') : $_('delegation.createAccount')}
            </button>
          </div>
        </div>
      {:else}
        <button class="ghost full-width" onclick={() => showCreateDelegated = true}>
          {$_('delegation.createDelegatedAccountButton')}
        </button>
      {/if}
    </section>

    <section class="section">
      <div class="section-header">
        <h2>{$_('delegation.auditLog')}</h2>
        <p class="section-description">{$_('delegation.auditLogDesc')}</p>
      </div>
      <a href="/app/delegation-audit" class="btn-link">{$_('delegation.viewAuditLog')}</a>
    </section>
  {/if}
</div>

<style>
  .page {
    max-width: var(--width-lg);
    margin: 0 auto;
    padding: var(--space-7);
  }

  header {
    margin-bottom: var(--space-7);
  }

  .back {
    color: var(--text-secondary);
    text-decoration: none;
    font-size: var(--text-sm);
  }

  .back:hover {
    color: var(--accent);
  }

  h1 {
    margin: var(--space-2) 0 0 0;
  }

  .empty {
    text-align: center;
    color: var(--text-secondary);
    padding: var(--space-4);
  }

  .constraint-notice {
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: var(--space-4);
  }

  .constraint-notice p {
    margin: 0;
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  .section {
    margin-bottom: var(--space-8);
  }

  .section-header {
    margin-bottom: var(--space-4);
  }

  .section-header h2 {
    margin: 0 0 var(--space-1) 0;
    font-size: var(--text-lg);
  }

  .section-description {
    color: var(--text-secondary);
    margin: 0;
    font-size: var(--text-sm);
  }

  .items-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    margin-bottom: var(--space-4);
  }

  .item-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-xl);
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

  .item-actions button {
    padding: var(--space-2) var(--space-4);
    font-size: var(--text-sm);
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
    transition: background var(--transition-normal), color var(--transition-normal);
  }

  .btn-link:hover {
    background: var(--accent);
    color: var(--text-inverse);
  }

  .full-width {
    width: 100%;
  }

  .form-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-xl);
    padding: var(--space-5);
    margin-top: var(--space-4);
  }

  .form-card h3 {
    margin: 0 0 var(--space-4) 0;
  }

  .warning-box {
    background: var(--warning-bg, #fef3c7);
    border: 1px solid var(--warning-border, #f59e0b);
    border-radius: var(--radius-md);
    padding: var(--space-4);
    margin-bottom: var(--space-5);
  }

  .warning-header {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-weight: var(--font-semibold);
    color: var(--warning-text, #92400e);
    margin-bottom: var(--space-2);
  }

  .warning-icon {
    width: 20px;
    height: 20px;
    flex-shrink: 0;
    stroke: var(--warning-text, #92400e);
  }

  .warning-text {
    margin: 0 0 var(--space-3) 0;
    color: var(--warning-text, #92400e);
    font-size: var(--text-sm);
    line-height: 1.5;
  }

  .warning-bullets {
    margin: 0;
    padding-left: var(--space-5);
    color: var(--warning-text, #92400e);
    font-size: var(--text-sm);
    line-height: 1.6;
  }

  .warning-bullets li {
    margin-bottom: var(--space-1);
  }

  .warning-bullets li:last-child {
    margin-bottom: 0;
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
    padding: var(--space-3);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-size: var(--text-base);
    background: var(--bg-input);
    color: var(--text-primary);
  }

  .field input:focus,
  .field select:focus {
    outline: none;
    border-color: var(--accent);
  }

  .form-actions {
    display: flex;
    gap: var(--space-3);
    justify-content: flex-end;
  }

  .form-actions button {
    padding: var(--space-2) var(--space-4);
    font-size: var(--text-sm);
  }

  .skeleton-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .skeleton-card {
    height: 120px;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-xl);
    animation: skeleton-pulse 1.5s ease-in-out infinite;
  }

  @keyframes skeleton-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
</style>
