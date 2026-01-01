<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'
  import { formatDateTime } from '../lib/date'

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

  const auth = getAuthState()
  let loading = $state(true)
  let error = $state<string | null>(null)
  let success = $state<string | null>(null)
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

  let showCreateDelegated = $state(false)
  let newDelegatedHandle = $state('')
  let newDelegatedEmail = $state('')
  let newDelegatedScopes = $state('atproto')
  let creatingDelegated = $state(false)

  $effect(() => {
    if (!auth.loading && !auth.session) {
      navigate('/login')
    }
  })

  $effect(() => {
    if (auth.session) {
      loadData()
    }
  })

  async function loadData() {
    loading = true
    error = null
    try {
      await Promise.all([loadControllers(), loadControlledAccounts(), loadScopePresets()])
    } finally {
      loading = false
    }
  }

  async function loadControllers() {
    if (!auth.session) return
    try {
      const response = await fetch('/xrpc/_delegation.listControllers', {
        headers: { 'Authorization': `Bearer ${auth.session.accessJwt}` }
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
    if (!auth.session) return
    try {
      const response = await fetch('/xrpc/_delegation.listControlledAccounts', {
        headers: { 'Authorization': `Bearer ${auth.session.accessJwt}` }
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
    if (!auth.session || !addControllerDid.trim()) return
    addingController = true
    error = null
    success = null

    try {
      const response = await fetch('/xrpc/_delegation.addController', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${auth.session.accessJwt}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          controller_did: addControllerDid.trim(),
          granted_scopes: addControllerScopes
        })
      })

      if (!response.ok) {
        const data = await response.json()
        error = data.message || data.error || $_('delegation.failedToAddController')
        return
      }

      success = $_('delegation.controllerAdded')
      addControllerDid = ''
      addControllerScopes = 'atproto'
      showAddController = false
      await loadControllers()
    } catch (e) {
      error = $_('delegation.failedToAddController')
    } finally {
      addingController = false
    }
  }

  async function removeController(controllerDid: string) {
    if (!auth.session) return
    if (!confirm($_('delegation.removeConfirm'))) return

    error = null
    success = null

    try {
      const response = await fetch('/xrpc/_delegation.removeController', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${auth.session.accessJwt}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ controller_did: controllerDid })
      })

      if (!response.ok) {
        const data = await response.json()
        error = data.message || data.error || $_('delegation.failedToRemoveController')
        return
      }

      success = $_('delegation.controllerRemoved')
      await loadControllers()
    } catch (e) {
      error = $_('delegation.failedToRemoveController')
    }
  }

  async function createDelegatedAccount() {
    if (!auth.session || !newDelegatedHandle.trim()) return
    creatingDelegated = true
    error = null
    success = null

    try {
      const response = await fetch('/xrpc/_delegation.createDelegatedAccount', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${auth.session.accessJwt}`,
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
        error = data.message || data.error || $_('delegation.failedToCreateAccount')
        return
      }

      const data = await response.json()
      success = $_('delegation.accountCreated', { values: { handle: data.handle } })
      newDelegatedHandle = ''
      newDelegatedEmail = ''
      newDelegatedScopes = 'atproto'
      showCreateDelegated = false
      await loadControlledAccounts()
    } catch (e) {
      error = $_('delegation.failedToCreateAccount')
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
    <a href="#/dashboard" class="back">{$_('common.backToDashboard')}</a>
    <h1>{$_('delegation.title')}</h1>
  </header>

  {#if loading}
    <p class="loading">{$_('delegation.loading')}</p>
  {:else}
    {#if error}
      <div class="message error">{error}</div>
    {/if}

    {#if success}
      <div class="message success">{success}</div>
    {/if}

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
          <div class="form-actions">
            <button class="ghost" onclick={() => showAddController = false} disabled={addingController}>
              {$_('common.cancel')}
            </button>
            <button onclick={addController} disabled={addingController || !addControllerDid.trim()}>
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
                <a href="/#/act-as?did={encodeURIComponent(account.did)}" class="btn-link">
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
      <a href="#/delegation-audit" class="btn-link">{$_('delegation.viewAuditLog')}</a>
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

  .loading,
  .empty {
    text-align: center;
    color: var(--text-secondary);
    padding: var(--space-4);
  }

  .message {
    padding: var(--space-3);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-4);
  }

  .message.error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-text);
  }

  .message.success {
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    color: var(--success-text);
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
</style>
