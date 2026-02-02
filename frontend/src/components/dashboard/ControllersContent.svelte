<script lang="ts">
  import { onMount } from 'svelte'
  import { _ } from '../../lib/i18n'
  import { api } from '../../lib/api'
  import { toast } from '../../lib/toast.svelte'
  import { formatDateTime } from '../../lib/date'
  import { routes, getFullUrl } from '../../lib/router.svelte'
  import type { Session, DelegationController, DelegationControlledAccount, DelegationScopePreset } from '../../lib/types/api'
  import { unsafeAsDid, unsafeAsScopeSet, unsafeAsHandle, unsafeAsEmail } from '../../lib/types/branded'
  import type { Did, Handle, ScopeSet } from '../../lib/types/branded'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  interface Controller {
    did: Did
    handle: Handle
    grantedScopes: ScopeSet
    grantedAt: string
    isActive: boolean
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
  let addControllerDid = $state('')
  let addControllerScopes = $state('atproto')
  let addingController = $state(false)
  let addControllerConfirmed = $state(false)

  let showCreateDelegated = $state(false)
  let newDelegatedHandle = $state('')
  let newDelegatedEmail = $state('')
  let newDelegatedScopes = $state('atproto')
  let creatingDelegated = $state(false)

  onMount(async () => {
    await loadData()
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
        isActive: c.isActive
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
    if (!addControllerDid.trim()) return
    addingController = true

    const controllerDid = unsafeAsDid(addControllerDid.trim())
    const scopes = unsafeAsScopeSet(addControllerScopes)
    const result = await api.addDelegationController(session.accessJwt, controllerDid, scopes)
    if (result.ok) {
      toast.success($_('delegation.controllerAdded'))
      addControllerDid = ''
      addControllerScopes = 'atproto'
      addControllerConfirmed = false
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
                  <span class="item-handle">@{controller.handle || controller.did}</span>
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
            <button type="button" class="ghost" onclick={() => { showAddController = false; addControllerConfirmed = false }} disabled={addingController}>
              {$_('common.cancel')}
            </button>
            <button type="button" onclick={addController} disabled={addingController || !addControllerDid.trim() || !addControllerConfirmed}>
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
    </section>

    <section class="section">
      <div class="section-header">
        <h3>{$_('delegation.auditLog')}</h3>
        <p class="section-description">{$_('delegation.auditLogDesc')}</p>
      </div>
      <a href={getFullUrl(routes.delegationAudit)} class="btn-link">{$_('delegation.viewAuditLog')}</a>
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
  }
</style>
