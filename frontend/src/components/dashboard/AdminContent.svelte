<script lang="ts">
  import { onMount } from 'svelte'
  import { _ } from '../../lib/i18n'
  import { api, ApiError } from '../../lib/api'
  import { toast } from '../../lib/toast.svelte'
  import type { Session } from '../../lib/types/api'
  import { formatDate } from '../../lib/date'
  import { unsafeAsDid } from '../../lib/types/branded'
  import {
    setServerName as setGlobalServerName,
    setColors as setGlobalColors,
    setHasLogo as setGlobalHasLogo
  } from '../../lib/serverConfig.svelte'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  interface ServerStats {
    userCount: number
    repoCount: number
    recordCount: number
    blobStorageBytes: number
  }

  interface User {
    did: string
    handle: string
    email?: string
    indexedAt: string
    emailConfirmedAt?: string
    deactivatedAt?: string
    invitesDisabled?: boolean
  }

  interface Invite {
    code: string
    available: number
    disabled: boolean
    forAccount: string
    createdBy: string
    createdAt: string
    uses: Array<{ usedBy: string; usedAt: string }>
  }

  let stats = $state<ServerStats | null>(null)
  let users = $state<User[]>([])
  let loading = $state(true)
  let usersLoading = $state(false)
  let searchQuery = $state('')
  let usersCursor = $state<string | undefined>(undefined)

  let invites = $state<Invite[]>([])
  let invitesLoading = $state(false)
  let invitesCursor = $state<string | undefined>(undefined)
  let showInvites = $state(false)

  let selectedUser = $state<User | null>(null)
  let userActionLoading = $state(false)
  let userDetailLoading = $state(false)

  let serverName = $state('')
  let serverNameInput = $state('')
  let primaryColor = $state('')
  let primaryColorInput = $state('')
  let primaryColorDark = $state('')
  let primaryColorDarkInput = $state('')
  let secondaryColor = $state('')
  let secondaryColorInput = $state('')
  let secondaryColorDark = $state('')
  let secondaryColorDarkInput = $state('')
  let logoCid = $state<string | null>(null)
  let originalLogoCid = $state<string | null>(null)
  let logoFile = $state<File | null>(null)
  let logoPreview = $state<string | null>(null)
  let serverConfigLoading = $state(false)

  onMount(async () => {
    await Promise.all([loadStats(), loadServerConfig()])
  })

  async function loadStats() {
    loading = true
    try {
      stats = await api.getServerStats(session.accessJwt)
    } catch {
      toast.error($_('admin.failedToLoadStats'))
    } finally {
      loading = false
    }
  }

  async function loadUsers(reset = false) {
    usersLoading = true
    if (reset) {
      users = []
      usersCursor = undefined
    }
    try {
      const result = await api.searchAccounts(session.accessJwt, {
        handle: searchQuery || undefined,
        cursor: reset ? undefined : usersCursor,
        limit: 25,
      })
      users = reset ? result.accounts : [...users, ...result.accounts]
      usersCursor = result.cursor
    } catch {
      toast.error($_('admin.failedToLoadUsers'))
    } finally {
      usersLoading = false
    }
  }

  function handleSearch(e: Event) {
    e.preventDefault()
    loadUsers(true)
  }

  function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B'
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  }

  function formatNumber(num: number): string {
    return num.toLocaleString()
  }

  async function loadServerConfig() {
    try {
      const config = await api.getServerConfig()
      serverName = config.serverName
      serverNameInput = config.serverName
      primaryColor = config.primaryColor || ''
      primaryColorInput = config.primaryColor || ''
      primaryColorDark = config.primaryColorDark || ''
      primaryColorDarkInput = config.primaryColorDark || ''
      secondaryColor = config.secondaryColor || ''
      secondaryColorInput = config.secondaryColor || ''
      secondaryColorDark = config.secondaryColorDark || ''
      secondaryColorDarkInput = config.secondaryColorDark || ''
      logoCid = config.logoCid
      originalLogoCid = config.logoCid
      if (config.logoCid) {
        logoPreview = '/logo'
      }
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('admin.failedToLoadConfig'))
    }
  }

  async function saveServerConfig(e: Event) {
    e.preventDefault()
    serverConfigLoading = true
    try {
      let newLogoCid = logoCid
      if (logoFile) {
        const result = await api.uploadBlob(session.accessJwt, logoFile)
        newLogoCid = result.blob.ref.$link
      }
      await api.updateServerConfig(session.accessJwt, {
        serverName: serverNameInput,
        primaryColor: primaryColorInput,
        primaryColorDark: primaryColorDarkInput,
        secondaryColor: secondaryColorInput,
        secondaryColorDark: secondaryColorDarkInput,
        logoCid: newLogoCid ?? '',
      })
      serverName = serverNameInput
      primaryColor = primaryColorInput
      primaryColorDark = primaryColorDarkInput
      secondaryColor = secondaryColorInput
      secondaryColorDark = secondaryColorDarkInput
      logoCid = newLogoCid
      originalLogoCid = newLogoCid
      logoFile = null
      setGlobalServerName(serverNameInput)
      setGlobalColors({
        primaryColor: primaryColorInput || null,
        primaryColorDark: primaryColorDarkInput || null,
        secondaryColor: secondaryColorInput || null,
        secondaryColorDark: secondaryColorDarkInput || null,
      })
      setGlobalHasLogo(!!newLogoCid)
      toast.success($_('admin.configSaved'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('admin.failedToSaveConfig'))
    } finally {
      serverConfigLoading = false
    }
  }

  function handleLogoChange(e: Event) {
    const input = e.target as HTMLInputElement
    const file = input.files?.[0]
    if (file) {
      logoFile = file
      logoPreview = URL.createObjectURL(file)
    }
  }

  function removeLogo() {
    logoFile = null
    logoCid = null
    logoPreview = null
  }

  function hasConfigChanges(): boolean {
    const logoChanged = logoFile !== null || logoCid !== originalLogoCid
    return serverNameInput !== serverName ||
      primaryColorInput !== primaryColor ||
      primaryColorDarkInput !== primaryColorDark ||
      secondaryColorInput !== secondaryColor ||
      secondaryColorDarkInput !== secondaryColorDark ||
      logoChanged
  }

  async function loadInvites(reset = false) {
    invitesLoading = true
    if (reset) {
      invites = []
      invitesCursor = undefined
    }
    try {
      const result = await api.getInviteCodes(session.accessJwt, {
        cursor: reset ? undefined : invitesCursor,
        limit: 25,
      })
      invites = reset ? result.codes : [...invites, ...result.codes]
      invitesCursor = result.cursor
      showInvites = true
    } catch {
      toast.error($_('admin.failedToLoadInvites'))
    } finally {
      invitesLoading = false
    }
  }

  async function disableInvite(code: string) {
    if (!confirm($_('admin.disableInviteConfirm', { values: { code } }))) return
    try {
      await api.disableInviteCodes(session.accessJwt, [code])
      invites = invites.map(i => i.code === code ? { ...i, disabled: true } : i)
      toast.success($_('admin.inviteDisabled'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('admin.failedToDisableInvite'))
    }
  }

  async function showUserDetail(user: User) {
    selectedUser = user
    userDetailLoading = true
    try {
      const details = await api.getAccountInfo(session.accessJwt, unsafeAsDid(user.did))
      selectedUser = {
        did: details.did,
        handle: details.handle,
        email: details.email,
        indexedAt: details.indexedAt,
        emailConfirmedAt: details.emailConfirmedAt,
        deactivatedAt: details.deactivatedAt,
        invitesDisabled: details.invitesDisabled
      }
    } catch {
    } finally {
      userDetailLoading = false
    }
  }

  function closeUserDetail() {
    selectedUser = null
  }

  async function toggleUserInvites() {
    if (!selectedUser) return
    userActionLoading = true
    try {
      if (selectedUser.invitesDisabled) {
        await api.enableAccountInvites(session.accessJwt, unsafeAsDid(selectedUser.did))
        selectedUser = { ...selectedUser, invitesDisabled: false }
        toast.success($_('admin.invitesEnabled'))
      } else {
        await api.disableAccountInvites(session.accessJwt, unsafeAsDid(selectedUser.did))
        selectedUser = { ...selectedUser, invitesDisabled: true }
        toast.success($_('admin.invitesDisabled'))
      }
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('admin.failedToToggleInvites'))
    } finally {
      userActionLoading = false
    }
  }

  async function deleteUserAccount() {
    if (!selectedUser) return
    if (!confirm($_('admin.deleteConfirm', { values: { handle: selectedUser.handle } }))) return
    userActionLoading = true
    try {
      await api.adminDeleteAccount(session.accessJwt, unsafeAsDid(selectedUser.did))
      users = users.filter(u => u.did !== selectedUser!.did)
      selectedUser = null
      toast.success($_('admin.userDeleted'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('admin.failedToDeleteAccount'))
    } finally {
      userActionLoading = false
    }
  }
</script>

<div class="admin">
  <section class="config-section">
    <h3>{$_('admin.serverConfig')}</h3>
    <form onsubmit={saveServerConfig}>
      <div class="field">
        <label for="server-name">{$_('admin.serverName')}</label>
        <input
          id="server-name"
          type="text"
          bind:value={serverNameInput}
          placeholder={$_('admin.serverNamePlaceholder')}
          disabled={serverConfigLoading}
        />
        <span class="field-help">{$_('admin.serverNameHelp')}</span>
      </div>

      <div class="field">
        <label for="server-logo">{$_('admin.serverLogo')}</label>
        <div class="logo-section">
          {#if logoPreview}
            <div class="logo-preview">
              <img src={logoPreview} alt={$_('admin.logoPreview')} />
              <button type="button" class="remove-logo" onclick={removeLogo}>
                {$_('admin.removeLogo')}
              </button>
            </div>
          {/if}
          <input id="server-logo" type="file" accept="image/*" onchange={handleLogoChange} disabled={serverConfigLoading} />
        </div>
        <span class="field-help">{$_('admin.logoHelp')}</span>
      </div>

      <div class="colors-grid">
        <h4>{$_('admin.themeColors')}</h4>
        <span class="field-help">{$_('admin.themeColorsHint')}</span>
        <div class="color-fields">
          <div class="color-field">
            <label for="primary-light">{$_('admin.primaryLight')}</label>
            <div class="color-input-row">
              <input type="color" bind:value={primaryColorInput} disabled={serverConfigLoading} />
              <input id="primary-light" type="text" bind:value={primaryColorInput} placeholder="#1A1D1D" disabled={serverConfigLoading} />
            </div>
          </div>
          <div class="color-field">
            <label for="primary-dark">{$_('admin.primaryDark')}</label>
            <div class="color-input-row">
              <input type="color" bind:value={primaryColorDarkInput} disabled={serverConfigLoading} />
              <input id="primary-dark" type="text" bind:value={primaryColorDarkInput} placeholder="#E6E8E8" disabled={serverConfigLoading} />
            </div>
          </div>
          <div class="color-field">
            <label for="secondary-light">{$_('admin.secondaryLight')}</label>
            <div class="color-input-row">
              <input type="color" bind:value={secondaryColorInput} disabled={serverConfigLoading} />
              <input id="secondary-light" type="text" bind:value={secondaryColorInput} placeholder="#1A1D1D" disabled={serverConfigLoading} />
            </div>
          </div>
          <div class="color-field">
            <label for="secondary-dark">{$_('admin.secondaryDark')}</label>
            <div class="color-input-row">
              <input type="color" bind:value={secondaryColorDarkInput} disabled={serverConfigLoading} />
              <input id="secondary-dark" type="text" bind:value={secondaryColorDarkInput} placeholder="#E6E8E8" disabled={serverConfigLoading} />
            </div>
          </div>
        </div>
      </div>

      <button type="submit" disabled={serverConfigLoading || !hasConfigChanges()}>
        {serverConfigLoading ? $_('common.saving') : $_('admin.saveConfig')}
      </button>
    </form>
  </section>

  <section class="stats-section">
    <div class="section-header-row">
      <h3>{$_('admin.serverStats')}</h3>
      <button type="button" class="refresh-btn" onclick={loadStats} disabled={loading}>
        {$_('admin.refreshStats')}
      </button>
    </div>
    {#if loading}
      <div class="loading">{$_('common.loading')}</div>
    {:else if stats}
      <div class="stats-grid">
        <div class="stat-item">
          <span class="stat-value">{formatNumber(stats.userCount)}</span>
          <span class="stat-label">{$_('admin.users')}</span>
        </div>
        <div class="stat-item">
          <span class="stat-value">{formatNumber(stats.repoCount)}</span>
          <span class="stat-label">{$_('admin.repos')}</span>
        </div>
        <div class="stat-item">
          <span class="stat-value">{formatNumber(stats.recordCount)}</span>
          <span class="stat-label">{$_('admin.records')}</span>
        </div>
        <div class="stat-item">
          <span class="stat-value">{formatBytes(stats.blobStorageBytes)}</span>
          <span class="stat-label">{$_('admin.blobStorage')}</span>
        </div>
      </div>
    {/if}
  </section>

  <section class="users-section">
    <h3>{$_('admin.userManagement')}</h3>

    <form class="search-bar" onsubmit={handleSearch}>
      <input
        type="text"
        bind:value={searchQuery}
        placeholder={$_('admin.searchPlaceholder')}
      />
      <button type="submit" disabled={usersLoading}>
        {usersLoading ? $_('common.loading') : $_('admin.search')}
      </button>
    </form>

    {#if users.length === 0 && !usersLoading}
      <p class="empty">{$_('admin.searchToSeeUsers')}</p>
    {:else}
      <ul class="user-list">
        {#each users as user}
          <li class="user-item">
            <button type="button" class="user-item-btn" onclick={() => showUserDetail(user)}>
              <div class="user-info">
                <span class="user-handle">@{user.handle}</span>
                <span class="user-did">{user.did}</span>
                {#if user.email}
                  <span class="user-email">{user.email}</span>
                {/if}
                <span class="user-date">{$_('admin.created')}: {formatDate(user.indexedAt)}</span>
              </div>
              <div class="user-badges">
                {#if user.emailConfirmedAt}
                  <span class="badge verified">{$_('admin.verified')}</span>
                {:else}
                  <span class="badge unverified">{$_('admin.unverified')}</span>
                {/if}
                {#if user.deactivatedAt}
                  <span class="badge deactivated">{$_('admin.deactivated')}</span>
                {/if}
              </div>
            </button>
          </li>
        {/each}
      </ul>
      {#if usersCursor}
        <button type="button" class="load-more" onclick={() => loadUsers(false)} disabled={usersLoading}>
          {usersLoading ? $_('common.loading') : $_('admin.loadMore')}
        </button>
      {/if}
    {/if}
  </section>

  <section class="invites-section">
    <h3>{$_('admin.inviteCodes')}</h3>
    <div class="section-actions">
      <button onclick={() => loadInvites(true)} disabled={invitesLoading}>
        {invitesLoading ? $_('common.loading') : showInvites ? $_('admin.refresh') : $_('admin.loadInviteCodes')}
      </button>
    </div>
    {#if showInvites}
      {#if invites.length === 0}
        <p class="empty">{$_('admin.noInvites')}</p>
      {:else}
        <ul class="invite-list">
          {#each invites as invite}
            <li class="invite-item" class:disabled-row={invite.disabled}>
              <div class="invite-info">
                <code class="invite-code">{invite.code}</code>
                <span class="invite-meta">
                  {$_('admin.available')}: {invite.available} - {$_('admin.uses')}: {invite.uses.length} - {$_('admin.created')}: {formatDate(invite.createdAt)}
                </span>
              </div>
              <div class="invite-status">
                {#if invite.disabled}
                  <span class="badge deactivated">{$_('admin.disabled')}</span>
                {:else if invite.available === 0}
                  <span class="badge unverified">{$_('admin.exhausted')}</span>
                {:else}
                  <span class="badge verified">{$_('admin.active')}</span>
                {/if}
              </div>
              <div class="invite-actions">
                {#if !invite.disabled}
                  <button class="action-btn danger" onclick={() => disableInvite(invite.code)}>
                    {$_('admin.disable')}
                  </button>
                {/if}
              </div>
            </li>
          {/each}
        </ul>
        {#if invitesCursor}
          <button type="button" class="load-more" onclick={() => loadInvites(false)} disabled={invitesLoading}>
            {invitesLoading ? $_('common.loading') : $_('admin.loadMore')}
          </button>
        {/if}
      {/if}
    {/if}
  </section>
</div>

{#if selectedUser}
  <div class="modal-overlay" onclick={closeUserDetail} onkeydown={(e) => e.key === 'Escape' && closeUserDetail()} role="presentation">
    <div class="modal" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="dialog" aria-modal="true" tabindex="-1">
      <div class="modal-header">
        <h2>{$_('admin.userDetails')}</h2>
        <button class="close-btn" onclick={closeUserDetail}>&times;</button>
      </div>
      <div class="modal-body">
        {#if userDetailLoading}
          <div class="loading">{$_('common.loading')}</div>
        {/if}
        <dl class="user-details">
          <dt>{$_('admin.handle')}</dt>
          <dd>@{selectedUser.handle}</dd>
          <dt>{$_('admin.did')}</dt>
          <dd class="mono">{selectedUser.did}</dd>
          <dt>{$_('admin.email')}</dt>
          <dd>{selectedUser.email || '-'}</dd>
          <dt>{$_('admin.created')}</dt>
          <dd>{formatDate(selectedUser.indexedAt)}</dd>
          <dt>{$_('admin.status')}</dt>
          <dd>
            {#if selectedUser.deactivatedAt}
              <span class="badge deactivated">{$_('admin.deactivated')}</span>
            {:else if selectedUser.emailConfirmedAt}
              <span class="badge verified">{$_('admin.verified')}</span>
            {:else}
              <span class="badge unverified">{$_('admin.unverified')}</span>
            {/if}
          </dd>
          <dt>{$_('admin.invites')}</dt>
          <dd>
            {#if selectedUser.invitesDisabled}
              <span class="badge deactivated">{$_('admin.disabled')}</span>
            {:else}
              <span class="badge verified">{$_('admin.enabled')}</span>
            {/if}
          </dd>
        </dl>
        <div class="modal-actions">
          <button
            onclick={toggleUserInvites}
            disabled={userActionLoading}
          >
            {selectedUser.invitesDisabled ? $_('admin.enableInvites') : $_('admin.disableInvites')}
          </button>
          <button
            class="danger"
            onclick={deleteUserAccount}
            disabled={userActionLoading}
          >
            {$_('admin.deleteAccount')}
          </button>
        </div>
      </div>
    </div>
  </div>
{/if}

<style>
  .admin {
    max-width: var(--width-lg);
  }

  section {
    background: var(--bg-secondary);
    padding: var(--space-5);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-5);
  }

  section h3 {
    margin: 0 0 var(--space-4) 0;
    font-size: var(--text-base);
  }

  .section-header-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--space-4);
  }

  .section-header-row h3 {
    margin: 0;
  }

  .refresh-btn {
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-sm);
    background: transparent;
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    cursor: pointer;
    color: var(--text-primary);
  }

  .refresh-btn:hover:not(:disabled) {
    border-color: var(--accent);
  }

  .refresh-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .loading,
  .empty {
    color: var(--text-secondary);
    padding: var(--space-4);
    text-align: center;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: var(--space-4);
  }

  .stat-item {
    background: var(--bg-card);
    padding: var(--space-4);
    border-radius: var(--radius-md);
    text-align: center;
  }

  .stat-value {
    display: block;
    font-size: var(--text-2xl);
    font-weight: var(--font-bold);
    color: var(--accent);
  }

  .stat-label {
    display: block;
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin-top: var(--space-1);
  }

  .search-bar {
    display: flex;
    gap: var(--space-2);
    margin-bottom: var(--space-4);
  }

  .search-bar input {
    flex: 1;
  }

  .user-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .user-item {
    list-style: none;
  }

  .user-item-btn {
    display: flex;
    align-items: flex-start;
    width: 100%;
    padding: var(--space-3);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    gap: var(--space-3);
    cursor: pointer;
    text-align: left;
    color: inherit;
    font: inherit;
  }

  .user-item-btn:hover {
    border-color: var(--accent);
  }

  .user-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .user-handle {
    font-weight: var(--font-medium);
  }

  .user-did {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    color: var(--text-secondary);
    word-break: break-all;
  }

  .user-email {
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .user-date {
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .user-badges {
    display: flex;
    gap: var(--space-2);
    flex-shrink: 0;
  }

  .badge {
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
  }

  .badge.deactivated {
    background: var(--warning-bg);
    color: var(--warning-text);
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

  .field-help {
    display: block;
    font-size: var(--text-xs);
    color: var(--text-secondary);
    margin-top: var(--space-1);
  }

  .logo-section {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .logo-preview {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .logo-preview img {
    width: 48px;
    height: 48px;
    object-fit: contain;
    border-radius: var(--radius-md);
    background: var(--bg-card);
    padding: var(--space-2);
  }

  .remove-logo {
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-sm);
    background: transparent;
    border: 1px solid var(--error-border);
    color: var(--error-text);
    border-radius: var(--radius-md);
    cursor: pointer;
  }

  .remove-logo:hover {
    background: var(--error-bg);
  }

  .colors-grid {
    margin-bottom: var(--space-5);
  }

  .colors-grid h4 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
  }

  .color-fields {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: var(--space-3);
    margin-top: var(--space-3);
  }

  .color-field label {
    display: block;
    font-size: var(--text-xs);
    color: var(--text-secondary);
    margin-bottom: var(--space-1);
  }

  .color-input-row {
    display: flex;
    gap: var(--space-2);
    align-items: center;
  }

  .color-input-row input[type="color"] {
    width: 40px;
    height: 36px;
    padding: 2px;
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    cursor: pointer;
    flex-shrink: 0;
  }

  .color-input-row input[type="text"] {
    flex: 1;
    font-family: var(--font-mono);
    font-size: var(--text-sm);
  }

  .load-more {
    display: block;
    width: 100%;
    margin-top: var(--space-4);
  }

  .badge.verified {
    background: var(--success-bg);
    color: var(--success-text);
  }

  .badge.unverified {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
  }

  .section-actions {
    margin-bottom: var(--space-4);
  }

  .invite-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .invite-item {
    display: flex;
    align-items: center;
    padding: var(--space-3);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    gap: var(--space-3);
  }

  .invite-item.disabled-row {
    opacity: 0.6;
  }

  .invite-info {
    flex: 1;
    min-width: 0;
  }

  .invite-code {
    display: block;
    font-family: var(--font-mono);
    font-size: var(--text-sm);
  }

  .invite-meta {
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .invite-status {
    flex-shrink: 0;
  }

  .invite-actions {
    flex-shrink: 0;
  }

  .action-btn {
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-sm);
    border-radius: var(--radius-md);
    cursor: pointer;
  }

  .action-btn.danger {
    background: transparent;
    border: 1px solid var(--error-border);
    color: var(--error-text);
  }

  .action-btn.danger:hover {
    background: var(--error-bg);
  }

  .modal-overlay {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: var(--z-modal);
  }

  .modal {
    background: var(--bg-card);
    border-radius: var(--radius-xl);
    box-shadow: var(--shadow-lg);
    max-width: var(--width-sm);
    width: 90%;
    max-height: 90vh;
    overflow-y: auto;
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-4) var(--space-5);
    border-bottom: 1px solid var(--border-color);
  }

  .modal-header h2 {
    margin: 0;
    font-size: var(--text-lg);
  }

  .close-btn {
    background: none;
    border: none;
    font-size: var(--text-xl);
    cursor: pointer;
    color: var(--text-secondary);
    padding: 0;
    line-height: 1;
  }

  .close-btn:hover {
    color: var(--text-primary);
  }

  .modal-body {
    padding: var(--space-5);
  }

  .user-details {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: var(--space-2) var(--space-4);
    margin: 0 0 var(--space-5) 0;
  }

  .user-details dt {
    font-weight: var(--font-medium);
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  .user-details dd {
    margin: 0;
  }

  .user-details .mono {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    word-break: break-all;
  }

  .modal-actions {
    display: flex;
    gap: var(--space-3);
    flex-wrap: wrap;
  }

  .modal-actions button.danger {
    background: var(--error-text);
    border: 1px solid var(--error-text);
    color: white;
  }

  .modal-actions button.danger:hover {
    background: var(--error-border);
  }

  @media (max-width: 600px) {
    .user-item {
      flex-direction: column;
    }

    .user-item-btn {
      flex-direction: column;
      gap: var(--space-2);
    }

    .user-info {
      width: 100%;
    }

    .user-badges {
      width: 100%;
      flex-wrap: wrap;
    }

    .search-bar {
      flex-direction: column;
    }

    .color-fields {
      grid-template-columns: 1fr;
    }
  }
</style>
