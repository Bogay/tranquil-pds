<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { setServerName as setGlobalServerName, setColors as setGlobalColors, setHasLogo as setGlobalHasLogo } from '../lib/serverConfig.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import { formatDate, formatDateTime } from '../lib/date'
  const auth = getAuthState()
  const DEFAULT_COLORS = {
    primaryLight: '#1A1D1D',
    primaryDark: '#E6E8E8',
    secondaryLight: '#1A1D1D',
    secondaryDark: '#E6E8E8',
  }
  let loading = $state(true)
  let error = $state<string | null>(null)
  let stats = $state<{
    userCount: number
    repoCount: number
    recordCount: number
    blobStorageBytes: number
  } | null>(null)
  let usersLoading = $state(false)
  let usersError = $state<string | null>(null)
  let users = $state<Array<{
    did: string
    handle: string
    email?: string
    indexedAt: string
    emailConfirmedAt?: string
    deactivatedAt?: string
  }>>([])
  let usersCursor = $state<string | undefined>(undefined)
  let handleSearchQuery = $state('')
  let showUsers = $state(false)
  let invitesLoading = $state(false)
  let invitesError = $state<string | null>(null)
  let invites = $state<Array<{
    code: string
    available: number
    disabled: boolean
    forAccount: string
    createdBy: string
    createdAt: string
    uses: Array<{ usedBy: string; usedAt: string }>
  }>>([])
  let invitesCursor = $state<string | undefined>(undefined)
  let showInvites = $state(false)
  let selectedUser = $state<{
    did: string
    handle: string
    email?: string
    indexedAt: string
    emailConfirmedAt?: string
    invitesDisabled?: boolean
    deactivatedAt?: string
  } | null>(null)
  let userDetailLoading = $state(false)
  let userActionLoading = $state(false)
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
  let serverConfigError = $state<string | null>(null)
  let serverConfigSuccess = $state(false)
  $effect(() => {
    if (!auth.loading && !auth.session) {
      navigate('/login')
    } else if (!auth.loading && auth.session && !auth.session.isAdmin) {
      navigate('/dashboard')
    }
  })
  $effect(() => {
    if (auth.session?.isAdmin) {
      loadStats()
      loadServerConfig()
    }
  })
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
      serverConfigError = e instanceof ApiError ? e.message : 'Failed to load server config'
    }
  }
  async function saveServerConfig(e: Event) {
    e.preventDefault()
    if (!auth.session) return
    serverConfigLoading = true
    serverConfigError = null
    serverConfigSuccess = false
    try {
      let newLogoCid = logoCid
      if (logoFile) {
        const result = await api.uploadBlob(auth.session.accessJwt, logoFile)
        newLogoCid = result.blob.ref.$link
      }
      await api.updateServerConfig(auth.session.accessJwt, {
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
      serverConfigSuccess = true
      setTimeout(() => { serverConfigSuccess = false }, 3000)
    } catch (e) {
      serverConfigError = e instanceof ApiError ? e.message : 'Failed to save server config'
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
  async function loadStats() {
    if (!auth.session) return
    loading = true
    error = null
    try {
      stats = await api.getServerStats(auth.session.accessJwt)
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to load server stats'
    } finally {
      loading = false
    }
  }
  async function loadUsers(reset = false) {
    if (!auth.session) return
    usersLoading = true
    usersError = null
    if (reset) {
      users = []
      usersCursor = undefined
    }
    try {
      const result = await api.searchAccounts(auth.session.accessJwt, {
        handle: handleSearchQuery || undefined,
        cursor: reset ? undefined : usersCursor,
        limit: 25,
      })
      users = reset ? result.accounts : [...users, ...result.accounts]
      usersCursor = result.cursor
      showUsers = true
    } catch (e) {
      usersError = e instanceof ApiError ? e.message : 'Failed to load users'
    } finally {
      usersLoading = false
    }
  }
  function handleSearch(e: Event) {
    e.preventDefault()
    loadUsers(true)
  }
  async function loadInvites(reset = false) {
    if (!auth.session) return
    invitesLoading = true
    invitesError = null
    if (reset) {
      invites = []
      invitesCursor = undefined
    }
    try {
      const result = await api.getInviteCodes(auth.session.accessJwt, {
        cursor: reset ? undefined : invitesCursor,
        limit: 25,
      })
      invites = reset ? result.codes : [...invites, ...result.codes]
      invitesCursor = result.cursor
      showInvites = true
    } catch (e) {
      invitesError = e instanceof ApiError ? e.message : 'Failed to load invites'
    } finally {
      invitesLoading = false
    }
  }
  async function disableInvite(code: string) {
    if (!auth.session) return
    if (!confirm($_('admin.disableInviteConfirm', { values: { code } }))) return
    try {
      await api.disableInviteCodes(auth.session.accessJwt, [code])
      invites = invites.map(inv => inv.code === code ? { ...inv, disabled: true } : inv)
    } catch (e) {
      invitesError = e instanceof ApiError ? e.message : 'Failed to disable invite'
    }
  }
  async function selectUser(did: string) {
    if (!auth.session) return
    userDetailLoading = true
    try {
      selectedUser = await api.getAccountInfo(auth.session.accessJwt, did)
    } catch (e) {
      usersError = e instanceof ApiError ? e.message : 'Failed to load user details'
    } finally {
      userDetailLoading = false
    }
  }
  function closeUserDetail() {
    selectedUser = null
  }
  async function toggleUserInvites() {
    if (!auth.session || !selectedUser) return
    userActionLoading = true
    try {
      if (selectedUser.invitesDisabled) {
        await api.enableAccountInvites(auth.session.accessJwt, selectedUser.did)
        selectedUser = { ...selectedUser, invitesDisabled: false }
      } else {
        await api.disableAccountInvites(auth.session.accessJwt, selectedUser.did)
        selectedUser = { ...selectedUser, invitesDisabled: true }
      }
    } catch (e) {
      usersError = e instanceof ApiError ? e.message : 'Failed to update user'
    } finally {
      userActionLoading = false
    }
  }
  async function deleteUser() {
    if (!auth.session || !selectedUser) return
    if (!confirm($_('admin.deleteConfirm', { values: { handle: selectedUser.handle } }))) return
    userActionLoading = true
    try {
      await api.adminDeleteAccount(auth.session.accessJwt, selectedUser.did)
      users = users.filter(u => u.did !== selectedUser!.did)
      selectedUser = null
    } catch (e) {
      usersError = e instanceof ApiError ? e.message : 'Failed to delete user'
    } finally {
      userActionLoading = false
    }
  }
  function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
  }
  function formatNumber(num: number): string {
    return num.toLocaleString()
  }
</script>
{#if auth.session?.isAdmin}
  <div class="page">
    <header>
      <a href="#/dashboard" class="back">{$_('common.backToDashboard')}</a>
      <h1>{$_('admin.title')}</h1>
    </header>
    {#if loading}
      <p class="loading">{$_('admin.loading')}</p>
    {:else}
      {#if error}
        <div class="message error">{error}</div>
      {/if}
      <section>
        <h2>{$_('admin.serverConfig')}</h2>
        <form class="config-form" onsubmit={saveServerConfig}>
          <div class="form-group">
            <label for="serverName">{$_('admin.serverName')}</label>
            <input
              type="text"
              id="serverName"
              bind:value={serverNameInput}
              placeholder={$_('admin.serverNamePlaceholder')}
              maxlength="100"
              disabled={serverConfigLoading}
            />
            <span class="help-text">{$_('admin.serverNameHelp')}</span>
          </div>

          <div class="form-group">
            <label for="serverLogo">{$_('admin.serverLogo')}</label>
            <div class="logo-upload">
              {#if logoPreview}
                <div class="logo-preview">
                  <img src={logoPreview} alt={$_('admin.logoPreview')} />
                  <button type="button" class="remove-logo" onclick={removeLogo} disabled={serverConfigLoading}>{$_('admin.removeLogo')}</button>
                </div>
              {:else}
                <input
                  type="file"
                  id="serverLogo"
                  accept="image/*"
                  onchange={handleLogoChange}
                  disabled={serverConfigLoading}
                />
              {/if}
            </div>
            <span class="help-text">{$_('admin.logoHelp')}</span>
          </div>

          <h3 class="subsection-title">{$_('admin.themeColors')}</h3>
          <p class="theme-hint">{$_('admin.themeColorsHint')}</p>

          <div class="color-grid">
            <div class="color-group">
              <label for="primaryColor">{$_('admin.primaryLight')}</label>
              <div class="color-input-row">
                <input
                  type="color"
                  bind:value={primaryColorInput}
                  disabled={serverConfigLoading}
                />
                <input
                  type="text"
                  id="primaryColor"
                  bind:value={primaryColorInput}
                  placeholder={$_('admin.colorDefault', { values: { color: DEFAULT_COLORS.primaryLight } })}
                  disabled={serverConfigLoading}
                />
              </div>
            </div>
            <div class="color-group">
              <label for="primaryColorDark">{$_('admin.primaryDark')}</label>
              <div class="color-input-row">
                <input
                  type="color"
                  bind:value={primaryColorDarkInput}
                  disabled={serverConfigLoading}
                />
                <input
                  type="text"
                  id="primaryColorDark"
                  bind:value={primaryColorDarkInput}
                  placeholder={$_('admin.colorDefault', { values: { color: DEFAULT_COLORS.primaryDark } })}
                  disabled={serverConfigLoading}
                />
              </div>
            </div>
            <div class="color-group">
              <label for="secondaryColor">{$_('admin.secondaryLight')}</label>
              <div class="color-input-row">
                <input
                  type="color"
                  bind:value={secondaryColorInput}
                  disabled={serverConfigLoading}
                />
                <input
                  type="text"
                  id="secondaryColor"
                  bind:value={secondaryColorInput}
                  placeholder={$_('admin.colorDefault', { values: { color: DEFAULT_COLORS.secondaryLight } })}
                  disabled={serverConfigLoading}
                />
              </div>
            </div>
            <div class="color-group">
              <label for="secondaryColorDark">{$_('admin.secondaryDark')}</label>
              <div class="color-input-row">
                <input
                  type="color"
                  bind:value={secondaryColorDarkInput}
                  disabled={serverConfigLoading}
                />
                <input
                  type="text"
                  id="secondaryColorDark"
                  bind:value={secondaryColorDarkInput}
                  placeholder={$_('admin.colorDefault', { values: { color: DEFAULT_COLORS.secondaryDark } })}
                  disabled={serverConfigLoading}
                />
              </div>
            </div>
          </div>

          {#if serverConfigError}
            <div class="message error">{serverConfigError}</div>
          {/if}
          {#if serverConfigSuccess}
            <div class="message success">{$_('admin.configSaved')}</div>
          {/if}
          <button type="submit" disabled={serverConfigLoading || !hasConfigChanges()}>
            {serverConfigLoading ? $_('common.saving') : $_('admin.saveConfig')}
          </button>
        </form>
      </section>
      {#if stats}
        <section>
          <h2>{$_('admin.serverStats')}</h2>
          <div class="stats-grid">
            <div class="stat-card">
              <div class="stat-value">{formatNumber(stats.userCount)}</div>
              <div class="stat-label">{$_('admin.users')}</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">{formatNumber(stats.repoCount)}</div>
              <div class="stat-label">{$_('admin.repos')}</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">{formatNumber(stats.recordCount)}</div>
              <div class="stat-label">{$_('admin.records')}</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">{formatBytes(stats.blobStorageBytes)}</div>
              <div class="stat-label">{$_('admin.blobStorage')}</div>
            </div>
          </div>
          <button class="refresh-btn" onclick={loadStats}>{$_('admin.refreshStats')}</button>
        </section>
      {/if}
      <section>
        <h2>{$_('admin.userManagement')}</h2>
        <form class="search-form" onsubmit={handleSearch}>
          <input
            type="text"
            bind:value={handleSearchQuery}
            placeholder={$_('admin.searchPlaceholder')}
            disabled={usersLoading}
          />
          <button type="submit" disabled={usersLoading}>
            {usersLoading ? $_('admin.loading') : $_('admin.searchUsers')}
          </button>
        </form>
        {#if usersError}
          <div class="message error">{usersError}</div>
        {/if}
        {#if showUsers}
          <div class="user-list">
            {#if users.length === 0}
              <p class="no-results">{$_('admin.noUsers')}</p>
            {:else}
              <table>
                <thead>
                  <tr>
                    <th>{$_('admin.handle')}</th>
                    <th>{$_('admin.email')}</th>
                    <th>{$_('admin.status')}</th>
                    <th>{$_('admin.created')}</th>
                  </tr>
                </thead>
                <tbody>
                  {#each users as user}
                    <tr class="clickable" onclick={() => selectUser(user.did)}>
                      <td class="handle">@{user.handle}</td>
                      <td class="email">{user.email || '-'}</td>
                      <td>
                        {#if user.deactivatedAt}
                          <span class="badge deactivated">{$_('admin.deactivated')}</span>
                        {:else if user.emailConfirmedAt}
                          <span class="badge verified">{$_('admin.verified')}</span>
                        {:else}
                          <span class="badge unverified">{$_('admin.unverified')}</span>
                        {/if}
                      </td>
                      <td class="date">{formatDate(user.indexedAt)}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
              {#if usersCursor}
                <button class="load-more" onclick={() => loadUsers(false)} disabled={usersLoading}>
                  {usersLoading ? $_('admin.loading') : $_('admin.loadMore')}
                </button>
              {/if}
            {/if}
          </div>
        {/if}
      </section>
      <section>
        <h2>{$_('admin.inviteCodes')}</h2>
        <div class="section-actions">
          <button onclick={() => loadInvites(true)} disabled={invitesLoading}>
            {invitesLoading ? $_('admin.loading') : showInvites ? $_('admin.refresh') : $_('admin.loadInviteCodes')}
          </button>
        </div>
        {#if invitesError}
          <div class="message error">{invitesError}</div>
        {/if}
        {#if showInvites}
          <div class="invite-list">
            {#if invites.length === 0}
              <p class="no-results">{$_('admin.noInvites')}</p>
            {:else}
              <table>
                <thead>
                  <tr>
                    <th>{$_('admin.code')}</th>
                    <th>{$_('admin.available')}</th>
                    <th>{$_('admin.uses')}</th>
                    <th>{$_('admin.status')}</th>
                    <th>{$_('admin.created')}</th>
                    <th>{$_('admin.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {#each invites as invite}
                    <tr class:disabled-row={invite.disabled}>
                      <td class="code">{invite.code}</td>
                      <td>{invite.available}</td>
                      <td>{invite.uses.length}</td>
                      <td>
                        {#if invite.disabled}
                          <span class="badge deactivated">{$_('admin.disabled')}</span>
                        {:else if invite.available === 0}
                          <span class="badge unverified">{$_('admin.exhausted')}</span>
                        {:else}
                          <span class="badge verified">{$_('admin.active')}</span>
                        {/if}
                      </td>
                      <td class="date">{formatDate(invite.createdAt)}</td>
                      <td>
                        {#if !invite.disabled}
                          <button class="action-btn danger" onclick={() => disableInvite(invite.code)}>
                            {$_('admin.disable')}
                          </button>
                        {:else}
                          <span class="muted">-</span>
                        {/if}
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
              {#if invitesCursor}
                <button class="load-more" onclick={() => loadInvites(false)} disabled={invitesLoading}>
                  {invitesLoading ? $_('admin.loading') : $_('admin.loadMore')}
                </button>
              {/if}
            {/if}
          </div>
        {/if}
      </section>
    {/if}
  </div>
  {#if selectedUser}
    <div class="modal-overlay" onclick={closeUserDetail} onkeydown={(e) => e.key === 'Escape' && closeUserDetail()} role="presentation">
      <div class="modal" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="dialog" aria-modal="true" tabindex="-1">
        <div class="modal-header">
          <h2>{$_('admin.userDetails')}</h2>
          <button class="close-btn" onclick={closeUserDetail}>&times;</button>
        </div>
        {#if userDetailLoading}
          <p class="loading">{$_('admin.loading')}</p>
        {:else}
          <div class="modal-body">
            <dl class="user-details">
              <dt>{$_('admin.handle')}</dt>
              <dd>@{selectedUser.handle}</dd>
              <dt>{$_('admin.did')}</dt>
              <dd class="mono">{selectedUser.did}</dd>
              <dt>{$_('admin.email')}</dt>
              <dd>{selectedUser.email || '-'}</dd>
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
              <dt>{$_('admin.created')}</dt>
              <dd>{formatDateTime(selectedUser.indexedAt)}</dd>
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
                class="action-btn"
                onclick={toggleUserInvites}
                disabled={userActionLoading}
              >
                {selectedUser.invitesDisabled ? $_('admin.enableInvites') : $_('admin.disableInvites')}
              </button>
              <button
                class="action-btn danger"
                onclick={deleteUser}
                disabled={userActionLoading}
              >
                {$_('admin.deleteAccount')}
              </button>
            </div>
          </div>
        {/if}
      </div>
    </div>
  {/if}
{:else if auth.loading}
  <div class="loading">{$_('admin.loading')}</div>
{/if}
<style>
  .page {
    max-width: var(--width-xl);
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

  .loading {
    text-align: center;
    color: var(--text-secondary);
    padding: var(--space-7);
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

  .config-form {
    max-width: 500px;
  }

  .form-group {
    margin-bottom: var(--space-4);
  }

  .form-group label {
    display: block;
    font-weight: var(--font-medium);
    margin-bottom: var(--space-2);
    font-size: var(--text-sm);
  }

  .form-group input {
    width: 100%;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    background: var(--bg-input);
    color: var(--text-primary);
  }

  .form-group input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .help-text {
    display: block;
    font-size: var(--text-xs);
    color: var(--text-secondary);
    margin-top: var(--space-1);
  }

  .config-form button {
    padding: var(--space-2) var(--space-4);
    background: var(--accent);
    color: var(--text-inverse);
    border: none;
    border-radius: var(--radius-md);
    cursor: pointer;
    font-size: var(--text-sm);
  }

  .config-form button:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .config-form button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .subsection-title {
    font-size: var(--text-sm);
    font-weight: var(--font-semibold);
    color: var(--text-primary);
    margin: var(--space-5) 0 var(--space-2) 0;
    padding-top: var(--space-4);
    border-top: 1px solid var(--border-color);
  }

  .theme-hint {
    font-size: var(--text-xs);
    color: var(--text-secondary);
    margin-bottom: var(--space-4);
  }

  .color-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-4);
    margin-bottom: var(--space-4);
  }

  @media (max-width: 500px) {
    .color-grid {
      grid-template-columns: 1fr;
    }
  }

  .color-group label {
    display: block;
    font-size: var(--text-xs);
    font-weight: var(--font-medium);
    color: var(--text-secondary);
    margin-bottom: var(--space-1);
  }

  .color-group input[type="text"] {
    width: 100%;
  }

  .logo-upload {
    margin-top: var(--space-2);
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
    border: 1px solid var(--border-color);
    background: var(--bg-input);
  }

  .remove-logo {
    background: transparent;
    color: var(--error-text);
    border: 1px solid var(--error-border);
    padding: var(--space-1) var(--space-2);
    font-size: var(--text-xs);
  }

  .remove-logo:hover:not(:disabled) {
    background: var(--error-bg);
  }

  section {
    background: var(--bg-secondary);
    padding: var(--space-6);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-6);
  }

  section h2 {
    margin: 0 0 var(--space-4) 0;
    font-size: var(--text-lg);
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: var(--space-4);
    margin-bottom: var(--space-4);
  }

  .stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-xl);
    padding: var(--space-4);
    text-align: center;
  }

  .stat-value {
    font-size: var(--text-xl);
    font-weight: var(--font-semibold);
    color: var(--accent);
  }

  .stat-label {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin-top: var(--space-1);
  }

  .refresh-btn {
    padding: var(--space-2) var(--space-4);
    background: transparent;
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    cursor: pointer;
    color: var(--text-primary);
  }

  .refresh-btn:hover {
    background: var(--bg-card);
    border-color: var(--accent);
  }

  .search-form {
    display: flex;
    gap: var(--space-2);
    margin-bottom: var(--space-4);
  }

  .search-form input {
    flex: 1;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    background: var(--bg-input);
    color: var(--text-primary);
  }

  .search-form input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .search-form button {
    padding: var(--space-2) var(--space-4);
    background: var(--accent);
    color: var(--text-inverse);
    border: none;
    border-radius: var(--radius-md);
    cursor: pointer;
    font-size: var(--text-sm);
  }

  .search-form button:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .search-form button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .user-list {
    margin-top: var(--space-4);
  }

  .no-results {
    color: var(--text-secondary);
    text-align: center;
    padding: var(--space-4);
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--text-sm);
  }

  th, td {
    padding: var(--space-3) var(--space-2);
    text-align: left;
    border-bottom: 1px solid var(--border-color);
  }

  th {
    font-weight: var(--font-semibold);
    color: var(--text-secondary);
    font-size: var(--text-xs);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .handle {
    font-weight: var(--font-medium);
  }

  .email {
    color: var(--text-secondary);
  }

  .date {
    color: var(--text-secondary);
    font-size: var(--text-xs);
  }

  .badge {
    display: inline-block;
    padding: 2px var(--space-2);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
  }

  .badge.verified {
    background: var(--success-bg);
    color: var(--success-text);
  }

  .badge.unverified {
    background: var(--warning-bg);
    color: var(--warning-text);
  }

  .badge.deactivated {
    background: var(--error-bg);
    color: var(--error-text);
  }

  .load-more {
    display: block;
    width: 100%;
    padding: var(--space-3);
    margin-top: var(--space-4);
    background: transparent;
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    cursor: pointer;
    color: var(--text-primary);
    font-size: var(--text-sm);
  }

  .load-more:hover:not(:disabled) {
    background: var(--bg-card);
    border-color: var(--accent);
  }

  .load-more:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .section-actions {
    margin-bottom: var(--space-4);
  }

  .section-actions button {
    padding: var(--space-2) var(--space-4);
    background: var(--accent);
    color: var(--text-inverse);
    border: none;
    border-radius: var(--radius-md);
    cursor: pointer;
    font-size: var(--text-sm);
  }

  .section-actions button:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .section-actions button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .invite-list {
    margin-top: var(--space-4);
  }

  .code {
    font-family: monospace;
    font-size: var(--text-xs);
  }

  .disabled-row {
    opacity: 0.5;
  }

  .action-btn {
    padding: var(--space-1) var(--space-2);
    font-size: var(--text-xs);
    border: none;
    border-radius: var(--radius-md);
    cursor: pointer;
  }

  .action-btn.danger {
    background: var(--error-text);
    color: var(--text-inverse);
  }

  .action-btn.danger:hover {
    background: #900;
  }

  .muted {
    color: var(--text-muted);
  }

  .clickable {
    cursor: pointer;
  }

  .clickable:hover {
    background: var(--bg-card);
  }

  .modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .modal {
    background: var(--bg-card);
    border-radius: var(--radius-xl);
    max-width: 500px;
    width: 90%;
    max-height: 90vh;
    overflow-y: auto;
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-4) var(--space-6);
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
    padding: var(--space-6);
  }

  .user-details {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: var(--space-2) var(--space-4);
    margin: 0 0 var(--space-6) 0;
  }

  .user-details dt {
    font-weight: var(--font-medium);
    color: var(--text-secondary);
  }

  .user-details dd {
    margin: 0;
  }

  .mono {
    font-family: monospace;
    font-size: var(--text-xs);
    word-break: break-all;
  }

  .modal-actions {
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  .modal-actions .action-btn {
    padding: var(--space-2) var(--space-4);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    background: transparent;
    cursor: pointer;
    font-size: var(--text-sm);
    color: var(--text-primary);
  }

  .modal-actions .action-btn:hover:not(:disabled) {
    background: var(--bg-secondary);
  }

  .modal-actions .action-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .modal-actions .action-btn.danger {
    border-color: var(--error-text);
    color: var(--error-text);
  }

  .modal-actions .action-btn.danger:hover:not(:disabled) {
    background: var(--error-bg);
  }
</style>
