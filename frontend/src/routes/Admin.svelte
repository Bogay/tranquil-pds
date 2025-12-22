<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import { formatDate, formatDateTime } from '../lib/date'
  const auth = getAuthState()
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
    }
  })
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
      <a href="#/dashboard" class="back">&larr; Dashboard</a>
      <h1>Admin Panel</h1>
    </header>
    {#if loading}
      <p class="loading">Loading...</p>
    {:else}
      {#if error}
        <div class="message error">{error}</div>
      {/if}
      {#if stats}
        <section>
          <h2>Server Statistics</h2>
          <div class="stats-grid">
            <div class="stat-card">
              <div class="stat-value">{formatNumber(stats.userCount)}</div>
              <div class="stat-label">Users</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">{formatNumber(stats.repoCount)}</div>
              <div class="stat-label">Repositories</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">{formatNumber(stats.recordCount)}</div>
              <div class="stat-label">Records</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">{formatBytes(stats.blobStorageBytes)}</div>
              <div class="stat-label">Blob Storage</div>
            </div>
          </div>
          <button class="refresh-btn" onclick={loadStats}>Refresh Stats</button>
        </section>
      {/if}
      <section>
        <h2>User Management</h2>
        <form class="search-form" onsubmit={handleSearch}>
          <input
            type="text"
            bind:value={handleSearchQuery}
            placeholder="Search by handle (optional)"
            disabled={usersLoading}
          />
          <button type="submit" disabled={usersLoading}>
            {usersLoading ? 'Loading...' : 'Search Users'}
          </button>
        </form>
        {#if usersError}
          <div class="message error">{usersError}</div>
        {/if}
        {#if showUsers}
          <div class="user-list">
            {#if users.length === 0}
              <p class="no-results">No users found</p>
            {:else}
              <table>
                <thead>
                  <tr>
                    <th>Handle</th>
                    <th>Email</th>
                    <th>Status</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {#each users as user}
                    <tr class="clickable" onclick={() => selectUser(user.did)}>
                      <td class="handle">@{user.handle}</td>
                      <td class="email">{user.email || '-'}</td>
                      <td>
                        {#if user.deactivatedAt}
                          <span class="badge deactivated">Deactivated</span>
                        {:else if user.emailConfirmedAt}
                          <span class="badge verified">Verified</span>
                        {:else}
                          <span class="badge unverified">Unverified</span>
                        {/if}
                      </td>
                      <td class="date">{formatDate(user.indexedAt)}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
              {#if usersCursor}
                <button class="load-more" onclick={() => loadUsers(false)} disabled={usersLoading}>
                  {usersLoading ? 'Loading...' : 'Load More'}
                </button>
              {/if}
            {/if}
          </div>
        {/if}
      </section>
      <section>
        <h2>Invite Codes</h2>
        <div class="section-actions">
          <button onclick={() => loadInvites(true)} disabled={invitesLoading}>
            {invitesLoading ? 'Loading...' : showInvites ? 'Refresh' : 'Load Invite Codes'}
          </button>
        </div>
        {#if invitesError}
          <div class="message error">{invitesError}</div>
        {/if}
        {#if showInvites}
          <div class="invite-list">
            {#if invites.length === 0}
              <p class="no-results">No invite codes found</p>
            {:else}
              <table>
                <thead>
                  <tr>
                    <th>Code</th>
                    <th>Available</th>
                    <th>Uses</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Actions</th>
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
                          <span class="badge deactivated">Disabled</span>
                        {:else if invite.available === 0}
                          <span class="badge unverified">Exhausted</span>
                        {:else}
                          <span class="badge verified">Active</span>
                        {/if}
                      </td>
                      <td class="date">{formatDate(invite.createdAt)}</td>
                      <td>
                        {#if !invite.disabled}
                          <button class="action-btn danger" onclick={() => disableInvite(invite.code)}>
                            Disable
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
                  {invitesLoading ? 'Loading...' : 'Load More'}
                </button>
              {/if}
            {/if}
          </div>
        {/if}
      </section>
    {/if}
  </div>
  {#if selectedUser}
    <div class="modal-overlay" onclick={closeUserDetail} role="presentation">
      <div class="modal" onclick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div class="modal-header">
          <h2>User Details</h2>
          <button class="close-btn" onclick={closeUserDetail}>&times;</button>
        </div>
        {#if userDetailLoading}
          <p class="loading">Loading...</p>
        {:else}
          <div class="modal-body">
            <dl class="user-details">
              <dt>Handle</dt>
              <dd>@{selectedUser.handle}</dd>
              <dt>DID</dt>
              <dd class="mono">{selectedUser.did}</dd>
              <dt>Email</dt>
              <dd>{selectedUser.email || '-'}</dd>
              <dt>Status</dt>
              <dd>
                {#if selectedUser.deactivatedAt}
                  <span class="badge deactivated">Deactivated</span>
                {:else if selectedUser.emailConfirmedAt}
                  <span class="badge verified">Verified</span>
                {:else}
                  <span class="badge unverified">Unverified</span>
                {/if}
              </dd>
              <dt>Created</dt>
              <dd>{formatDateTime(selectedUser.indexedAt)}</dd>
              <dt>Invites</dt>
              <dd>
                {#if selectedUser.invitesDisabled}
                  <span class="badge deactivated">Disabled</span>
                {:else}
                  <span class="badge verified">Enabled</span>
                {/if}
              </dd>
            </dl>
            <div class="modal-actions">
              <button
                class="action-btn"
                onclick={toggleUserInvites}
                disabled={userActionLoading}
              >
                {selectedUser.invitesDisabled ? 'Enable Invites' : 'Disable Invites'}
              </button>
              <button
                class="action-btn danger"
                onclick={deleteUser}
                disabled={userActionLoading}
              >
                Delete Account
              </button>
            </div>
          </div>
        {/if}
      </div>
    </div>
  {/if}
{:else if auth.loading}
  <div class="loading">Loading...</div>
{/if}
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
