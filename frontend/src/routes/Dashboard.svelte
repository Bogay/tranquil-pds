<script lang="ts">
  import { getAuthState, logout, switchAccount } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  const auth = getAuthState()
  let dropdownOpen = $state(false)
  let switching = $state(false)
  $effect(() => {
    if (!auth.loading && !auth.session) {
      navigate('/login')
    }
  })
  async function handleLogout() {
    await logout()
    navigate('/login')
  }
  async function handleSwitchAccount(did: string) {
    switching = true
    dropdownOpen = false
    try {
      await switchAccount(did)
    } catch {
      navigate('/login')
    } finally {
      switching = false
    }
  }
  function toggleDropdown() {
    dropdownOpen = !dropdownOpen
  }
  function closeDropdown(e: MouseEvent) {
    const target = e.target as HTMLElement
    if (!target.closest('.account-dropdown')) {
      dropdownOpen = false
    }
  }
  $effect(() => {
    if (dropdownOpen) {
      document.addEventListener('click', closeDropdown)
      return () => document.removeEventListener('click', closeDropdown)
    }
  })
  let otherAccounts = $derived(
    auth.savedAccounts.filter(a => a.did !== auth.session?.did)
  )
</script>
{#if auth.session}
  <div class="dashboard">
    <header>
      <h1>Dashboard</h1>
      <div class="account-dropdown">
        <button class="account-trigger" onclick={toggleDropdown} disabled={switching}>
          <span class="account-handle">@{auth.session.handle}</span>
          <span class="dropdown-arrow">{dropdownOpen ? '▲' : '▼'}</span>
        </button>
        {#if dropdownOpen}
          <div class="dropdown-menu">
            {#if otherAccounts.length > 0}
              <div class="dropdown-section">
                <span class="dropdown-label">Switch Account</span>
                {#each otherAccounts as account}
                  <button
                    type="button"
                    class="dropdown-item"
                    onclick={() => handleSwitchAccount(account.did)}
                  >
                    @{account.handle}
                  </button>
                {/each}
              </div>
              <div class="dropdown-divider"></div>
            {/if}
            <button
              type="button"
              class="dropdown-item"
              onclick={() => { dropdownOpen = false; navigate('/login') }}
            >
              Add another account
            </button>
            <div class="dropdown-divider"></div>
            <button type="button" class="dropdown-item logout-item" onclick={handleLogout}>
              Sign out @{auth.session.handle}
            </button>
          </div>
        {/if}
      </div>
    </header>
    <section class="account-overview">
      <h2>Account Overview</h2>
      <dl>
        <dt>Handle</dt>
        <dd>
          @{auth.session.handle}
          {#if auth.session.isAdmin}
            <span class="badge admin">Admin</span>
          {/if}
        </dd>
        <dt>DID</dt>
        <dd class="mono">{auth.session.did}</dd>
        {#if auth.session.preferredChannel}
          <dt>Primary Contact</dt>
          <dd>
            {#if auth.session.preferredChannel === 'email'}
              {auth.session.email || 'Email'}
            {:else if auth.session.preferredChannel === 'discord'}
              Discord
            {:else if auth.session.preferredChannel === 'telegram'}
              Telegram
            {:else if auth.session.preferredChannel === 'signal'}
              Signal
            {:else}
              {auth.session.preferredChannel}
            {/if}
            {#if auth.session.preferredChannelVerified}
              <span class="badge success">Verified</span>
            {:else}
              <span class="badge warning">Unverified</span>
            {/if}
          </dd>
        {:else if auth.session.email}
          <dt>Email</dt>
          <dd>
            {auth.session.email}
            {#if auth.session.emailConfirmed}
              <span class="badge success">Verified</span>
            {:else}
              <span class="badge warning">Unverified</span>
            {/if}
          </dd>
        {/if}
      </dl>
    </section>
    <nav class="nav-grid">
      <a href="#/app-passwords" class="nav-card">
        <h3>App Passwords</h3>
        <p>Manage passwords for third-party apps</p>
      </a>
      <a href="#/sessions" class="nav-card">
        <h3>Active Sessions</h3>
        <p>View and manage your login sessions</p>
      </a>
      <a href="#/invite-codes" class="nav-card">
        <h3>Invite Codes</h3>
        <p>View and create invite codes</p>
      </a>
      <a href="#/settings" class="nav-card">
        <h3>Account Settings</h3>
        <p>Email, password, handle, and more</p>
      </a>
      <a href="#/notifications" class="nav-card">
        <h3>Notification Preferences</h3>
        <p>Discord, Telegram, Signal channels</p>
      </a>
      <a href="#/repo" class="nav-card">
        <h3>Repository Explorer</h3>
        <p>Browse and manage raw AT Protocol records</p>
      </a>
      {#if auth.session.isAdmin}
        <a href="#/admin" class="nav-card admin-card">
          <h3>Admin Panel</h3>
          <p>Server stats and admin operations</p>
        </a>
      {/if}
    </nav>
  </div>
{:else if auth.loading}
  <div class="loading">Loading...</div>
{/if}
<style>
  .dashboard {
    max-width: 800px;
    margin: 0 auto;
    padding: 2rem;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
  }
  header h1 {
    margin: 0;
  }
  .account-dropdown {
    position: relative;
  }
  .account-trigger {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    background: transparent;
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    cursor: pointer;
    color: var(--text-primary);
  }
  .account-trigger:hover:not(:disabled) {
    background: var(--bg-secondary);
  }
  .account-trigger:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .account-trigger .account-handle {
    font-weight: 500;
  }
  .dropdown-arrow {
    font-size: 0.625rem;
    color: var(--text-secondary);
  }
  .dropdown-menu {
    position: absolute;
    top: 100%;
    right: 0;
    margin-top: 0.25rem;
    min-width: 200px;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    z-index: 100;
    overflow: hidden;
  }
  .dropdown-section {
    padding: 0.5rem 0;
  }
  .dropdown-label {
    display: block;
    padding: 0.25rem 1rem;
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .dropdown-item {
    display: block;
    width: 100%;
    padding: 0.75rem 1rem;
    background: transparent;
    border: none;
    text-align: left;
    cursor: pointer;
    color: var(--text-primary);
    font-size: 0.875rem;
  }
  .dropdown-item:hover {
    background: var(--bg-secondary);
  }
  .dropdown-item.logout-item {
    color: var(--error-text);
  }
  .dropdown-divider {
    height: 1px;
    background: var(--border-color);
    margin: 0;
  }
  section {
    background: var(--bg-secondary);
    padding: 1.5rem;
    border-radius: 8px;
    margin-bottom: 2rem;
  }
  section h2 {
    margin: 0 0 1rem 0;
    font-size: 1.25rem;
  }
  dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 0.5rem 1rem;
    margin: 0;
  }
  dt {
    font-weight: 500;
    color: var(--text-secondary);
  }
  dd {
    margin: 0;
  }
  .mono {
    font-family: monospace;
    font-size: 0.875rem;
    word-break: break-all;
  }
  .badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    margin-left: 0.5rem;
  }
  .badge.success {
    background: var(--success-bg);
    color: var(--success-text);
  }
  .badge.warning {
    background: var(--warning-bg);
    color: var(--warning-text);
  }
  .badge.admin {
    background: var(--accent);
    color: white;
  }
  .nav-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
  }
  .nav-card {
    display: block;
    padding: 1.5rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    text-decoration: none;
    color: inherit;
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  .nav-card:hover {
    border-color: var(--accent);
    box-shadow: 0 2px 8px rgba(77, 166, 255, 0.15);
  }
  .nav-card h3 {
    margin: 0 0 0.5rem 0;
    color: var(--accent);
  }
  .nav-card p {
    margin: 0;
    color: var(--text-secondary);
    font-size: 0.875rem;
  }
  .nav-card.admin-card {
    border-color: var(--accent);
    background: linear-gradient(135deg, var(--bg-card) 0%, rgba(77, 166, 255, 0.05) 100%);
  }
  .nav-card.admin-card:hover {
    box-shadow: 0 2px 12px rgba(77, 166, 255, 0.25);
  }
  .loading {
    text-align: center;
    padding: 4rem;
    color: var(--text-secondary);
  }
</style>
