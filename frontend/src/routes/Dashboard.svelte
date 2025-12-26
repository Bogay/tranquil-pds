<script lang="ts">
  import { getAuthState, logout, switchAccount } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'
  import { api } from '../lib/api'
  import { onMount } from 'svelte'

  const auth = getAuthState()
  let dropdownOpen = $state(false)
  let switching = $state(false)
  let inviteCodesEnabled = $state(false)

  onMount(async () => {
    try {
      const serverInfo = await api.describeServer()
      inviteCodesEnabled = serverInfo.inviteCodeRequired
    } catch {
      inviteCodesEnabled = false
    }
  })

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
      <h1>{$_('dashboard.title')}</h1>
      <div class="account-dropdown">
        <button class="account-trigger" onclick={toggleDropdown} disabled={switching}>
          <span class="account-handle">@{auth.session.handle}</span>
          <span class="dropdown-arrow">{dropdownOpen ? '▲' : '▼'}</span>
        </button>
        {#if dropdownOpen}
          <div class="dropdown-menu">
            {#if otherAccounts.length > 0}
              <div class="dropdown-section">
                <span class="dropdown-label">{$_('dashboard.switchAccount')}</span>
                {#each otherAccounts as account}
                  <button type="button" class="dropdown-item" onclick={() => handleSwitchAccount(account.did)}>
                    @{account.handle}
                  </button>
                {/each}
              </div>
              <div class="dropdown-divider"></div>
            {/if}
            <button type="button" class="dropdown-item" onclick={() => { dropdownOpen = false; navigate('/login') }}>
              {$_('dashboard.addAnotherAccount')}
            </button>
            <div class="dropdown-divider"></div>
            <button type="button" class="dropdown-item logout-item" onclick={handleLogout}>
              {$_('dashboard.signOut', { values: { handle: auth.session.handle } })}
            </button>
          </div>
        {/if}
      </div>
    </header>

    {#if auth.session.status === 'deactivated' || auth.session.active === false}
      <div class="deactivated-banner">
        <strong>{$_('dashboard.deactivatedTitle')}</strong>
        <p>{$_('dashboard.deactivatedMessage')}</p>
      </div>
    {/if}

    <section class="account-overview">
      <h2>{$_('dashboard.accountOverview')}</h2>
      <dl>
        <dt>{$_('dashboard.handle')}</dt>
        <dd>
          @{auth.session.handle}
          {#if auth.session.isAdmin}
            <span class="badge admin">{$_('dashboard.admin')}</span>
          {/if}
          {#if auth.session.status === 'deactivated' || auth.session.active === false}
            <span class="badge deactivated">{$_('dashboard.deactivated')}</span>
          {/if}
        </dd>
        <dt>{$_('dashboard.did')}</dt>
        <dd class="mono">{auth.session.did}</dd>
        {#if auth.session.preferredChannel}
          <dt>{$_('dashboard.primaryContact')}</dt>
          <dd>
            {#if auth.session.preferredChannel === 'email'}
              {auth.session.email || $_('register.email')}
            {:else if auth.session.preferredChannel === 'discord'}
              {$_('register.discord')}
            {:else if auth.session.preferredChannel === 'telegram'}
              {$_('register.telegram')}
            {:else if auth.session.preferredChannel === 'signal'}
              {$_('register.signal')}
            {:else}
              {auth.session.preferredChannel}
            {/if}
            {#if auth.session.preferredChannelVerified}
              <span class="badge success">{$_('dashboard.verified')}</span>
            {:else}
              <span class="badge warning">{$_('dashboard.unverified')}</span>
            {/if}
          </dd>
        {:else if auth.session.email}
          <dt>{$_('register.email')}</dt>
          <dd>
            {auth.session.email}
            {#if auth.session.emailConfirmed}
              <span class="badge success">{$_('dashboard.verified')}</span>
            {:else}
              <span class="badge warning">{$_('dashboard.unverified')}</span>
            {/if}
          </dd>
        {/if}
      </dl>
    </section>

    <nav class="nav-grid">
      <a href="#/app-passwords" class="nav-card">
        <h3>{$_('dashboard.navAppPasswords')}</h3>
        <p>{$_('dashboard.navAppPasswordsDesc')}</p>
      </a>
      <a href="#/sessions" class="nav-card">
        <h3>{$_('dashboard.navSessions')}</h3>
        <p>{$_('dashboard.navSessionsDesc')}</p>
      </a>
      {#if inviteCodesEnabled}
        <a href="#/invite-codes" class="nav-card">
          <h3>{$_('dashboard.navInviteCodes')}</h3>
          <p>{$_('dashboard.navInviteCodesDesc')}</p>
        </a>
      {/if}
      <a href="#/settings" class="nav-card">
        <h3>{$_('dashboard.navSettings')}</h3>
        <p>{$_('dashboard.navSettingsDesc')}</p>
      </a>
      <a href="#/security" class="nav-card">
        <h3>{$_('dashboard.navSecurity')}</h3>
        <p>{$_('dashboard.navSecurityDesc')}</p>
      </a>
      <a href="#/comms" class="nav-card">
        <h3>{$_('dashboard.navComms')}</h3>
        <p>{$_('dashboard.navCommsDesc')}</p>
      </a>
      <a href="#/repo" class="nav-card">
        <h3>{$_('dashboard.navRepo')}</h3>
        <p>{$_('dashboard.navRepoDesc')}</p>
      </a>
      <a href="#/controllers" class="nav-card">
        <h3>{$_('dashboard.navDelegation')}</h3>
        <p>{$_('dashboard.navDelegationDesc')}</p>
      </a>
      {#if auth.session.isAdmin}
        <a href="#/admin" class="nav-card admin-card">
          <h3>{$_('dashboard.navAdmin')}</h3>
          <p>{$_('dashboard.navAdminDesc')}</p>
        </a>
      {/if}
    </nav>
  </div>
{:else if auth.loading}
  <div class="loading">{$_('common.loading')}</div>
{/if}

<style>
  .dashboard {
    max-width: var(--width-xl);
    margin: 0 auto;
    padding: var(--space-7);
  }

  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--space-7);
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
    gap: var(--space-3);
    padding: var(--space-3) var(--space-5);
    background: transparent;
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
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
    font-weight: var(--font-medium);
  }

  .dropdown-arrow {
    font-size: 0.625rem;
    color: var(--text-secondary);
  }

  .dropdown-menu {
    position: absolute;
    top: 100%;
    right: 0;
    margin-top: var(--space-2);
    min-width: 200px;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-xl);
    box-shadow: var(--shadow-lg);
    z-index: 100;
    overflow: hidden;
  }

  .dropdown-section {
    padding: var(--space-3) 0;
  }

  .dropdown-label {
    display: block;
    padding: var(--space-2) var(--space-5);
    font-size: var(--text-xs);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .dropdown-item {
    display: block;
    width: 100%;
    padding: var(--space-4) var(--space-5);
    background: transparent;
    border: none;
    text-align: left;
    cursor: pointer;
    color: var(--text-primary);
    font-size: var(--text-sm);
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
    padding: var(--space-6);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-7);
  }

  section h2 {
    margin: 0 0 var(--space-4) 0;
    font-size: var(--text-xl);
  }

  dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: var(--space-3) var(--space-5);
    margin: 0;
  }

  dt {
    font-weight: var(--font-medium);
    color: var(--text-secondary);
  }

  dd {
    margin: 0;
  }

  .mono {
    font-family: ui-monospace, monospace;
    font-size: var(--text-sm);
    word-break: break-all;
  }

  .badge {
    display: inline-block;
    padding: var(--space-1) var(--space-3);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
    margin-left: var(--space-3);
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
    color: var(--text-inverse);
  }

  .badge.deactivated {
    background: var(--warning-bg);
    color: var(--warning-text);
    border: 1px solid var(--warning-border);
  }

  .nav-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: var(--space-4);
  }

  .nav-card {
    display: block;
    padding: var(--space-6);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-xl);
    text-decoration: none;
    color: inherit;
    transition: border-color var(--transition-normal), box-shadow var(--transition-normal);
  }

  .nav-card:hover {
    border-color: var(--accent);
    box-shadow: 0 2px 8px var(--accent-muted);
  }

  .nav-card h3 {
    margin: 0 0 var(--space-3) 0;
    color: var(--accent);
  }

  .nav-card p {
    margin: 0;
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  .nav-card.admin-card {
    border-color: var(--accent);
    background: linear-gradient(135deg, var(--bg-card) 0%, var(--accent-muted) 100%);
  }

  .nav-card.admin-card:hover {
    box-shadow: 0 2px 12px var(--accent-muted);
  }

  .loading {
    text-align: center;
    padding: var(--space-9);
    color: var(--text-secondary);
  }

  .deactivated-banner {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius-xl);
    padding: var(--space-5) var(--space-6);
    margin-bottom: var(--space-7);
  }

  .deactivated-banner strong {
    color: var(--warning-text);
    font-size: var(--text-base);
  }

  .deactivated-banner p {
    margin: var(--space-3) 0 0 0;
    color: var(--warning-text);
    font-size: var(--text-sm);
  }
</style>
