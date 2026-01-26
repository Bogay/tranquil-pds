<script lang="ts">
  import {
    getAuthState,
    logout,
    switchAccount,
    type SavedAccount,
  } from '../lib/auth.svelte'
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'
  import { api } from '../lib/api'
  import { isOk } from '../lib/types/result'
  import { unsafeAsDid, type Did } from '../lib/types/branded'
  import type { Session } from '../lib/types/api'
  import { isMigrated, isDeactivated, getSessionEmail, isEmailVerified } from '../lib/types/api'
  import { onMount } from 'svelte'

  const auth = $derived(getAuthState())
  let dropdownOpen = $state(false)
  let switching = $state(false)
  let inviteCodesEnabled = $state(false)

  function getSession(): Session | null {
    return auth.kind === 'authenticated' ? auth.session : null
  }

  function getSavedAccounts(): readonly SavedAccount[] {
    return auth.savedAccounts
  }

  function isLoading(): boolean {
    return auth.kind === 'loading'
  }

  const session = $derived(getSession())
  const savedAccounts = $derived(getSavedAccounts())
  const loading = $derived(isLoading())
  const isDidWeb = $derived(session?.did?.startsWith('did:web:') ?? false)
  const otherAccounts = $derived(savedAccounts.filter(a => a.did !== session?.did))

  onMount(async () => {
    try {
      const serverInfo = await api.describeServer()
      inviteCodesEnabled = serverInfo.inviteCodeRequired
    } catch {
      inviteCodesEnabled = false
    }
  })

  $effect(() => {
    if (!loading && !session) {
      navigate(routes.login)
    }
  })

  async function handleLogout() {
    await logout()
    navigate(routes.login)
  }

  async function handleSwitchAccount(did: Did) {
    switching = true
    dropdownOpen = false
    const result = await switchAccount(did)
    if (!isOk(result)) {
      navigate(routes.login)
    }
    switching = false
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
    }
    return () => {
      if (dropdownOpen) {
        document.removeEventListener('click', closeDropdown)
      }
    }
  })
</script>

{#if session}
  <div class="dashboard">
    <header>
      <h1>{$_('dashboard.title')}</h1>
      <div class="account-dropdown">
        <button class="account-trigger" onclick={toggleDropdown} disabled={switching}>
          <span class="account-handle">@{session.handle}</span>
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
            <button type="button" class="dropdown-item" onclick={() => { dropdownOpen = false; navigate(routes.login) }}>
              {$_('dashboard.addAnotherAccount')}
            </button>
            <div class="dropdown-divider"></div>
            <button type="button" class="dropdown-item logout-item" onclick={handleLogout}>
              {$_('dashboard.signOut', { values: { handle: session.handle } })}
            </button>
          </div>
        {/if}
      </div>
    </header>

    {#if session.accountKind === 'migrated'}
      <div class="migrated-banner">
        <strong>{$_('dashboard.migratedTitle')}</strong>
        <p>{$_('dashboard.migratedMessage', { values: { pds: session.migratedToPds || 'another PDS' } })}</p>
      </div>
    {:else if session.accountKind === 'deactivated'}
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
          @{session.handle}
          {#if session.isAdmin}
            <span class="badge admin">{$_('dashboard.admin')}</span>
          {/if}
          {#if session.accountKind === 'migrated'}
            <span class="badge migrated">{$_('dashboard.migrated')}</span>
          {:else if session.accountKind === 'deactivated'}
            <span class="badge deactivated">{$_('dashboard.deactivated')}</span>
          {/if}
        </dd>
        <dt>{$_('dashboard.did')}</dt>
        <dd class="mono">{session.did}</dd>
        {#if session.contactKind === 'channel'}
          <dt>{$_('dashboard.primaryContact')}</dt>
          <dd>
            {#if session.preferredChannel === 'email'}
              {session.email || $_('register.email')}
            {:else if session.preferredChannel === 'discord'}
              {$_('register.discord')}
            {:else if session.preferredChannel === 'telegram'}
              {$_('register.telegram')}
            {:else if session.preferredChannel === 'signal'}
              {$_('register.signal')}
            {:else}
              {session.preferredChannel}
            {/if}
            {#if session.preferredChannelVerified}
              <span class="badge success">{$_('dashboard.verified')}</span>
            {:else}
              <span class="badge warning">{$_('dashboard.unverified')}</span>
            {/if}
          </dd>
        {:else if session.contactKind === 'email'}
          <dt>{$_('register.email')}</dt>
          <dd>
            {session.email}
            {#if session.emailConfirmed}
              <span class="badge success">{$_('dashboard.verified')}</span>
            {:else}
              <span class="badge warning">{$_('dashboard.unverified')}</span>
            {/if}
          </dd>
        {/if}
      </dl>
    </section>

    <nav class="nav-grid">
      {#if session.accountKind === 'migrated'}
        <a href={getFullUrl(routes.didDocument)} class="nav-card migrated-card">
          <h3>{$_('dashboard.navDidDocument')}</h3>
          <p>{$_('dashboard.navDidDocumentDesc')}</p>
        </a>
        <a href={getFullUrl(routes.sessions)} class="nav-card">
          <h3>{$_('dashboard.navSessions')}</h3>
          <p>{$_('dashboard.navSessionsDesc')}</p>
        </a>
        <a href={getFullUrl(routes.security)} class="nav-card">
          <h3>{$_('dashboard.navSecurity')}</h3>
          <p>{$_('dashboard.navSecurityDesc')}</p>
        </a>
        <a href={getFullUrl(routes.settings)} class="nav-card">
          <h3>{$_('dashboard.navSettings')}</h3>
          <p>{$_('dashboard.navSettingsDesc')}</p>
        </a>
        <a href={getFullUrl(routes.migrate)} class="nav-card">
          <h3>{$_('dashboard.navMigrateAgain')}</h3>
          <p>{$_('dashboard.navMigrateAgainDesc')}</p>
        </a>
      {:else}
        <a href={getFullUrl(routes.appPasswords)} class="nav-card">
          <h3>{$_('dashboard.navAppPasswords')}</h3>
          <p>{$_('dashboard.navAppPasswordsDesc')}</p>
        </a>
        <a href={getFullUrl(routes.sessions)} class="nav-card">
          <h3>{$_('dashboard.navSessions')}</h3>
          <p>{$_('dashboard.navSessionsDesc')}</p>
        </a>
        {#if inviteCodesEnabled && session.isAdmin}
          <a href={getFullUrl(routes.inviteCodes)} class="nav-card">
            <h3>{$_('dashboard.navInviteCodes')}</h3>
            <p>{$_('dashboard.navInviteCodesDesc')}</p>
          </a>
        {/if}
        <a href={getFullUrl(routes.settings)} class="nav-card">
          <h3>{$_('dashboard.navSettings')}</h3>
          <p>{$_('dashboard.navSettingsDesc')}</p>
        </a>
        <a href={getFullUrl(routes.security)} class="nav-card">
          <h3>{$_('dashboard.navSecurity')}</h3>
          <p>{$_('dashboard.navSecurityDesc')}</p>
        </a>
        <a href={getFullUrl(routes.comms)} class="nav-card">
          <h3>{$_('dashboard.navComms')}</h3>
          <p>{$_('dashboard.navCommsDesc')}</p>
        </a>
        <a href={getFullUrl(routes.repo)} class="nav-card">
          <h3>{$_('dashboard.navRepo')}</h3>
          <p>{$_('dashboard.navRepoDesc')}</p>
        </a>
        <a href={getFullUrl(routes.controllers)} class="nav-card">
          <h3>{$_('dashboard.navDelegation')}</h3>
          <p>{$_('dashboard.navDelegationDesc')}</p>
        </a>
        {#if isDidWeb}
          <a href={getFullUrl(routes.didDocument)} class="nav-card did-web-card">
            <h3>{$_('dashboard.navDidDocument')}</h3>
            <p>{$_('dashboard.navDidDocumentDescActive')}</p>
          </a>
        {/if}
        <a href={getFullUrl(routes.migrate)} class="nav-card">
          <h3>{$_('migration.navTitle')}</h3>
          <p>{$_('migration.navDesc')}</p>
        </a>
        {#if session.isAdmin}
          <a href={getFullUrl(routes.admin)} class="nav-card admin-card">
            <h3>{$_('dashboard.navAdmin')}</h3>
            <p>{$_('dashboard.navAdminDesc')}</p>
          </a>
        {/if}
      {/if}
    </nav>
  </div>
{:else if loading}
  <div class="dashboard">
    <div class="skeleton-section"></div>
    <nav class="nav-grid">
      {#each Array(6) as _}
        <div class="skeleton-card"></div>
      {/each}
    </nav>
  </div>
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
    gap: var(--space-4);
  }

  @media (max-width: 500px) {
    header {
      flex-direction: column-reverse;
      align-items: flex-start;
    }
  }

  header h1 {
    margin: 0;
    min-width: 0;
  }

  .account-dropdown {
    position: relative;
    max-width: 100%;
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
    max-width: 100%;
  }

  .account-trigger .account-handle {
    font-weight: var(--font-medium);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .account-trigger:hover:not(:disabled) {
    background: var(--bg-secondary);
  }

  .account-trigger:disabled {
    opacity: 0.6;
    cursor: not-allowed;
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
    overflow: hidden;
    min-width: 0;
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
    max-width: 6rem;
  }

  dd {
    margin: 0;
    min-width: 0;
  }

  .mono {
    font-family: var(--font-mono);
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

  .badge.migrated {
    background: var(--info-bg, #e0f2fe);
    color: var(--info-text, #0369a1);
    border: 1px solid var(--info-border, #7dd3fc);
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

  .skeleton-section {
    height: 140px;
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-7);
    animation: skeleton-pulse 1.5s ease-in-out infinite;
  }

  .skeleton-card {
    height: 100px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-xl);
    animation: skeleton-pulse 1.5s ease-in-out infinite;
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

  .migrated-banner {
    background: var(--info-bg, #e0f2fe);
    border: 1px solid var(--info-border, #7dd3fc);
    border-radius: var(--radius-xl);
    padding: var(--space-5) var(--space-6);
    margin-bottom: var(--space-7);
  }

  .migrated-banner strong {
    color: var(--info-text, #0369a1);
    font-size: var(--text-base);
  }

  .migrated-banner p {
    margin: var(--space-3) 0 0 0;
    color: var(--info-text, #0369a1);
    font-size: var(--text-sm);
  }

  .nav-card.migrated-card {
    border-color: var(--info-border, #7dd3fc);
    background: linear-gradient(135deg, var(--bg-card) 0%, var(--info-bg, #e0f2fe) 100%);
  }

  .nav-card.migrated-card:hover {
    box-shadow: 0 2px 12px var(--info-bg, #e0f2fe);
  }

  .nav-card.migrated-card h3 {
    color: var(--info-text, #0369a1);
  }

  .nav-card.did-web-card {
    border-color: var(--accent);
    background: linear-gradient(135deg, var(--bg-card) 0%, var(--accent-muted) 100%);
  }

  .nav-card.did-web-card:hover {
    box-shadow: 0 2px 12px var(--accent-muted);
  }
</style>
