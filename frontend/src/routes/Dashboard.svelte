<script lang="ts">
  import { getAuthState, logout } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'

  const auth = getAuthState()

  $effect(() => {
    if (!auth.loading && !auth.session) {
      navigate('/login')
    }
  })

  async function handleLogout() {
    await logout()
    navigate('/login')
  }
</script>

{#if auth.session}
  <div class="dashboard">
    <header>
      <h1>Dashboard</h1>
      <button class="logout" onclick={handleLogout}>Sign Out</button>
    </header>

    <section class="account-overview">
      <h2>Account Overview</h2>
      <dl>
        <dt>Handle</dt>
        <dd>@{auth.session.handle}</dd>

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

  .logout {
    padding: 0.5rem 1rem;
    background: transparent;
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    cursor: pointer;
    color: var(--text-primary);
  }

  .logout:hover {
    background: var(--bg-secondary);
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

  .loading {
    text-align: center;
    padding: 4rem;
    color: var(--text-secondary);
  }
</style>
