<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, type AppPassword, ApiError } from '../lib/api'
  const auth = getAuthState()
  let passwords = $state<AppPassword[]>([])
  let loading = $state(true)
  let error = $state<string | null>(null)
  let newPasswordName = $state('')
  let creating = $state(false)
  let createdPassword = $state<{ name: string; password: string } | null>(null)
  let revoking = $state<string | null>(null)
  $effect(() => {
    if (!auth.loading && !auth.session) {
      navigate('/login')
    }
  })
  $effect(() => {
    if (auth.session) {
      loadPasswords()
    }
  })
  async function loadPasswords() {
    if (!auth.session) return
    loading = true
    error = null
    try {
      const result = await api.listAppPasswords(auth.session.accessJwt)
      passwords = result.passwords
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to load app passwords'
    } finally {
      loading = false
    }
  }
  async function handleCreate(e: Event) {
    e.preventDefault()
    if (!auth.session || !newPasswordName.trim()) return
    creating = true
    error = null
    try {
      const result = await api.createAppPassword(auth.session.accessJwt, newPasswordName.trim())
      createdPassword = { name: result.name, password: result.password }
      newPasswordName = ''
      await loadPasswords()
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to create app password'
    } finally {
      creating = false
    }
  }
  async function handleRevoke(name: string) {
    if (!auth.session) return
    if (!confirm(`Revoke app password "${name}"? Apps using this password will no longer be able to access your account.`)) {
      return
    }
    revoking = name
    error = null
    try {
      await api.revokeAppPassword(auth.session.accessJwt, name)
      await loadPasswords()
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to revoke app password'
    } finally {
      revoking = null
    }
  }
  function dismissCreated() {
    createdPassword = null
  }
</script>
<div class="page">
  <header>
    <a href="#/dashboard" class="back">&larr; Dashboard</a>
    <h1>App Passwords</h1>
  </header>
  <p class="description">
    App passwords let you sign in to third-party apps without giving them your main password.
    Each app password can be revoked individually.
  </p>
  {#if error}
    <div class="error">{error}</div>
  {/if}
  {#if createdPassword}
    <div class="created-password">
      <h3>App Password Created</h3>
      <p>Copy this password now. You won't be able to see it again.</p>
      <div class="password-display">
        <code>{createdPassword.password}</code>
      </div>
      <p class="password-name">Name: {createdPassword.name}</p>
      <button onclick={dismissCreated}>Done</button>
    </div>
  {/if}
  <section class="create-section">
    <h2>Create New App Password</h2>
    <form onsubmit={handleCreate}>
      <input
        type="text"
        bind:value={newPasswordName}
        placeholder="App name (e.g., Graysky, Skeets)"
        disabled={creating}
        required
      />
      <button type="submit" disabled={creating || !newPasswordName.trim()}>
        {creating ? 'Creating...' : 'Create'}
      </button>
    </form>
  </section>
  <section class="list-section">
    <h2>Your App Passwords</h2>
    {#if loading}
      <p class="empty">Loading...</p>
    {:else if passwords.length === 0}
      <p class="empty">No app passwords yet</p>
    {:else}
      <ul class="password-list">
        {#each passwords as pw}
          <li>
            <div class="password-info">
              <span class="name">{pw.name}</span>
              <span class="date">Created {new Date(pw.createdAt).toLocaleDateString()}</span>
            </div>
            <button
              class="revoke"
              onclick={() => handleRevoke(pw.name)}
              disabled={revoking === pw.name}
            >
              {revoking === pw.name ? 'Revoking...' : 'Revoke'}
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
</div>
<style>
  .page {
    max-width: 600px;
    margin: 0 auto;
    padding: 2rem;
  }
  header {
    margin-bottom: 1rem;
  }
  .back {
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 0.875rem;
  }
  .back:hover {
    color: var(--accent);
  }
  h1 {
    margin: 0.5rem 0 0 0;
  }
  .description {
    color: var(--text-secondary);
    margin-bottom: 2rem;
  }
  .error {
    padding: 0.75rem;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: 4px;
    color: var(--error-text);
    margin-bottom: 1rem;
  }
  .created-password {
    padding: 1.5rem;
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    border-radius: 8px;
    margin-bottom: 2rem;
  }
  .created-password h3 {
    margin: 0 0 0.5rem 0;
    color: var(--success-text);
  }
  .password-display {
    background: var(--bg-card);
    padding: 1rem;
    border-radius: 4px;
    margin: 1rem 0;
  }
  .password-display code {
    font-size: 1.25rem;
    font-family: monospace;
    word-break: break-all;
  }
  .password-name {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin-bottom: 1rem;
  }
  section {
    margin-bottom: 2rem;
  }
  section h2 {
    font-size: 1.125rem;
    margin: 0 0 1rem 0;
  }
  .create-section form {
    display: flex;
    gap: 0.5rem;
  }
  .create-section input {
    flex: 1;
    padding: 0.75rem;
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    font-size: 1rem;
    background: var(--bg-input);
    color: var(--text-primary);
  }
  .create-section input:focus {
    outline: none;
    border-color: var(--accent);
  }
  .create-section button {
    padding: 0.75rem 1.5rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }
  .create-section button:hover:not(:disabled) {
    background: var(--accent-hover);
  }
  .create-section button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .password-list {
    list-style: none;
    padding: 0;
    margin: 0;
  }
  .password-list li {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    margin-bottom: 0.5rem;
    background: var(--bg-card);
  }
  .password-info {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .name {
    font-weight: 500;
  }
  .date {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }
  .revoke {
    padding: 0.5rem 1rem;
    background: transparent;
    border: 1px solid var(--error-text);
    border-radius: 4px;
    color: var(--error-text);
    cursor: pointer;
  }
  .revoke:hover:not(:disabled) {
    background: var(--error-bg);
  }
  .revoke:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .empty {
    color: var(--text-secondary);
    text-align: center;
    padding: 2rem;
  }
</style>
