<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, type AppPassword, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import { formatDate } from '../lib/date'
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
    if (!confirm($_('appPasswords.revokeConfirm', { values: { name } }))) {
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
    <a href="#/dashboard" class="back">{$_('common.backToDashboard')}</a>
    <h1>{$_('appPasswords.title')}</h1>
  </header>
  <p class="description">
    {$_('appPasswords.description')}
  </p>
  {#if error}
    <div class="error">{error}</div>
  {/if}
  {#if createdPassword}
    <div class="created-password">
      <h3>{$_('appPasswords.created')}</h3>
      <p>{$_('appPasswords.createdMessage')}</p>
      <div class="password-display">
        <code>{createdPassword.password}</code>
      </div>
      <p class="password-name">{$_('common.name')}: {createdPassword.name}</p>
      <button onclick={dismissCreated}>{$_('common.done')}</button>
    </div>
  {/if}
  <section class="create-section">
    <h2>{$_('appPasswords.createNew')}</h2>
    <form onsubmit={handleCreate}>
      <input
        type="text"
        bind:value={newPasswordName}
        placeholder={$_('appPasswords.appNamePlaceholder')}
        disabled={creating}
        required
      />
      <button type="submit" disabled={creating || !newPasswordName.trim()}>
        {creating ? $_('appPasswords.creating') : $_('common.create')}
      </button>
    </form>
  </section>
  <section class="list-section">
    <h2>{$_('appPasswords.yourPasswords')}</h2>
    {#if loading}
      <p class="empty">{$_('common.loading')}</p>
    {:else if passwords.length === 0}
      <p class="empty">{$_('appPasswords.noPasswords')}</p>
    {:else}
      <ul class="password-list">
        {#each passwords as pw}
          <li>
            <div class="password-info">
              <span class="name">{pw.name}</span>
              <span class="date">{$_('common.created')} {formatDate(pw.createdAt)}</span>
            </div>
            <button
              class="revoke"
              onclick={() => handleRevoke(pw.name)}
              disabled={revoking === pw.name}
            >
              {revoking === pw.name ? $_('appPasswords.revoking') : $_('appPasswords.revoke')}
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
</div>
<style>
  .page {
    max-width: var(--width-md);
    margin: 0 auto;
    padding: var(--space-7);
  }

  header {
    margin-bottom: var(--space-4);
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

  .description {
    color: var(--text-secondary);
    margin-bottom: var(--space-7);
  }

  .error {
    padding: var(--space-3);
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: var(--radius-md);
    color: var(--error-text);
    margin-bottom: var(--space-4);
  }

  .created-password {
    padding: var(--space-6);
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-7);
  }

  .created-password h3 {
    margin: 0 0 var(--space-2) 0;
    color: var(--success-text);
  }

  .password-display {
    background: var(--bg-card);
    padding: var(--space-4);
    border-radius: var(--radius-md);
    margin: var(--space-4) 0;
  }

  .password-display code {
    font-size: var(--text-xl);
    font-family: ui-monospace, monospace;
    word-break: break-all;
  }

  .password-name {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin-bottom: var(--space-4);
  }

  section {
    margin-bottom: var(--space-7);
  }

  section h2 {
    font-size: var(--text-lg);
    margin: 0 0 var(--space-4) 0;
  }

  .create-section form {
    display: flex;
    gap: var(--space-2);
  }

  .create-section input {
    flex: 1;
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
    padding: var(--space-4);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-2);
    background: var(--bg-card);
  }

  .password-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .name {
    font-weight: var(--font-medium);
  }

  .date {
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .revoke {
    padding: var(--space-2) var(--space-4);
    background: transparent;
    border: 1px solid var(--error-text);
    border-radius: var(--radius-md);
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
    padding: var(--space-7);
  }
</style>
