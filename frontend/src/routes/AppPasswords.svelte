<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { api, type AppPassword, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import { formatDate } from '../lib/date'
  import type { Session } from '../lib/types/api'
  import { toast } from '../lib/toast.svelte'

  const auth = $derived(getAuthState())

  function getSession(): Session | null {
    return auth.kind === 'authenticated' ? auth.session : null
  }

  function isLoading(): boolean {
    return auth.kind === 'loading'
  }

  const session = $derived(getSession())
  const authLoading = $derived(isLoading())
  let passwords = $state<AppPassword[]>([])
  let loading = $state(true)
  let newPasswordName = $state('')
  let selectedScope = $state<string | null>(null)
  let creating = $state(false)
  let createdPassword = $state<{ name: string; password: string } | null>(null)
  let passwordCopied = $state(false)
  let passwordAcknowledged = $state(false)
  let revoking = $state<string | null>(null)

  const SCOPE_PRESETS = [
    { id: 'full', label: 'appPasswords.scopeFull', scopes: null },
    { id: 'readonly', label: 'appPasswords.scopeReadOnly', scopes: 'rpc:app.bsky.*?aud=* rpc:chat.bsky.*?aud=* account:status?action=read' },
    { id: 'post', label: 'appPasswords.scopePostOnly', scopes: 'repo:app.bsky.feed.post?action=create blob:*/*' },
  ]

  function getScopeLabel(scopes: string | null | undefined): string {
    if (!scopes) return $_('appPasswords.scopeFull')
    const preset = SCOPE_PRESETS.find(p => p.scopes === scopes)
    if (preset) return $_(preset.label)
    return $_('appPasswords.scopeCustom')
  }
  $effect(() => {
    if (!authLoading && !session) {
      navigate(routes.login)
    }
  })
  $effect(() => {
    if (session) {
      loadPasswords()
    }
  })
  async function loadPasswords() {
    if (!session) return
    loading = true
    try {
      const result = await api.listAppPasswords(session.accessJwt)
      passwords = result.passwords
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('appPasswords.failedToLoad'))
    } finally {
      loading = false
    }
  }
  async function handleCreate(e: Event) {
    e.preventDefault()
    if (!session || !newPasswordName.trim()) return
    creating = true
    try {
      const scopeValue = selectedScope === null ? undefined : selectedScope
      const result = await api.createAppPassword(session.accessJwt, newPasswordName.trim(), scopeValue ?? undefined)
      createdPassword = { name: result.name, password: result.password }
      newPasswordName = ''
      selectedScope = null
      await loadPasswords()
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('appPasswords.failedToCreate'))
    } finally {
      creating = false
    }
  }
  async function handleRevoke(name: string) {
    if (!session) return
    if (!confirm($_('appPasswords.revokeConfirm', { values: { name } }))) {
      return
    }
    revoking = name
    try {
      await api.revokeAppPassword(session.accessJwt, name)
      await loadPasswords()
      toast.success($_('appPasswords.passwordRevoked'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('appPasswords.failedToRevoke'))
    } finally {
      revoking = null
    }
  }
  function copyPassword() {
    if (createdPassword) {
      navigator.clipboard.writeText(createdPassword.password)
      passwordCopied = true
    }
  }
  function dismissCreated() {
    createdPassword = null
    passwordCopied = false
    passwordAcknowledged = false
  }
</script>
<div class="page">
  <header>
    <a href={getFullUrl(routes.dashboard)} class="back">{$_('common.backToDashboard')}</a>
    <h1>{$_('appPasswords.title')}</h1>
  </header>
  <p class="description">
    {$_('appPasswords.description')}
  </p>
  {#if createdPassword}
    <div class="created-password">
      <div class="warning-box">
        <strong>{$_('appPasswords.saveWarningTitle')}</strong>
        <p>{$_('appPasswords.saveWarningMessage')}</p>
      </div>
      <div class="password-display">
        <div class="password-label">{$_('common.name')}: <strong>{createdPassword.name}</strong></div>
        <code class="password-code">{createdPassword.password}</code>
        <button type="button" class="copy-btn" onclick={copyPassword}>
          {passwordCopied ? $_('common.copied') : $_('common.copyToClipboard')}
        </button>
      </div>
      <label class="checkbox-label">
        <input type="checkbox" bind:checked={passwordAcknowledged} />
        <span>{$_('appPasswords.acknowledgeLabel')}</span>
      </label>
      <button onclick={dismissCreated} disabled={!passwordAcknowledged}>{$_('common.done')}</button>
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
      <div class="scope-selector" role="group" aria-label={$_('appPasswords.permissions')}>
        <span class="scope-label">{$_('appPasswords.permissions')}:</span>
        <div class="scope-buttons">
          {#each SCOPE_PRESETS as preset}
            <button
              type="button"
              class="scope-btn"
              class:selected={selectedScope === preset.scopes}
              onclick={() => selectedScope = preset.scopes}
              disabled={creating}
            >
              {$_(preset.label)}
            </button>
          {/each}
        </div>
      </div>
      <button type="submit" disabled={creating || !newPasswordName.trim()}>
        {creating ? $_('common.creating') : $_('common.create')}
      </button>
    </form>
  </section>
  <section class="list-section">
    <h2>{$_('appPasswords.yourPasswords')}</h2>
    {#if loading}
      <ul class="password-list">
        {#each Array(2) as _}
          <li class="skeleton-item"></li>
        {/each}
      </ul>
    {:else if passwords.length === 0}
      <p class="empty">{$_('appPasswords.noPasswords')}</p>
    {:else}
      <ul class="password-list">
        {#each passwords as pw}
          <li>
            <div class="password-info">
              <span class="name">{pw.name}</span>
              <span class="meta">
                <span class="scope-badge" class:full={!pw.scopes}>{getScopeLabel(pw.scopes)}</span>
                {#if pw.createdByController}
                  <span class="controller-badge" title={pw.createdByController}>{$_('appPasswords.byController')}</span>
                {/if}
                <span class="date">{$_('common.created')} {formatDate(pw.createdAt)}</span>
              </span>
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
    max-width: var(--width-lg);
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

  .created-password {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    padding: var(--space-6);
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-7);
  }

  .warning-box {
    padding: var(--space-5);
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius-lg);
    font-size: var(--text-sm);
  }

  .warning-box strong {
    display: block;
    margin-bottom: var(--space-2);
    color: var(--warning-text);
  }

  .warning-box p {
    margin: 0;
    color: var(--warning-text);
  }

  .password-display {
    background: var(--bg-card);
    border: 2px solid var(--accent);
    border-radius: var(--radius-xl);
    padding: var(--space-6);
    text-align: center;
  }

  .password-label {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin-bottom: var(--space-4);
  }

  .password-code {
    display: block;
    font-size: var(--text-xl);
    font-family: var(--font-mono);
    letter-spacing: 0.1em;
    padding: var(--space-5);
    background: var(--bg-input);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-4);
    user-select: all;
    word-break: break-all;
  }

  .copy-btn {
    padding: var(--space-3) var(--space-5);
    font-size: var(--text-sm);
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    cursor: pointer;
    font-weight: var(--font-normal);
  }

  .checkbox-label input[type="checkbox"] {
    width: auto;
    padding: 0;
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
    flex-direction: column;
    gap: var(--space-4);
  }

  .create-section form > input {
    flex: 1;
  }

  .create-section form > button {
    align-self: flex-start;
  }

  .scope-selector {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .scope-label {
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .scope-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }

  .scope-btn {
    padding: var(--space-2) var(--space-4);
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    color: var(--text-primary);
    cursor: pointer;
    font-size: var(--text-sm);
    transition: all 0.15s ease;
  }

  .scope-btn:hover:not(:disabled) {
    background: var(--bg-hover);
    border-color: var(--accent);
  }

  .scope-btn.selected {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--text-inverse);
  }

  .scope-btn:disabled {
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

  .meta {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .scope-badge {
    font-size: var(--text-xs);
    padding: var(--space-1) var(--space-2);
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-sm);
    color: var(--text-secondary);
  }

  .scope-badge.full {
    background: var(--success-bg);
    border-color: var(--success-border);
    color: var(--success-text);
  }

  .controller-badge {
    font-size: var(--text-xs);
    padding: var(--space-1) var(--space-2);
    background: var(--info-bg, #e3f2fd);
    border: 1px solid var(--info-border, #90caf9);
    border-radius: var(--radius-sm);
    color: var(--info-text, #1565c0);
    cursor: help;
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

  .skeleton-item {
    height: 60px;
    background: var(--bg-tertiary);
    animation: skeleton-pulse 1.5s ease-in-out infinite;
  }

</style>
