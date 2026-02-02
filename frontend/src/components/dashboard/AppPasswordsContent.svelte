<script lang="ts">
  import { onMount } from 'svelte'
  import { _ } from '../../lib/i18n'
  import { api, ApiError } from '../../lib/api'
  import { toast } from '../../lib/toast.svelte'
  import { formatDate } from '../../lib/date'
  import type { Session } from '../../lib/types/api'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  interface AppPassword {
    name: string
    createdAt: string
    scopes?: string | null
    createdByController?: string | null
  }

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

  let appPasswords = $state<AppPassword[]>([])
  let loading = $state(true)
  let creating = $state(false)
  let newName = $state('')
  let selectedScope = $state<string | null>(null)
  let newPassword = $state<string | null>(null)
  let newPasswordName = $state<string | null>(null)
  let passwordAcknowledged = $state(false)
  let deleting = $state<string | null>(null)

  onMount(async () => {
    await loadAppPasswords()
  })

  async function loadAppPasswords() {
    loading = true
    try {
      const result = await api.listAppPasswords(session.accessJwt)
      appPasswords = result.passwords
    } catch {
      toast.error($_('appPasswords.loadFailed'))
    } finally {
      loading = false
    }
  }

  async function handleCreate(e: Event) {
    e.preventDefault()
    if (!newName.trim()) return
    creating = true
    try {
      const scopeValue = selectedScope === null ? undefined : selectedScope
      const createdName = newName.trim()
      const result = await api.createAppPassword(session.accessJwt, createdName, scopeValue ?? undefined)
      newPassword = result.password
      newPasswordName = createdName
      passwordAcknowledged = false
      await loadAppPasswords()
      newName = ''
      selectedScope = null
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('appPasswords.createFailed'))
    } finally {
      creating = false
    }
  }

  async function handleDelete(name: string) {
    if (!confirm($_('appPasswords.deleteConfirm', { values: { name } }))) return
    deleting = name
    try {
      await api.revokeAppPassword(session.accessJwt, name)
      appPasswords = appPasswords.filter(p => p.name !== name)
      toast.success($_('appPasswords.deleted'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('appPasswords.deleteFailed'))
    } finally {
      deleting = null
    }
  }

  function dismissNewPassword() {
    newPassword = null
    newPasswordName = null
    passwordAcknowledged = false
  }

  function copyPassword() {
    if (newPassword) {
      navigator.clipboard.writeText(newPassword)
      toast.success($_('common.copied'))
    }
  }
</script>

<div class="app-passwords">
  {#if newPassword}
    <div class="new-password-banner">
      {#if newPasswordName}
        <div class="password-label">{$_('common.name')}: <strong>{newPasswordName}</strong></div>
      {/if}
      <p class="warning">{$_('appPasswords.saveWarning')}</p>
      <div class="password-display">
        <code>{newPassword}</code>
        <button type="button" class="copy-btn" onclick={copyPassword}>
          {$_('common.copyToClipboard')}
        </button>
      </div>
      <label class="acknowledge-label">
        <input type="checkbox" bind:checked={passwordAcknowledged} />
        <span>{$_('appPasswords.acknowledgeLabel')}</span>
      </label>
      <button type="button" class="dismiss-btn" onclick={dismissNewPassword} disabled={!passwordAcknowledged}>
        {$_('common.done')}
      </button>
    </div>
  {/if}

  <form class="create-form" onsubmit={handleCreate}>
    <div class="field">
      <label for="app-name">{$_('appPasswords.name')}</label>
      <input
        id="app-name"
        type="text"
        bind:value={newName}
        placeholder={$_('appPasswords.namePlaceholder')}
        disabled={creating}
        required
      />
    </div>
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
    <button type="submit" disabled={creating || !newName.trim()}>
      {creating ? $_('common.creating') : $_('appPasswords.create')}
    </button>
  </form>

  {#if loading}
    <div class="loading">{$_('common.loading')}</div>
  {:else if appPasswords.length === 0}
    <p class="empty">{$_('appPasswords.noPasswords')}</p>
  {:else}
    <ul class="password-list">
      {#each appPasswords as pw}
        <li class="password-item">
          <div class="password-info">
            <span class="password-name">{pw.name}</span>
            <span class="password-meta">
              <span class="scope-badge" class:full={!pw.scopes}>{getScopeLabel(pw.scopes)}</span>
              {#if pw.createdByController}
                <span class="controller-badge" title={pw.createdByController}>{$_('appPasswords.byController')}</span>
              {/if}
              <span class="date">{$_('common.created')} {formatDate(pw.createdAt)}</span>
            </span>
          </div>
          <button
            type="button"
            class="delete-btn"
            onclick={() => handleDelete(pw.name)}
            disabled={deleting === pw.name}
          >
            {deleting === pw.name ? $_('common.loading') : $_('common.revoke')}
          </button>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .app-passwords {
    max-width: var(--width-lg);
  }

  .new-password-banner {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    margin-bottom: var(--space-6);
  }

  .new-password-banner .password-label {
    font-size: var(--text-sm);
    color: var(--text-primary);
    margin-bottom: var(--space-2);
  }

  .new-password-banner .warning {
    color: var(--warning-text);
    font-weight: var(--font-medium);
    margin: 0 0 var(--space-3) 0;
  }

  .acknowledge-label {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-bottom: var(--space-3);
    cursor: pointer;
    font-size: var(--text-sm);
    color: var(--text-primary);
  }

  .acknowledge-label input[type="checkbox"] {
    width: 18px;
    height: 18px;
    accent-color: var(--accent);
  }

  .password-display {
    display: flex;
    gap: var(--space-2);
    margin-bottom: var(--space-3);
  }

  .password-display code {
    flex: 1;
    padding: var(--space-3);
    background: var(--bg-card);
    border-radius: var(--radius-md);
    font-family: var(--font-mono);
    word-break: break-all;
  }

  .copy-btn {
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-sm);
  }

  .dismiss-btn {
    width: 100%;
  }

  .create-form {
    background: var(--bg-secondary);
    padding: var(--space-5);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-6);
  }

  .create-form .field {
    margin-bottom: var(--space-4);
  }

  .scope-selector {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin-bottom: var(--space-4);
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
    background: var(--bg-card);
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

  .loading,
  .empty {
    color: var(--text-secondary);
    padding: var(--space-6);
    text-align: center;
  }

  .password-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .password-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-4);
    background: var(--bg-secondary);
    border-radius: var(--radius-lg);
    gap: var(--space-4);
  }

  .password-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .password-name {
    font-weight: var(--font-medium);
  }

  .password-meta {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-2);
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .scope-badge {
    font-size: var(--text-xs);
    padding: var(--space-1) var(--space-2);
    background: var(--bg-card);
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
    background: var(--accent-muted);
    border: 1px solid var(--accent);
    border-radius: var(--radius-sm);
    color: var(--accent);
    cursor: help;
  }

  .date {
    color: var(--text-secondary);
  }

  .delete-btn {
    flex-shrink: 0;
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-sm);
    background: transparent;
    border: 1px solid var(--error-border);
    color: var(--error-text);
    border-radius: var(--radius-md);
    cursor: pointer;
  }

  .delete-btn:hover:not(:disabled) {
    background: var(--error-bg);
  }

  .delete-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  @media (max-width: 500px) {
    .password-item {
      flex-direction: column;
      align-items: stretch;
    }

    .delete-btn {
      width: 100%;
    }

    .password-display {
      flex-direction: column;
    }
  }
</style>
