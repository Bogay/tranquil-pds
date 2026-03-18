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
    <div>
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
            class="sm danger-outline"
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
