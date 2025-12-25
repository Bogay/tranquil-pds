<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import { formatDateTime } from '../lib/date'
  const auth = getAuthState()
  let loading = $state(true)
  let error = $state<string | null>(null)
  let sessions = $state<Array<{
    id: string
    sessionType: string
    clientName: string | null
    createdAt: string
    expiresAt: string
    isCurrent: boolean
  }>>([])
  $effect(() => {
    if (!auth.loading && !auth.session) {
      navigate('/login')
    }
  })
  $effect(() => {
    if (auth.session) {
      loadSessions()
    }
  })
  async function loadSessions() {
    if (!auth.session) return
    loading = true
    error = null
    try {
      const result = await api.listSessions(auth.session.accessJwt)
      sessions = result.sessions
    } catch (e) {
      error = e instanceof ApiError ? e.message : $_('sessions.failedToLoad')
    } finally {
      loading = false
    }
  }
  async function revokeSession(sessionId: string, isCurrent: boolean) {
    if (!auth.session) return
    const msg = isCurrent
      ? $_('sessions.revokeCurrentConfirm')
      : $_('sessions.revokeConfirm')
    if (!confirm(msg)) return
    try {
      await api.revokeSession(auth.session.accessJwt, sessionId)
      if (isCurrent) {
        navigate('/login')
      } else {
        sessions = sessions.filter(s => s.id !== sessionId)
      }
    } catch (e) {
      error = e instanceof ApiError ? e.message : $_('sessions.failedToRevoke')
    }
  }
  async function revokeAllSessions() {
    if (!auth.session) return
    const otherSessions = sessions.filter(s => !s.isCurrent)
    if (otherSessions.length === 0) {
      error = $_('sessions.noOtherSessions')
      return
    }
    if (!confirm($_('sessions.revokeAllConfirm', { values: { count: otherSessions.length } }))) return
    try {
      await api.revokeAllSessions(auth.session.accessJwt)
      sessions = sessions.filter(s => s.isCurrent)
    } catch (e) {
      error = e instanceof ApiError ? e.message : $_('sessions.failedToRevokeAll')
    }
  }
  function formatDate(dateStr: string): string {
    return formatDateTime(dateStr)
  }
  function timeAgo(dateStr: string): string {
    const date = new Date(dateStr)
    const now = new Date()
    const diff = now.getTime() - date.getTime()
    const days = Math.floor(diff / (1000 * 60 * 60 * 24))
    const hours = Math.floor(diff / (1000 * 60 * 60))
    const minutes = Math.floor(diff / (1000 * 60))
    if (days > 0) return $_('sessions.daysAgo', { values: { count: days } })
    if (hours > 0) return $_('sessions.hoursAgo', { values: { count: hours } })
    if (minutes > 0) return $_('sessions.minutesAgo', { values: { count: minutes } })
    return $_('sessions.justNow')
  }
</script>
<div class="page">
  <header>
    <a href="#/dashboard" class="back">{$_('common.backToDashboard')}</a>
    <h1>{$_('sessions.title')}</h1>
  </header>
  {#if loading}
    <p class="loading">{$_('sessions.loadingSessions')}</p>
  {:else}
    {#if error}
      <div class="message error">{error}</div>
    {/if}
    {#if sessions.length === 0}
      <p class="empty">{$_('sessions.noSessions')}</p>
    {:else}
      <div class="sessions-list">
        {#each sessions as session}
          <div class="session-card" class:current={session.isCurrent}>
            <div class="session-info">
              <div class="session-header">
                {#if session.isCurrent}
                  <span class="badge current">{$_('sessions.current')}</span>
                {/if}
                <span class="badge type" class:oauth={session.sessionType === 'oauth'}>
                  {session.sessionType === 'oauth' ? $_('sessions.oauth') : $_('sessions.session')}
                </span>
                {#if session.clientName}
                  <span class="client-name">{session.clientName}</span>
                {/if}
              </div>
              <div class="session-details">
                <div class="detail">
                  <span class="label">{$_('sessions.created')}</span>
                  <span class="value">{timeAgo(session.createdAt)}</span>
                </div>
                <div class="detail">
                  <span class="label">{$_('sessions.expires')}</span>
                  <span class="value">{formatDate(session.expiresAt)}</span>
                </div>
              </div>
            </div>
            <div class="session-actions">
              <button
                class="revoke-btn"
                class:danger={!session.isCurrent}
                onclick={() => revokeSession(session.id, session.isCurrent)}
              >
                {session.isCurrent ? $_('sessions.signOut') : $_('sessions.revoke')}
              </button>
            </div>
          </div>
        {/each}
      </div>
      <div class="actions-bar">
        <button class="refresh-btn" onclick={loadSessions}>{$_('common.refresh')}</button>
        {#if sessions.filter(s => !s.isCurrent).length > 0}
          <button class="revoke-all-btn" onclick={revokeAllSessions}>{$_('sessions.revokeAll')}</button>
        {/if}
      </div>
    {/if}
  {/if}
</div>
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

  .loading,
  .empty {
    text-align: center;
    color: var(--text-secondary);
    padding: var(--space-7);
  }

  .sessions-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .session-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-xl);
    padding: var(--space-4);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .session-card.current {
    border-color: var(--accent);
    background: var(--bg-card);
  }

  .session-header {
    margin-bottom: var(--space-2);
    display: flex;
    align-items: center;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  .client-name {
    font-weight: var(--font-medium);
    color: var(--text-primary);
  }

  .badge {
    display: inline-block;
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
    font-weight: var(--font-medium);
  }

  .badge.current {
    background: var(--accent);
    color: var(--text-inverse);
  }

  .badge.type {
    background: var(--bg-secondary);
    color: var(--text-secondary);
    border: 1px solid var(--border-color);
  }

  .badge.type.oauth {
    background: var(--success-bg);
    color: var(--success-text);
    border-color: var(--success-border);
  }

  .session-details {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .detail {
    font-size: var(--text-sm);
  }

  .detail .label {
    color: var(--text-secondary);
    margin-right: var(--space-2);
  }

  .detail .value {
    color: var(--text-primary);
  }

  .revoke-btn {
    padding: var(--space-2) var(--space-4);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--text-primary);
    cursor: pointer;
    font-size: var(--text-sm);
  }

  .revoke-btn:hover {
    background: var(--bg-card);
  }

  .revoke-btn.danger {
    border-color: var(--error-text);
    color: var(--error-text);
  }

  .revoke-btn.danger:hover {
    background: var(--error-bg);
  }

  .actions-bar {
    margin-top: var(--space-4);
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
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

  .revoke-all-btn {
    padding: var(--space-2) var(--space-4);
    background: transparent;
    border: 1px solid var(--error-text);
    border-radius: var(--radius-md);
    cursor: pointer;
    color: var(--error-text);
  }

  .revoke-all-btn:hover {
    background: var(--error-bg);
  }
</style>
