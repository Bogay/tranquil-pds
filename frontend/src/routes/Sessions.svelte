<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
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
      error = e instanceof ApiError ? e.message : 'Failed to load sessions'
    } finally {
      loading = false
    }
  }
  async function revokeSession(sessionId: string, isCurrent: boolean) {
    if (!auth.session) return
    const msg = isCurrent
      ? 'This will log you out of this session. Continue?'
      : 'Revoke this session?'
    if (!confirm(msg)) return
    try {
      await api.revokeSession(auth.session.accessJwt, sessionId)
      if (isCurrent) {
        navigate('/login')
      } else {
        sessions = sessions.filter(s => s.id !== sessionId)
      }
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to revoke session'
    }
  }
  async function revokeAllSessions() {
    if (!auth.session) return
    const otherCount = sessions.filter(s => !s.isCurrent).length
    if (otherCount === 0) {
      error = 'No other sessions to revoke'
      return
    }
    if (!confirm(`This will revoke ${otherCount} other session${otherCount > 1 ? 's' : ''}. Continue?`)) return
    try {
      await api.revokeAllSessions(auth.session.accessJwt)
      sessions = sessions.filter(s => s.isCurrent)
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to revoke sessions'
    }
  }
  function formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleString()
  }
  function timeAgo(dateStr: string): string {
    const date = new Date(dateStr)
    const now = new Date()
    const diff = now.getTime() - date.getTime()
    const days = Math.floor(diff / (1000 * 60 * 60 * 24))
    const hours = Math.floor(diff / (1000 * 60 * 60))
    const minutes = Math.floor(diff / (1000 * 60))
    if (days > 0) return `${days} day${days > 1 ? 's' : ''} ago`
    if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''} ago`
    if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`
    return 'Just now'
  }
</script>
<div class="page">
  <header>
    <a href="#/dashboard" class="back">&larr; Dashboard</a>
    <h1>Active Sessions</h1>
  </header>
  {#if loading}
    <p class="loading">Loading sessions...</p>
  {:else}
    {#if error}
      <div class="message error">{error}</div>
    {/if}
    {#if sessions.length === 0}
      <p class="empty">No active sessions found.</p>
    {:else}
      <div class="sessions-list">
        {#each sessions as session}
          <div class="session-card" class:current={session.isCurrent}>
            <div class="session-info">
              <div class="session-header">
                {#if session.isCurrent}
                  <span class="badge current">Current</span>
                {/if}
                <span class="badge type" class:oauth={session.sessionType === 'oauth'}>
                  {session.sessionType === 'oauth' ? 'OAuth' : 'Session'}
                </span>
                {#if session.clientName}
                  <span class="client-name">{session.clientName}</span>
                {/if}
              </div>
              <div class="session-details">
                <div class="detail">
                  <span class="label">Created:</span>
                  <span class="value">{timeAgo(session.createdAt)}</span>
                </div>
                <div class="detail">
                  <span class="label">Expires:</span>
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
                {session.isCurrent ? 'Sign Out' : 'Revoke'}
              </button>
            </div>
          </div>
        {/each}
      </div>
      <div class="actions-bar">
        <button class="refresh-btn" onclick={loadSessions}>Refresh</button>
        {#if sessions.filter(s => !s.isCurrent).length > 0}
          <button class="revoke-all-btn" onclick={revokeAllSessions}>Revoke All Other Sessions</button>
        {/if}
      </div>
    {/if}
  {/if}
</div>
<style>
  .page {
    max-width: 600px;
    margin: 0 auto;
    padding: 2rem;
  }
  header {
    margin-bottom: 2rem;
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
  .loading, .empty {
    text-align: center;
    color: var(--text-secondary);
    padding: 2rem;
  }
  .message {
    padding: 0.75rem;
    border-radius: 4px;
    margin-bottom: 1rem;
  }
  .message.error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-text);
  }
  .sessions-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .session-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .session-card.current {
    border-color: var(--accent);
    background: var(--bg-card);
  }
  .session-header {
    margin-bottom: 0.5rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .client-name {
    font-weight: 500;
    color: var(--text-primary);
  }
  .badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 500;
  }
  .badge.current {
    background: var(--accent);
    color: white;
  }
  .badge.type {
    background: var(--bg-secondary);
    color: var(--text-secondary);
    border: 1px solid var(--border-color);
  }
  .badge.type.oauth {
    background: #e6f4ea;
    color: #1e7e34;
    border-color: #b8d9c5;
  }
  .session-details {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .detail {
    font-size: 0.875rem;
  }
  .detail .label {
    color: var(--text-secondary);
    margin-right: 0.5rem;
  }
  .detail .value {
    color: var(--text-primary);
  }
  .revoke-btn {
    padding: 0.5rem 1rem;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    background: transparent;
    color: var(--text-primary);
    cursor: pointer;
    font-size: 0.875rem;
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
    margin-top: 1rem;
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .refresh-btn {
    padding: 0.5rem 1rem;
    background: transparent;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    cursor: pointer;
    color: var(--text-primary);
  }
  .refresh-btn:hover {
    background: var(--bg-card);
    border-color: var(--accent);
  }
  .revoke-all-btn {
    padding: 0.5rem 1rem;
    background: transparent;
    border: 1px solid var(--error-text);
    border-radius: 4px;
    cursor: pointer;
    color: var(--error-text);
  }
  .revoke-all-btn:hover {
    background: var(--error-bg);
  }
</style>
