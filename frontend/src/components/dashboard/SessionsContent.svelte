<script lang="ts">
  import { onMount } from 'svelte'
  import { _ } from '../../lib/i18n'
  import { api, ApiError } from '../../lib/api'
  import { toast } from '../../lib/toast.svelte'
  import { formatDateTime } from '../../lib/date'
  import { navigate, routes } from '../../lib/router.svelte'
  import type { Session } from '../../lib/types/api'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  interface SessionInfo {
    id: string
    sessionType: string
    clientName: string | null
    createdAt: string
    expiresAt: string
    isCurrent: boolean
  }

  let sessions = $state<SessionInfo[]>([])
  let loading = $state(true)

  onMount(async () => {
    await loadSessions()
  })

  async function loadSessions() {
    loading = true
    try {
      const result = await api.listSessions(session.accessJwt)
      sessions = result.sessions
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('sessions.failedToLoad'))
    } finally {
      loading = false
    }
  }

  async function revokeSession(sessionId: string, isCurrent: boolean) {
    const msg = isCurrent
      ? $_('sessions.revokeCurrentConfirm')
      : $_('sessions.revokeConfirm')
    if (!confirm(msg)) return
    try {
      await api.revokeSession(session.accessJwt, sessionId)
      if (isCurrent) {
        navigate(routes.login)
      } else {
        sessions = sessions.filter(s => s.id !== sessionId)
        toast.success($_('sessions.sessionRevoked'))
      }
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('sessions.failedToRevoke'))
    }
  }

  async function revokeAllSessions() {
    const otherSessions = sessions.filter(s => !s.isCurrent)
    if (otherSessions.length === 0) {
      toast.warning($_('sessions.noOtherSessions'))
      return
    }
    if (!confirm($_('sessions.revokeAllConfirm', { values: { count: otherSessions.length } }))) return
    try {
      await api.revokeAllSessions(session.accessJwt)
      sessions = sessions.filter(s => s.isCurrent)
      toast.success($_('sessions.allSessionsRevoked'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('sessions.failedToRevokeAll'))
    }
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

  function formatDate(dateStr: string): string {
    return formatDateTime(dateStr)
  }
</script>

<div class="sessions">
  {#if loading}
    <div class="loading">{$_('common.loading')}</div>
  {:else if sessions.length === 0}
    <p class="empty">{$_('sessions.noSessions')}</p>
  {:else}
    <div class="sessions-list">
      {#each sessions as s}
        <div class="session-card" class:current={s.isCurrent}>
          <div class="session-info">
            <div class="session-header">
              {#if s.isCurrent}
                <span class="badge current">{$_('sessions.current')}</span>
              {/if}
              <span class="badge type" class:oauth={s.sessionType === 'oauth'}>
                {s.sessionType === 'oauth' ? $_('sessions.oauth') : $_('sessions.session')}
              </span>
              {#if s.clientName}
                <span class="client-name">{s.clientName}</span>
              {/if}
            </div>
            <div class="session-details">
              <div class="detail">
                <span class="detail-label">{$_('sessions.created')}</span>
                <span class="detail-value">{timeAgo(s.createdAt)}</span>
              </div>
              <div class="detail">
                <span class="detail-label">{$_('sessions.expires')}</span>
                <span class="detail-value">{formatDate(s.expiresAt)}</span>
              </div>
            </div>
          </div>
          <button
            type="button"
            class="sm secondary"
            class:danger={!s.isCurrent}
            onclick={() => revokeSession(s.id, s.isCurrent)}
          >
            {s.isCurrent ? $_('sessions.signOut') : $_('sessions.revoke')}
          </button>
        </div>
      {/each}
    </div>
    <div class="actions-bar">
      <button type="button" class="sm tertiary" onclick={loadSessions}>{$_('common.refresh')}</button>
      {#if sessions.filter(s => !s.isCurrent).length > 0}
        <button type="button" class="sm danger-outline" onclick={revokeAllSessions}>{$_('sessions.revokeAll')}</button>
      {/if}
    </div>
  {/if}
</div>
