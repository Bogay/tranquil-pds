<script lang="ts">
  import { onMount } from 'svelte'
  import { _ } from '../../lib/i18n'
  import { api } from '../../lib/api'
  import { toast } from '../../lib/toast.svelte'
  import { formatDateTime } from '../../lib/date'
  import type { Session, DelegationAuditEntry } from '../../lib/types/api'
  import LoadMoreSentinel from '../LoadMoreSentinel.svelte'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  interface AuditEntry {
    id: string
    delegatedDid: string
    actorDid: string
    controllerDid: string | null
    actionType: string
    actionDetails: Record<string, unknown> | null
    createdAt: string
  }

  let loading = $state(true)
  let loadingMore = $state(false)
  let entries = $state<AuditEntry[]>([])
  let hasMore = $state(true)
  let offset = $state(0)
  const limit = 20

  onMount(async () => {
    await loadAuditLog()
  })

  async function loadAuditLog() {
    loading = true
    offset = 0
    try {
      const result = await api.getDelegationAuditLog(session.accessJwt, limit, 0)
      if (result.ok && result.value) {
        const rawEntries = Array.isArray(result.value.entries) ? result.value.entries : []
        entries = rawEntries.map(mapEntry)
        const total = result.value.total ?? 0
        hasMore = entries.length < total
        offset = entries.length
      } else {
        entries = []
        hasMore = false
      }
    } catch {
      toast.error($_('delegation.failedToLoadAudit'))
      entries = []
      hasMore = false
    } finally {
      loading = false
    }
  }

  async function loadMoreEntries() {
    if (loadingMore || !hasMore) return
    loadingMore = true
    try {
      const result = await api.getDelegationAuditLog(session.accessJwt, limit, offset)
      if (result.ok && result.value) {
        const rawEntries = Array.isArray(result.value.entries) ? result.value.entries : []
        const newEntries = rawEntries.map(mapEntry)
        entries = [...entries, ...newEntries]
        const total = result.value.total ?? 0
        hasMore = entries.length < total
        offset = entries.length
      }
    } catch {
      toast.error($_('delegation.failedToLoadAudit'))
    } finally {
      loadingMore = false
    }
  }

  function mapEntry(e: DelegationAuditEntry): AuditEntry {
    return {
      id: e.id,
      delegatedDid: e.target_did ?? '',
      actorDid: e.actor_did,
      controllerDid: null,
      actionType: e.action,
      actionDetails: e.details ? JSON.parse(e.details) : null,
      createdAt: e.created_at
    }
  }

  function formatActionType(type: string): string {
    const labels: Record<string, string> = {
      'GrantCreated': $_('delegation.actionGrantCreated'),
      'GrantRevoked': $_('delegation.actionGrantRevoked'),
      'ScopesModified': $_('delegation.actionScopesModified'),
      'TokenIssued': $_('delegation.actionTokenIssued'),
      'RepoWrite': $_('delegation.actionRepoWrite'),
      'BlobUpload': $_('delegation.actionBlobUpload'),
      'AccountAction': $_('delegation.actionAccountAction')
    }
    return labels[type] || type
  }

  function formatActionDetails(details: Record<string, unknown> | null): string {
    if (!details) return ''
    return Object.entries(details)
      .map(([key, value]) => `${key.replace(/_/g, ' ')}: ${JSON.stringify(value)}`)
      .join(', ')
  }

  function truncateDid(did: string): string {
    if (did.length <= 30) return did
    return did.substring(0, 20) + '...' + did.substring(did.length - 6)
  }
</script>

<div class="audit">
  <div class="actions-bar">
    <button type="button" class="ghost" onclick={() => loadAuditLog()} disabled={loading}>
      {loading ? $_('common.loading') : $_('delegation.refresh')}
    </button>
  </div>

  {#if loading}
    <div class="loading">{$_('common.loading')}</div>
  {:else if entries.length === 0}
    <p class="empty">{$_('delegation.noAuditEntries')}</p>
  {:else}
    <div class="entries">
      {#each entries as entry}
        <div class="entry">
          <div class="entry-header">
            <span class="action-type">{formatActionType(entry.actionType)}</span>
            <span class="entry-date">{formatDateTime(entry.createdAt)}</span>
          </div>
          <div class="entry-details">
            <div class="detail">
              <span class="label">{$_('delegation.actor')}</span>
              <span class="value did" title={entry.actorDid}>{truncateDid(entry.actorDid)}</span>
            </div>
            {#if entry.delegatedDid}
              <div class="detail">
                <span class="label">{$_('delegation.target')}</span>
                <span class="value did" title={entry.delegatedDid}>{truncateDid(entry.delegatedDid)}</span>
              </div>
            {/if}
            {#if entry.actionDetails}
              <div class="detail">
                <span class="label">{$_('delegation.details')}</span>
                <span class="value details">{formatActionDetails(entry.actionDetails)}</span>
              </div>
            {/if}
          </div>
        </div>
      {/each}
    </div>

    <LoadMoreSentinel {hasMore} loading={loadingMore} onLoadMore={loadMoreEntries} />
  {/if}
</div>

<style>
  .audit {
    max-width: var(--width-lg);
  }

  .actions-bar {
    display: flex;
    justify-content: flex-end;
    margin-bottom: var(--space-4);
  }

  .ghost {
    background: transparent;
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    padding: var(--space-2) var(--space-4);
    border-radius: var(--radius-md);
    cursor: pointer;
  }

  .ghost:hover:not(:disabled) {
    border-color: var(--accent);
  }

  .ghost:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .loading,
  .empty {
    color: var(--text-secondary);
    padding: var(--space-6);
    text-align: center;
  }

  .entries {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .entry {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
  }

  .entry-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--space-3);
  }

  .action-type {
    font-weight: var(--font-medium);
    padding: var(--space-1) var(--space-2);
    background: var(--accent);
    color: var(--text-inverse);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
  }

  .entry-date {
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .entry-details {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .detail {
    display: flex;
    gap: var(--space-2);
    font-size: var(--text-sm);
  }

  .detail .label {
    color: var(--text-secondary);
    min-width: 60px;
  }

  .detail .value {
    color: var(--text-primary);
  }

  .detail .value.did {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
  }

  .detail .value.details {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    word-break: break-word;
  }

  @media (max-width: 500px) {
    .entry-header {
      flex-direction: column;
      align-items: flex-start;
      gap: var(--space-2);
    }

    .detail {
      flex-direction: column;
      gap: var(--space-1);
    }

    .detail .label {
      min-width: unset;
    }
  }
</style>
