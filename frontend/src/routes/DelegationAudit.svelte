<script lang="ts">
  import AuthenticatedRoute from '../components/AuthenticatedRoute.svelte'
  import { _ } from '../lib/i18n'
  import { formatDateTime } from '../lib/date'
  import type { DelegationAuditEntry } from '../lib/types/api'
  import type { AuthenticatedClient } from '../lib/authenticated-client'

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
  let entries = $state<AuditEntry[]>([])
  let total = $state(0)
  let offset = $state(0)
  const limit = 20

  let currentClient: AuthenticatedClient | null = $state(null)

  function handleReady(_session: unknown, client: AuthenticatedClient) {
    currentClient = client
    loadAuditLog(client)
  }

  async function loadAuditLog(client: AuthenticatedClient) {
    loading = true

    const result = await client.getDelegationAuditLog(limit, offset)
    if (result.ok) {
      entries = (result.value.entries ?? []).map((e: DelegationAuditEntry) => ({
        id: e.id,
        delegatedDid: e.target_did ?? '',
        actorDid: e.actor_did,
        controllerDid: null,
        actionType: e.action,
        actionDetails: e.details ? JSON.parse(e.details) : null,
        createdAt: e.created_at
      }))
      total = result.value.total ?? 0
    }
    loading = false
  }

  function prevPage() {
    if (offset > 0 && currentClient) {
      offset = Math.max(0, offset - limit)
      loadAuditLog(currentClient)
    }
  }

  function nextPage() {
    if (offset + limit < total && currentClient) {
      offset = offset + limit
      loadAuditLog(currentClient)
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

<AuthenticatedRoute onReady={handleReady}>
  {#snippet children({ session, client })}
    <div class="page">
      <header>
        <a href="/app/controllers" class="back">{$_('delegation.backToControllers')}</a>
        <h1>{$_('delegation.auditLogTitle')}</h1>
      </header>

      {#if loading}
        <div class="skeleton-list">
          {#each Array(3) as _}
            <div class="skeleton-entry"></div>
          {/each}
        </div>
      {:else}
        {#if entries.length === 0}
          <p class="empty">{$_('delegation.noActivity')}</p>
        {:else}
          <div class="audit-list">
            {#each entries as entry}
              <div class="audit-entry">
                <div class="entry-header">
                  <span class="action-type">{formatActionType(entry.actionType)}</span>
                  <span class="timestamp">{formatDateTime(entry.createdAt)}</span>
                </div>
                <div class="entry-details">
                  <div class="detail">
                    <span class="label">{$_('delegation.actor')}</span>
                    <span class="value did" title={entry.actorDid}>{truncateDid(entry.actorDid)}</span>
                  </div>
                  {#if entry.controllerDid}
                    <div class="detail">
                      <span class="label">{$_('delegation.controller')}</span>
                      <span class="value did" title={entry.controllerDid}>{truncateDid(entry.controllerDid)}</span>
                    </div>
                  {/if}
                  <div class="detail">
                    <span class="label">{$_('delegation.account')}</span>
                    <span class="value did" title={entry.delegatedDid}>{truncateDid(entry.delegatedDid)}</span>
                  </div>
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

          <div class="pagination">
            <button
              class="ghost"
              onclick={prevPage}
              disabled={offset === 0}
            >
              {$_('delegation.previous')}
            </button>
            <span class="page-info">
              {$_('delegation.showing', { values: { start: offset + 1, end: Math.min(offset + limit, total), total } })}
            </span>
            <button
              class="ghost"
              onclick={nextPage}
              disabled={offset + limit >= total}
            >
              {$_('delegation.next')}
            </button>
          </div>
        {/if}

        <div class="actions-bar">
          <button class="ghost" onclick={() => currentClient && loadAuditLog(currentClient)}>{$_('delegation.refresh')}</button>
        </div>
      {/if}
    </div>
  {/snippet}
</AuthenticatedRoute>

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

  .empty {
    text-align: center;
    color: var(--text-secondary);
    padding: var(--space-7);
  }

  .audit-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    margin-bottom: var(--space-4);
  }

  .audit-entry {
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
    flex-wrap: wrap;
    gap: var(--space-2);
  }

  .action-type {
    font-weight: var(--font-semibold);
    color: var(--text-primary);
  }

  .timestamp {
    font-size: var(--text-sm);
    color: var(--text-muted);
  }

  .entry-details {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .detail {
    font-size: var(--text-sm);
    display: flex;
    gap: var(--space-2);
    align-items: baseline;
    flex-wrap: wrap;
  }

  .detail .label {
    color: var(--text-secondary);
    min-width: 80px;
  }

  .detail .value {
    color: var(--text-primary);
  }

  .detail .value.did {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    word-break: break-all;
  }

  .detail .value.details {
    font-size: var(--text-xs);
    color: var(--text-muted);
    word-break: break-word;
  }

  .pagination {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: var(--space-4);
    margin: var(--space-5) 0;
  }

  .pagination button {
    padding: var(--space-2) var(--space-4);
    font-size: var(--text-sm);
  }

  .page-info {
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .actions-bar {
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  .actions-bar button {
    padding: var(--space-2) var(--space-4);
    font-size: var(--text-sm);
  }

  .skeleton-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .skeleton-entry {
    height: 100px;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    animation: skeleton-pulse 1.5s ease-in-out infinite;
  }
</style>
