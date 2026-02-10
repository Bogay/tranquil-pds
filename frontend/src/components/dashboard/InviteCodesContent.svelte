<script lang="ts">
  import { onMount } from 'svelte'
  import { _ } from '../../lib/i18n'
  import { api, ApiError, type InviteCode } from '../../lib/api'
  import { toast } from '../../lib/toast.svelte'
  import { formatDate } from '../../lib/date'
  import type { Session } from '../../lib/types/api'
  import Skeleton from '../Skeleton.svelte'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  let codes = $state<InviteCode[]>([])
  let loading = $state(true)
  let creating = $state(false)
  let disablingCode = $state<string | null>(null)
  let createdCode = $state<string | null>(null)
  let createdCodeCopied = $state(false)
  let copiedCode = $state<string | null>(null)

  onMount(async () => {
    await loadCodes()
  })

  async function loadCodes() {
    loading = true
    try {
      const result = await api.getAccountInviteCodes(session.accessJwt)
      codes = result.codes
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('inviteCodes.loadFailed'))
    } finally {
      loading = false
    }
  }

  async function handleCreate() {
    creating = true
    try {
      const result = await api.createInviteCode(session.accessJwt, 1)
      createdCode = result.code
      await loadCodes()
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('inviteCodes.createFailed'))
    } finally {
      creating = false
    }
  }

  function dismissCreated() {
    createdCode = null
    createdCodeCopied = false
  }

  function copyCreatedCode() {
    if (createdCode) {
      navigator.clipboard.writeText(createdCode)
      createdCodeCopied = true
    }
  }

  async function disableCode(code: string) {
    if (!confirm($_('inviteCodes.disableConfirm', { values: { code } }))) return
    disablingCode = code
    try {
      await api.disableInviteCodes(session.accessJwt, [code])
      codes = codes.map(c => c.code === code ? { ...c, disabled: true } : c)
      toast.success($_('inviteCodes.disableSuccess'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('inviteCodes.disableFailed'))
    } finally {
      disablingCode = null
    }
  }

  function copyCode(code: string) {
    navigator.clipboard.writeText(code)
    copiedCode = code
    setTimeout(() => {
      if (copiedCode === code) {
        copiedCode = null
      }
    }, 2000)
  }
</script>

<div class="invite-codes">
  {#if createdCode}
    <div class="created-code">
      <h3>{$_('inviteCodes.created')}</h3>
      <div class="code-display">
        <code>{createdCode}</code>
        <button class="sm" onclick={copyCreatedCode}>
          {createdCodeCopied ? $_('common.copied') : $_('common.copyToClipboard')}
        </button>
      </div>
      <button class="ghost sm" onclick={dismissCreated}>{$_('common.done')}</button>
    </div>
  {/if}

  {#if session.isAdmin}
    <div class="actions">
      <button onclick={handleCreate} disabled={creating}>
        {creating ? $_('common.creating') : $_('inviteCodes.createNew')}
      </button>
    </div>
  {/if}

  <section class="list-section">
    <h2>{$_('inviteCodes.yourCodes')}</h2>
    {#if loading}
      <ul class="code-list">
        {#each Array(3) as _}
          <li class="code-item skeleton-item">
            <div class="code-main">
              <Skeleton variant="line" size="medium" />
            </div>
            <div class="code-meta">
              <Skeleton variant="line" size="short" />
              <Skeleton variant="line" size="tiny" />
            </div>
          </li>
        {/each}
      </ul>
    {:else if codes.length === 0}
      <p class="empty">{$_('inviteCodes.noCodes')}</p>
    {:else}
      <ul class="code-list">
        {#each codes as code}
          <li class="code-item" class:disabled={code.disabled} class:used={code.uses.length > 0 && code.available === 0}>
            <div class="code-main">
              <code class="code-value">{code.code}</code>
              <button
                class="tertiary sm copy-btn"
                onclick={() => copyCode(code.code)}
              >
                {copiedCode === code.code ? $_('common.copied') : $_('inviteCodes.copy')}
              </button>
            </div>
            <div class="code-meta">
              <span class="date">{$_('inviteCodes.createdOn', { values: { date: formatDate(code.createdAt) } })}</span>
              {#if code.disabled}
                <span class="status disabled">{$_('inviteCodes.disabled')}</span>
              {:else if code.uses.length > 0}
                <span class="status used">{$_('inviteCodes.used', { values: { handle: code.uses[0].usedByHandle || code.uses[0].usedBy.split(':').pop() } })}</span>
              {:else if code.available === 0}
                <span class="status spent">{$_('inviteCodes.spent')}</span>
              {:else}
                <span class="status available">{$_('inviteCodes.available')}</span>
              {/if}
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
</div>

<style>
  .invite-codes {
    max-width: var(--width-lg);
  }

  .created-code {
    padding: var(--space-5);
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-6);
  }

  .created-code h3 {
    margin: 0 0 var(--space-4) 0;
    color: var(--success-text);
  }

  .code-display {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    background: var(--bg-card);
    padding: var(--space-4);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-4);
  }

  .code-display code {
    font-size: var(--text-lg);
    font-family: var(--font-mono);
    flex: 1;
  }

  .actions {
    margin-bottom: var(--space-6);
  }

  .list-section h2 {
    font-size: var(--text-lg);
    margin: 0 0 var(--space-4) 0;
  }

  .empty {
    color: var(--text-secondary);
    padding: var(--space-6);
    text-align: center;
  }

  .code-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .code-item {
    padding: var(--space-4);
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
  }

  .skeleton-item {
    pointer-events: none;
  }

  .code-item.disabled {
    opacity: 0.6;
  }

  .code-item.used {
    background: var(--bg-tertiary);
  }

  .code-main {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin-bottom: var(--space-2);
  }

  .code-value {
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    padding: var(--space-2) var(--space-3);
    background: var(--bg-card);
    border-radius: var(--radius-md);
  }

  .copy-btn {
    flex-shrink: 0;
  }

  .danger-text {
    color: var(--error-text);
    flex-shrink: 0;
  }

  .code-meta {
    display: flex;
    gap: var(--space-4);
    font-size: var(--text-sm);
    align-items: center;
    flex-wrap: wrap;
  }

  .date {
    color: var(--text-secondary);
  }

  .status {
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
  }

  .status.available {
    background: var(--success-bg);
    color: var(--success-text);
  }

  .status.used {
    background: var(--bg-secondary);
    color: var(--text-secondary);
  }

  .status.spent {
    background: var(--bg-tertiary);
    color: var(--text-tertiary);
  }

  .status.disabled {
    background: var(--error-bg);
    color: var(--error-text);
  }

  @media (max-width: 500px) {
    .code-display {
      flex-direction: column;
      align-items: stretch;
    }

    .code-main {
      flex-direction: column;
      align-items: stretch;
    }
  }
</style>
