<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, type InviteCode, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import { formatDate } from '../lib/date'
  import { onMount } from 'svelte'

  const auth = getAuthState()
  let codes = $state<InviteCode[]>([])
  let loading = $state(true)
  let error = $state<string | null>(null)
  let creating = $state(false)
  let createdCode = $state<string | null>(null)
  let inviteCodesEnabled = $state<boolean | null>(null)

  onMount(async () => {
    try {
      const serverInfo = await api.describeServer()
      inviteCodesEnabled = serverInfo.inviteCodeRequired
      if (!serverInfo.inviteCodeRequired) {
        navigate('/dashboard')
      }
    } catch {
      navigate('/dashboard')
    }
  })

  $effect(() => {
    if (!auth.loading && !auth.session) {
      navigate('/login')
    }
  })
  $effect(() => {
    if (auth.session && inviteCodesEnabled) {
      loadCodes()
    }
  })
  async function loadCodes() {
    if (!auth.session) return
    loading = true
    error = null
    try {
      const result = await api.getAccountInviteCodes(auth.session.accessJwt)
      codes = result.codes
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to load invite codes'
    } finally {
      loading = false
    }
  }
  async function handleCreate() {
    if (!auth.session) return
    creating = true
    error = null
    try {
      const result = await api.createInviteCode(auth.session.accessJwt, 1)
      createdCode = result.code
      await loadCodes()
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to create invite code'
    } finally {
      creating = false
    }
  }
  function dismissCreated() {
    createdCode = null
  }
  function copyCode(code: string) {
    navigator.clipboard.writeText(code)
  }
</script>
<div class="page">
  <header>
    <a href="#/dashboard" class="back">{$_('common.backToDashboard')}</a>
    <h1>{$_('inviteCodes.title')}</h1>
  </header>
  <p class="description">
    {$_('inviteCodes.description')}
  </p>
  {#if error}
    <div class="error">{error}</div>
  {/if}
  {#if createdCode}
    <div class="created-code">
      <h3>{$_('inviteCodes.created')}</h3>
      <div class="code-display">
        <code>{createdCode}</code>
        <button class="copy" onclick={() => copyCode(createdCode!)}>{$_('inviteCodes.copy')}</button>
      </div>
      <button onclick={dismissCreated}>{$_('common.done')}</button>
    </div>
  {/if}
  <section class="create-section">
    <button onclick={handleCreate} disabled={creating}>
      {creating ? $_('inviteCodes.creating') : $_('inviteCodes.createNew')}
    </button>
  </section>
  <section class="list-section">
    <h2>{$_('inviteCodes.yourCodes')}</h2>
    {#if loading}
      <p class="empty">{$_('common.loading')}</p>
    {:else if codes.length === 0}
      <p class="empty">{$_('inviteCodes.noCodes')}</p>
    {:else}
      <ul class="code-list">
        {#each codes as code}
          <li class:disabled={code.disabled} class:used={code.uses.length > 0 && code.available === 0}>
            <div class="code-main">
              <code>{code.code}</code>
              <button class="copy-small" onclick={() => copyCode(code.code)} title={$_('inviteCodes.copy')}>
                {$_('inviteCodes.copy')}
              </button>
            </div>
            <div class="code-meta">
              <span class="date">{$_('inviteCodes.createdOn', { values: { date: formatDate(code.createdAt) } })}</span>
              {#if code.disabled}
                <span class="status disabled">{$_('inviteCodes.disabled')}</span>
              {:else if code.uses.length > 0}
                <span class="status used">{$_('inviteCodes.used', { values: { handle: code.uses[0].usedBy.split(':').pop() } })}</span>
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

  .error {
    padding: var(--space-3);
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: var(--radius-md);
    color: var(--error-text);
    margin-bottom: var(--space-4);
  }

  .created-code {
    padding: var(--space-6);
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-7);
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
    font-family: ui-monospace, monospace;
    flex: 1;
  }

  .copy {
    padding: var(--space-2) var(--space-4);
    background: var(--accent);
    color: var(--text-inverse);
    border: none;
    border-radius: var(--radius-md);
    cursor: pointer;
  }

  .copy:hover {
    background: var(--accent-hover);
  }

  .create-section {
    margin-bottom: var(--space-7);
  }

  section h2 {
    font-size: var(--text-lg);
    margin: 0 0 var(--space-4) 0;
  }

  .code-list {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .code-list li {
    padding: var(--space-4);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-2);
    background: var(--bg-card);
  }

  .code-list li.disabled {
    opacity: 0.6;
  }

  .code-list li.used {
    background: var(--bg-secondary);
  }

  .code-main {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-bottom: var(--space-2);
  }

  .code-main code {
    font-family: ui-monospace, monospace;
    font-size: var(--text-sm);
  }

  .copy-small {
    padding: var(--space-1) var(--space-2);
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
    cursor: pointer;
    color: var(--text-primary);
  }

  .copy-small:hover {
    background: var(--bg-input-disabled);
  }

  .code-meta {
    display: flex;
    gap: var(--space-4);
    font-size: var(--text-sm);
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

  .status.disabled {
    background: var(--error-bg);
    color: var(--error-text);
  }

  .empty {
    color: var(--text-secondary);
    text-align: center;
    padding: var(--space-7);
  }
</style>
