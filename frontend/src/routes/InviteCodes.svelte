<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, type InviteCode, ApiError } from '../lib/api'

  const auth = getAuthState()

  let codes = $state<InviteCode[]>([])
  let loading = $state(true)
  let error = $state<string | null>(null)

  let creating = $state(false)
  let createdCode = $state<string | null>(null)

  $effect(() => {
    if (!auth.loading && !auth.session) {
      navigate('/login')
    }
  })

  $effect(() => {
    if (auth.session) {
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
    <a href="#/dashboard" class="back">&larr; Dashboard</a>
    <h1>Invite Codes</h1>
  </header>

  <p class="description">
    Invite codes let you invite friends to join. Each code can be used once.
  </p>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  {#if createdCode}
    <div class="created-code">
      <h3>Invite Code Created</h3>
      <div class="code-display">
        <code>{createdCode}</code>
        <button class="copy" onclick={() => copyCode(createdCode!)}>Copy</button>
      </div>
      <button onclick={dismissCreated}>Done</button>
    </div>
  {/if}

  <section class="create-section">
    <button onclick={handleCreate} disabled={creating}>
      {creating ? 'Creating...' : 'Create New Invite Code'}
    </button>
  </section>

  <section class="list-section">
    <h2>Your Invite Codes</h2>

    {#if loading}
      <p class="empty">Loading...</p>
    {:else if codes.length === 0}
      <p class="empty">No invite codes yet</p>
    {:else}
      <ul class="code-list">
        {#each codes as code}
          <li class:disabled={code.disabled} class:used={code.uses.length > 0 && code.available === 0}>
            <div class="code-main">
              <code>{code.code}</code>
              <button class="copy-small" onclick={() => copyCode(code.code)} title="Copy">
                Copy
              </button>
            </div>
            <div class="code-meta">
              <span class="date">Created {new Date(code.createdAt).toLocaleDateString()}</span>
              {#if code.disabled}
                <span class="status disabled">Disabled</span>
              {:else if code.uses.length > 0}
                <span class="status used">Used by @{code.uses[0].usedBy.split(':').pop()}</span>
              {:else}
                <span class="status available">Available</span>
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
    max-width: 600px;
    margin: 0 auto;
    padding: 2rem;
  }

  header {
    margin-bottom: 1rem;
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

  .description {
    color: var(--text-secondary);
    margin-bottom: 2rem;
  }

  .error {
    padding: 0.75rem;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: 4px;
    color: var(--error-text);
    margin-bottom: 1rem;
  }

  .created-code {
    padding: 1.5rem;
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    border-radius: 8px;
    margin-bottom: 2rem;
  }

  .created-code h3 {
    margin: 0 0 1rem 0;
    color: var(--success-text);
  }

  .code-display {
    display: flex;
    align-items: center;
    gap: 1rem;
    background: var(--bg-card);
    padding: 1rem;
    border-radius: 4px;
    margin-bottom: 1rem;
  }

  .code-display code {
    font-size: 1.125rem;
    font-family: monospace;
    flex: 1;
  }

  .copy {
    padding: 0.5rem 1rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }

  .copy:hover {
    background: var(--accent-hover);
  }

  .create-section {
    margin-bottom: 2rem;
  }

  .create-section button {
    padding: 0.75rem 1.5rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 1rem;
  }

  .create-section button:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .create-section button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  section h2 {
    font-size: 1.125rem;
    margin: 0 0 1rem 0;
  }

  .code-list {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .code-list li {
    padding: 1rem;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    margin-bottom: 0.5rem;
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
    gap: 0.5rem;
    margin-bottom: 0.5rem;
  }

  .code-main code {
    font-family: monospace;
    font-size: 0.9rem;
  }

  .copy-small {
    padding: 0.25rem 0.5rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    font-size: 0.75rem;
    cursor: pointer;
    color: var(--text-primary);
  }

  .copy-small:hover {
    background: var(--bg-input-disabled);
  }

  .code-meta {
    display: flex;
    gap: 1rem;
    font-size: 0.875rem;
  }

  .date {
    color: var(--text-secondary);
  }

  .status {
    padding: 0.125rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
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
    padding: 2rem;
  }
</style>
