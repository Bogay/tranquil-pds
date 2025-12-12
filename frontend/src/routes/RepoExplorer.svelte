<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'

  const auth = getAuthState()

  type View = 'collections' | 'records' | 'record' | 'create'

  let view = $state<View>('collections')
  let collections = $state<string[]>([])
  let selectedCollection = $state<string | null>(null)
  let records = $state<Array<{ uri: string; cid: string; value: unknown; rkey: string }>>([])
  let recordsCursor = $state<string | undefined>(undefined)
  let selectedRecord = $state<{ uri: string; cid: string; value: unknown; rkey: string } | null>(null)

  let loading = $state(true)
  let loadingMore = $state(false)
  let error = $state<{ code?: string; message: string } | null>(null)
  let success = $state<string | null>(null)

  function setError(e: unknown) {
    if (e instanceof ApiError) {
      error = { code: e.error, message: e.message }
    } else if (e instanceof Error) {
      error = { message: e.message }
    } else {
      error = { message: 'An unknown error occurred' }
    }
  }

  let newCollection = $state('')
  let newRkey = $state('')
  let recordJson = $state('')
  let jsonError = $state<string | null>(null)
  let saving = $state(false)

  let filter = $state('')

  $effect(() => {
    if (!auth.loading && !auth.session) {
      navigate('/login')
    }
  })

  $effect(() => {
    if (auth.session) {
      loadCollections()
    }
  })

  async function loadCollections() {
    if (!auth.session) return
    loading = true
    error = null

    try {
      const result = await api.describeRepo(auth.session.accessJwt, auth.session.did)
      collections = result.collections.sort()
    } catch (e) {
      setError(e)
    } finally {
      loading = false
    }
  }

  async function selectCollection(collection: string) {
    if (!auth.session) return
    selectedCollection = collection
    records = []
    recordsCursor = undefined
    view = 'records'
    loading = true
    error = null

    try {
      const result = await api.listRecords(auth.session.accessJwt, auth.session.did, collection, { limit: 50 })
      records = result.records.map(r => ({
        ...r,
        rkey: r.uri.split('/').pop()!
      }))
      recordsCursor = result.cursor
    } catch (e) {
      setError(e)
    } finally {
      loading = false
    }
  }

  async function loadMoreRecords() {
    if (!auth.session || !selectedCollection || !recordsCursor) return
    loadingMore = true

    try {
      const result = await api.listRecords(auth.session.accessJwt, auth.session.did, selectedCollection, {
        limit: 50,
        cursor: recordsCursor
      })
      records = [...records, ...result.records.map(r => ({
        ...r,
        rkey: r.uri.split('/').pop()!
      }))]
      recordsCursor = result.cursor
    } catch (e) {
      setError(e)
    } finally {
      loadingMore = false
    }
  }

  async function selectRecord(record: { uri: string; cid: string; value: unknown; rkey: string }) {
    selectedRecord = record
    recordJson = JSON.stringify(record.value, null, 2)
    jsonError = null
    view = 'record'
  }

  function startCreate(collection?: string) {
    newCollection = collection || 'app.bsky.feed.post'
    newRkey = ''

    const exampleRecords: Record<string, unknown> = {
      'app.bsky.feed.post': {
        $type: 'app.bsky.feed.post',
        text: 'Hello from my PDS! This is my first post.',
        createdAt: new Date().toISOString(),
      },
      'app.bsky.actor.profile': {
        $type: 'app.bsky.actor.profile',
        displayName: 'Your Display Name',
        description: 'A short bio about yourself.',
      },
      'app.bsky.graph.follow': {
        $type: 'app.bsky.graph.follow',
        subject: 'did:web:example.com',
        createdAt: new Date().toISOString(),
      },
      'app.bsky.feed.like': {
        $type: 'app.bsky.feed.like',
        subject: {
          uri: 'at://did:web:example.com/app.bsky.feed.post/abc123',
          cid: 'bafyreiabc123...',
        },
        createdAt: new Date().toISOString(),
      },
    }

    const example = exampleRecords[collection || 'app.bsky.feed.post'] || {
      $type: collection || 'app.bsky.feed.post',
    }

    recordJson = JSON.stringify(example, null, 2)
    jsonError = null
    view = 'create'
  }

  function validateJson(): unknown | null {
    try {
      const parsed = JSON.parse(recordJson)
      jsonError = null
      return parsed
    } catch (e) {
      jsonError = e instanceof Error ? e.message : 'Invalid JSON'
      return null
    }
  }

  async function handleCreate(e: Event) {
    e.preventDefault()
    if (!auth.session) return

    const record = validateJson()
    if (!record) return

    if (!newCollection.trim()) {
      error = { message: 'Collection is required' }
      return
    }

    saving = true
    error = null

    try {
      const result = await api.createRecord(
        auth.session.accessJwt,
        auth.session.did,
        newCollection.trim(),
        record,
        newRkey.trim() || undefined
      )
      success = `Record created: ${result.uri}`
      await loadCollections()
      await selectCollection(newCollection.trim())
    } catch (e) {
      setError(e)
    } finally {
      saving = false
    }
  }

  async function handleUpdate(e: Event) {
    e.preventDefault()
    if (!auth.session || !selectedRecord || !selectedCollection) return

    const record = validateJson()
    if (!record) return

    saving = true
    error = null

    try {
      await api.putRecord(
        auth.session.accessJwt,
        auth.session.did,
        selectedCollection,
        selectedRecord.rkey,
        record
      )
      success = 'Record updated'
      const updated = await api.getRecord(
        auth.session.accessJwt,
        auth.session.did,
        selectedCollection,
        selectedRecord.rkey
      )
      selectedRecord = { ...updated, rkey: selectedRecord.rkey }
      recordJson = JSON.stringify(updated.value, null, 2)
    } catch (e) {
      setError(e)
    } finally {
      saving = false
    }
  }

  async function handleDelete() {
    if (!auth.session || !selectedRecord || !selectedCollection) return
    if (!confirm(`Delete record ${selectedRecord.rkey}? This cannot be undone.`)) return

    saving = true
    error = null

    try {
      await api.deleteRecord(
        auth.session.accessJwt,
        auth.session.did,
        selectedCollection,
        selectedRecord.rkey
      )
      success = 'Record deleted'
      selectedRecord = null
      await selectCollection(selectedCollection)
    } catch (e) {
      setError(e)
    } finally {
      saving = false
    }
  }

  function goBack() {
    if (view === 'record' || view === 'create') {
      if (selectedCollection) {
        view = 'records'
      } else {
        view = 'collections'
      }
    } else if (view === 'records') {
      selectedCollection = null
      view = 'collections'
    }
    error = null
    success = null
  }

  let filteredCollections = $derived(
    filter
      ? collections.filter(c => c.toLowerCase().includes(filter.toLowerCase()))
      : collections
  )

  let filteredRecords = $derived(
    filter
      ? records.filter(r =>
          r.rkey.toLowerCase().includes(filter.toLowerCase()) ||
          JSON.stringify(r.value).toLowerCase().includes(filter.toLowerCase())
        )
      : records
  )

  function groupCollectionsByAuthority(cols: string[]): Map<string, string[]> {
    const groups = new Map<string, string[]>()
    for (const col of cols) {
      const parts = col.split('.')
      const authority = parts.slice(0, -1).join('.')
      const name = parts[parts.length - 1]
      if (!groups.has(authority)) {
        groups.set(authority, [])
      }
      groups.get(authority)!.push(name)
    }
    return groups
  }

  let groupedCollections = $derived(groupCollectionsByAuthority(filteredCollections))
</script>

<div class="page">
  <header>
    <div class="breadcrumb">
      <a href="#/dashboard" class="back">&larr; Dashboard</a>
      {#if view !== 'collections'}
        <span class="sep">/</span>
        <button class="breadcrumb-link" onclick={goBack}>
          {view === 'records' || view === 'create' ? 'Collections' : selectedCollection}
        </button>
      {/if}
      {#if view === 'record' && selectedRecord}
        <span class="sep">/</span>
        <span class="current">{selectedRecord.rkey}</span>
      {/if}
      {#if view === 'create'}
        <span class="sep">/</span>
        <span class="current">New Record</span>
      {/if}
    </div>
    <h1>
      {#if view === 'collections'}
        Repository Explorer
      {:else if view === 'records'}
        {selectedCollection}
      {:else if view === 'record'}
        Record Detail
      {:else}
        Create Record
      {/if}
    </h1>
    {#if auth.session}
      <p class="did">{auth.session.did}</p>
    {/if}
  </header>

  {#if error}
    <div class="message error">
      {#if error.code}
        <strong class="error-code">{error.code}</strong>
      {/if}
      <span class="error-message">{error.message}</span>
    </div>
  {/if}

  {#if success}
    <div class="message success">{success}</div>
  {/if}

  {#if loading}
    <p class="loading-text">Loading...</p>
  {:else if view === 'collections'}
    <div class="toolbar">
      <input
        type="text"
        placeholder="Filter collections..."
        bind:value={filter}
        class="filter-input"
      />
      <button class="primary" onclick={() => startCreate()}>Create Record</button>
    </div>

    {#if collections.length === 0}
      <p class="empty">No collections yet. Create your first record to get started.</p>
    {:else}
      <div class="collections">
        {#each [...groupedCollections.entries()] as [authority, nsids]}
          <div class="collection-group">
            <h3 class="authority">{authority}</h3>
            <ul class="nsid-list">
              {#each nsids as nsid}
                <li>
                  <button class="collection-link" onclick={() => selectCollection(`${authority}.${nsid}`)}>
                    <span class="nsid">{nsid}</span>
                    <span class="arrow">&rarr;</span>
                  </button>
                </li>
              {/each}
            </ul>
          </div>
        {/each}
      </div>
    {/if}

  {:else if view === 'records'}
    <div class="toolbar">
      <input
        type="text"
        placeholder="Filter records..."
        bind:value={filter}
        class="filter-input"
      />
      <button class="primary" onclick={() => startCreate(selectedCollection!)}>Create Record</button>
    </div>

    {#if records.length === 0}
      <p class="empty">No records in this collection.</p>
    {:else}
      <ul class="record-list">
        {#each filteredRecords as record}
          <li>
            <button class="record-item" onclick={() => selectRecord(record)}>
              <div class="record-info">
                <span class="rkey">{record.rkey}</span>
                <span class="cid" title={record.cid}>{record.cid.slice(0, 12)}...</span>
              </div>
              <pre class="record-preview">{JSON.stringify(record.value, null, 2).slice(0, 200)}{JSON.stringify(record.value).length > 200 ? '...' : ''}</pre>
            </button>
          </li>
        {/each}
      </ul>

      {#if recordsCursor}
        <div class="load-more">
          <button onclick={loadMoreRecords} disabled={loadingMore}>
            {loadingMore ? 'Loading...' : 'Load More'}
          </button>
        </div>
      {/if}
    {/if}

  {:else if view === 'record' && selectedRecord}
    <div class="record-detail">
      <div class="record-meta">
        <dl>
          <dt>URI</dt>
          <dd class="mono">{selectedRecord.uri}</dd>
          <dt>CID</dt>
          <dd class="mono">{selectedRecord.cid}</dd>
        </dl>
      </div>

      <form onsubmit={handleUpdate}>
        <div class="editor-container">
          <label for="record-json">Record JSON</label>
          <textarea
            id="record-json"
            bind:value={recordJson}
            oninput={() => validateJson()}
            class:has-error={jsonError}
            spellcheck="false"
          ></textarea>
          {#if jsonError}
            <p class="json-error">{jsonError}</p>
          {/if}
        </div>

        <div class="actions">
          <button type="submit" class="primary" disabled={saving || !!jsonError}>
            {saving ? 'Saving...' : 'Update Record'}
          </button>
          <button type="button" class="danger" onclick={handleDelete} disabled={saving}>
            Delete
          </button>
        </div>
      </form>
    </div>

  {:else if view === 'create'}
    <form class="create-form" onsubmit={handleCreate}>
      <div class="field">
        <label for="collection">Collection (NSID)</label>
        <input
          id="collection"
          type="text"
          bind:value={newCollection}
          placeholder="app.bsky.feed.post"
          disabled={saving}
          required
        />
      </div>

      <div class="field">
        <label for="rkey">Record Key (optional)</label>
        <input
          id="rkey"
          type="text"
          bind:value={newRkey}
          placeholder="Auto-generated if empty (TID)"
          disabled={saving}
        />
        <p class="hint">Leave empty to auto-generate a TID-based key</p>
      </div>

      <div class="editor-container">
        <label for="new-record-json">Record JSON</label>
        <textarea
          id="new-record-json"
          bind:value={recordJson}
          oninput={() => validateJson()}
          class:has-error={jsonError}
          spellcheck="false"
        ></textarea>
        {#if jsonError}
          <p class="json-error">{jsonError}</p>
        {/if}
      </div>

      <div class="actions">
        <button type="submit" class="primary" disabled={saving || !!jsonError || !newCollection.trim()}>
          {saving ? 'Creating...' : 'Create Record'}
        </button>
        <button type="button" class="secondary" onclick={goBack}>
          Cancel
        </button>
      </div>
    </form>
  {/if}
</div>

<style>
  .page {
    max-width: 900px;
    margin: 0 auto;
    padding: 2rem;
  }

  header {
    margin-bottom: 1.5rem;
  }

  .breadcrumb {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.875rem;
    margin-bottom: 0.5rem;
  }

  .back {
    color: var(--text-secondary);
    text-decoration: none;
  }

  .back:hover {
    color: var(--accent);
  }

  .sep {
    color: var(--text-muted);
  }

  .breadcrumb-link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font-size: inherit;
  }

  .breadcrumb-link:hover {
    text-decoration: underline;
  }

  .current {
    color: var(--text-secondary);
  }

  h1 {
    margin: 0;
    font-size: 1.5rem;
  }

  .did {
    margin: 0.25rem 0 0 0;
    font-family: monospace;
    font-size: 0.75rem;
    color: var(--text-muted);
    word-break: break-all;
  }

  .message {
    padding: 1rem;
    border-radius: 8px;
    margin-bottom: 1rem;
  }

  .message.error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-text);
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .error-code {
    font-family: monospace;
    font-size: 0.875rem;
    opacity: 0.9;
  }

  .error-message {
    font-size: 0.9375rem;
    line-height: 1.5;
  }

  .message.success {
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    color: var(--success-text);
  }

  .loading-text {
    text-align: center;
    color: var(--text-secondary);
    padding: 2rem;
  }

  .toolbar {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }

  .filter-input {
    flex: 1;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    font-size: 0.875rem;
    background: var(--bg-input);
    color: var(--text-primary);
  }

  .filter-input:focus {
    outline: none;
    border-color: var(--accent);
  }

  button.primary {
    padding: 0.5rem 1rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.875rem;
  }

  button.primary:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  button.primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  button.secondary {
    padding: 0.5rem 1rem;
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.875rem;
  }

  button.secondary:hover:not(:disabled) {
    background: var(--bg-secondary);
  }

  button.danger {
    padding: 0.5rem 1rem;
    background: transparent;
    color: var(--error-text);
    border: 1px solid var(--error-text);
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.875rem;
  }

  button.danger:hover:not(:disabled) {
    background: var(--error-bg);
  }

  .empty {
    text-align: center;
    color: var(--text-secondary);
    padding: 3rem;
    background: var(--bg-secondary);
    border-radius: 8px;
  }

  .collections {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .collection-group {
    background: var(--bg-secondary);
    border-radius: 8px;
    padding: 1rem;
  }

  .authority {
    margin: 0 0 0.75rem 0;
    font-size: 0.875rem;
    color: var(--text-secondary);
    font-weight: 500;
  }

  .nsid-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .collection-link {
    display: flex;
    justify-content: space-between;
    align-items: center;
    width: 100%;
    padding: 0.75rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    cursor: pointer;
    text-align: left;
    color: var(--text-primary);
    transition: border-color 0.15s;
  }

  .collection-link:hover {
    border-color: var(--accent);
  }

  .nsid {
    font-weight: 500;
    color: var(--accent);
  }

  .arrow {
    color: var(--text-muted);
  }

  .record-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .record-item {
    display: block;
    width: 100%;
    padding: 1rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    cursor: pointer;
    text-align: left;
    color: var(--text-primary);
    transition: border-color 0.15s;
  }

  .record-item:hover {
    border-color: var(--accent);
  }

  .record-info {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.5rem;
  }

  .rkey {
    font-family: monospace;
    font-weight: 500;
    color: var(--accent);
  }

  .cid {
    font-family: monospace;
    font-size: 0.75rem;
    color: var(--text-muted);
  }

  .record-preview {
    margin: 0;
    padding: 0.5rem;
    background: var(--bg-secondary);
    border-radius: 4px;
    font-family: monospace;
    font-size: 0.75rem;
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 100px;
    overflow: hidden;
  }

  .load-more {
    text-align: center;
    padding: 1rem;
  }

  .load-more button {
    padding: 0.5rem 2rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    cursor: pointer;
    color: var(--text-primary);
  }

  .load-more button:hover:not(:disabled) {
    background: var(--bg-card);
  }

  .record-detail {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .record-meta {
    background: var(--bg-secondary);
    padding: 1rem;
    border-radius: 8px;
  }

  .record-meta dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 0.5rem 1rem;
    margin: 0;
  }

  .record-meta dt {
    font-weight: 500;
    color: var(--text-secondary);
  }

  .record-meta dd {
    margin: 0;
  }

  .mono {
    font-family: monospace;
    font-size: 0.75rem;
    word-break: break-all;
  }

  .field {
    margin-bottom: 1rem;
  }

  .field label {
    display: block;
    font-size: 0.875rem;
    font-weight: 500;
    margin-bottom: 0.25rem;
  }

  .field input {
    width: 100%;
    padding: 0.75rem;
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    font-size: 1rem;
    background: var(--bg-input);
    color: var(--text-primary);
    box-sizing: border-box;
  }

  .field input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .hint {
    font-size: 0.75rem;
    color: var(--text-muted);
    margin: 0.25rem 0 0 0;
  }

  .editor-container {
    margin-bottom: 1rem;
  }

  .editor-container label {
    display: block;
    font-size: 0.875rem;
    font-weight: 500;
    margin-bottom: 0.25rem;
  }

  textarea {
    width: 100%;
    min-height: 300px;
    padding: 1rem;
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    font-family: monospace;
    font-size: 0.875rem;
    background: var(--bg-input);
    color: var(--text-primary);
    resize: vertical;
    box-sizing: border-box;
  }

  textarea:focus {
    outline: none;
    border-color: var(--accent);
  }

  textarea.has-error {
    border-color: var(--error-text);
  }

  .json-error {
    margin: 0.25rem 0 0 0;
    font-size: 0.75rem;
    color: var(--error-text);
  }

  .actions {
    display: flex;
    gap: 0.5rem;
  }

  .create-form {
    background: var(--bg-secondary);
    padding: 1.5rem;
    border-radius: 8px;
  }
</style>
