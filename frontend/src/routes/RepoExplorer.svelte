<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { _, locale } from '../lib/i18n'
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
      error = { message: $_('repoExplorer.unknownError') }
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
    if (!auth.session || !selectedCollection || !recordsCursor || loadingMore) return
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

  $effect(() => {
    if (view === 'records' && recordsCursor && !loadingMore && !loading) {
      loadMoreRecords()
    }
  })
  async function selectRecord(record: { uri: string; cid: string; value: unknown; rkey: string }) {
    selectedRecord = record
    recordJson = JSON.stringify(record.value, null, 2)
    jsonError = null
    view = 'record'
  }
  function startCreate(collection?: string) {
    newCollection = collection || 'app.bsky.feed.post'
    newRkey = ''
    const currentLocale = $locale?.split('-')[0] || 'en'
    const exampleRecords: Record<string, unknown> = {
      'app.bsky.feed.post': {
        $type: 'app.bsky.feed.post',
        text: $_('repoExplorer.demoPostText'),
        langs: [currentLocale],
        createdAt: new Date().toISOString(),
      },
      'app.bsky.actor.profile': {
        $type: 'app.bsky.actor.profile',
        displayName: $_('repoExplorer.demoDisplayName'),
        description: $_('repoExplorer.demoBio'),
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
      jsonError = e instanceof Error ? e.message : $_('repoExplorer.invalidJson')
      return null
    }
  }
  async function handleCreate(e: Event) {
    e.preventDefault()
    if (!auth.session) return
    const record = validateJson()
    if (!record) return
    if (!newCollection.trim()) {
      error = { message: $_('repoExplorer.collectionRequired') }
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
      success = $_('repoExplorer.recordCreated', { values: { uri: result.uri } })
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
      success = $_('repoExplorer.recordUpdated')
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
    if (!confirm($_('repoExplorer.deleteConfirm', { values: { rkey: selectedRecord.rkey } }))) return
    saving = true
    error = null
    try {
      await api.deleteRecord(
        auth.session.accessJwt,
        auth.session.did,
        selectedCollection,
        selectedRecord.rkey
      )
      success = $_('repoExplorer.recordDeleted')
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
      <a href="#/dashboard" class="back">{$_('common.backToDashboard')}</a>
      {#if view !== 'collections'}
        <span class="sep">/</span>
        <button class="breadcrumb-link" onclick={goBack}>
          {view === 'records' || view === 'create' ? $_('repoExplorer.collections') : selectedCollection}
        </button>
      {/if}
      {#if view === 'record' && selectedRecord}
        <span class="sep">/</span>
        <span class="current">{selectedRecord.rkey}</span>
      {/if}
      {#if view === 'create'}
        <span class="sep">/</span>
        <span class="current">{$_('repoExplorer.newRecord')}</span>
      {/if}
    </div>
    <h1>
      {#if view === 'collections'}
        {$_('repoExplorer.title')}
      {:else if view === 'records'}
        {selectedCollection}
      {:else if view === 'record'}
        {$_('repoExplorer.recordDetails')}
      {:else}
        {$_('repoExplorer.createRecord')}
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
    <p class="loading-text">{$_('common.loading')}</p>
  {:else if view === 'collections'}
    <div class="toolbar">
      <input
        type="text"
        placeholder={$_('repoExplorer.filterCollections')}
        bind:value={filter}
        class="filter-input"
      />
      <button class="primary" onclick={() => startCreate()}>{$_('repoExplorer.createRecord')}</button>
    </div>
    {#if collections.length === 0}
      <p class="empty">{$_('repoExplorer.noCollectionsYet')}</p>
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
        placeholder={$_('repoExplorer.filterRecords')}
        bind:value={filter}
        class="filter-input"
      />
      <button class="primary" onclick={() => startCreate(selectedCollection!)}>{$_('repoExplorer.createRecord')}</button>
    </div>
    {#if records.length === 0}
      <p class="empty">{$_('repoExplorer.noRecords')}</p>
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
      {#if loadingMore}
        <div class="skeleton-records">
          {#each [1, 2, 3] as _}
            <div class="skeleton-record">
              <div class="skeleton-record-header">
                <div class="skeleton-line short"></div>
                <div class="skeleton-line tiny"></div>
              </div>
              <div class="skeleton-preview"></div>
            </div>
          {/each}
        </div>
      {/if}
    {/if}
  {:else if view === 'record' && selectedRecord}
    <div class="record-detail">
      <div class="record-meta">
        <dl>
          <dt>{$_('repoExplorer.uri')}</dt>
          <dd class="mono">{selectedRecord.uri}</dd>
          <dt>{$_('repoExplorer.cid')}</dt>
          <dd class="mono">{selectedRecord.cid}</dd>
        </dl>
      </div>
      <form onsubmit={handleUpdate}>
        <div class="editor-container">
          <label for="record-json">{$_('repoExplorer.recordJson')}</label>
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
            {saving ? $_('common.saving') : $_('repoExplorer.updateRecord')}
          </button>
          <button type="button" class="danger" onclick={handleDelete} disabled={saving}>
            {$_('common.delete')}
          </button>
        </div>
      </form>
    </div>
  {:else if view === 'create'}
    <form class="create-form" onsubmit={handleCreate}>
      <div class="field">
        <label for="collection">{$_('repoExplorer.collectionNsid')}</label>
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
        <label for="rkey">{$_('repoExplorer.recordKeyOptional')}</label>
        <input
          id="rkey"
          type="text"
          bind:value={newRkey}
          placeholder={$_('repoExplorer.autoGenerated')}
          disabled={saving}
        />
        <p class="hint">{$_('repoExplorer.autoGeneratedHint')}</p>
      </div>
      <div class="editor-container">
        <label for="new-record-json">{$_('repoExplorer.recordJson')}</label>
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
          {saving ? $_('common.creating') : $_('repoExplorer.createRecord')}
        </button>
        <button type="button" class="secondary" onclick={goBack}>
          {$_('common.cancel')}
        </button>
      </div>
    </form>
  {/if}
</div>
<style>
  .page {
    max-width: var(--width-xl);
    margin: 0 auto;
    padding: var(--space-7);
  }

  header {
    margin-bottom: var(--space-6);
  }

  .breadcrumb {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
    margin-bottom: var(--space-2);
  }

  .back {
    color: var(--text-secondary);
    text-decoration: none;
    padding: var(--space-1) var(--space-2);
    margin: calc(-1 * var(--space-1)) calc(-1 * var(--space-2));
    border-radius: var(--radius-sm);
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .back:hover {
    color: var(--accent);
    background: var(--accent-muted);
  }

  .back:focus {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .sep {
    color: var(--text-muted);
  }

  .breadcrumb-link {
    background: none;
    border: none;
    padding: var(--space-1) var(--space-2);
    margin: calc(-1 * var(--space-1)) calc(-1 * var(--space-2));
    color: var(--accent);
    cursor: pointer;
    font-size: inherit;
    border-radius: var(--radius-sm);
    transition: background var(--transition-fast);
  }

  .breadcrumb-link:hover {
    background: var(--accent-muted);
    text-decoration: underline;
  }

  .breadcrumb-link:focus {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .current {
    color: var(--text-secondary);
  }

  h1 {
    margin: 0;
    font-size: var(--text-xl);
  }

  .did {
    margin: var(--space-1) 0 0 0;
    font-family: monospace;
    font-size: var(--text-xs);
    color: var(--text-muted);
    word-break: break-all;
  }

  .message {
    padding: var(--space-4);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-4);
  }

  .message.error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-text);
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .error-code {
    font-family: monospace;
    font-size: var(--text-sm);
    opacity: 0.9;
  }

  .error-message {
    font-size: var(--text-sm);
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
    padding: var(--space-7);
  }

  .toolbar {
    display: flex;
    gap: var(--space-2);
    margin-bottom: var(--space-4);
  }

  .filter-input {
    flex: 1;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    background: var(--bg-input);
    color: var(--text-primary);
  }

  .filter-input:focus {
    outline: none;
    border-color: var(--accent);
  }

  button.primary {
    padding: var(--space-2) var(--space-4);
    background: var(--accent);
    color: var(--text-inverse);
    border: none;
    border-radius: var(--radius-md);
    cursor: pointer;
    font-size: var(--text-sm);
  }

  button.primary:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  button.primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  button.secondary {
    padding: var(--space-2) var(--space-4);
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    cursor: pointer;
    font-size: var(--text-sm);
  }

  button.secondary:hover:not(:disabled) {
    background: var(--bg-secondary);
  }

  button.danger {
    padding: var(--space-2) var(--space-4);
    background: transparent;
    color: var(--error-text);
    border: 1px solid var(--error-text);
    border-radius: var(--radius-md);
    cursor: pointer;
    font-size: var(--text-sm);
  }

  button.danger:hover:not(:disabled) {
    background: var(--error-bg);
  }

  .empty {
    text-align: center;
    color: var(--text-secondary);
    padding: var(--space-8);
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
  }

  .collections {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .collection-group {
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
    padding: var(--space-4);
  }

  .authority {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-sm);
    color: var(--text-secondary);
    font-weight: var(--font-medium);
  }

  .nsid-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .collection-link {
    display: flex;
    justify-content: space-between;
    align-items: center;
    width: 100%;
    padding: var(--space-3);
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    cursor: pointer;
    text-align: left;
    color: var(--text-primary);
    transition: background var(--transition-fast), border-color var(--transition-fast);
  }

  .collection-link:hover {
    background: var(--bg-secondary);
    border-color: var(--accent);
  }

  .collection-link:focus {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .collection-link:active {
    background: var(--bg-tertiary);
  }

  .nsid {
    font-weight: var(--font-medium);
    color: var(--accent);
  }

  .arrow {
    color: var(--text-muted);
  }

  .collection-link:hover .arrow {
    color: var(--accent);
  }

  .record-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .record-item {
    display: block;
    width: 100%;
    padding: var(--space-4);
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    cursor: pointer;
    text-align: left;
    color: var(--text-primary);
    transition: background var(--transition-fast), border-color var(--transition-fast);
  }

  .record-item:hover {
    background: var(--bg-secondary);
    border-color: var(--accent);
  }

  .record-item:focus {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .record-item:active {
    background: var(--bg-tertiary);
  }

  .record-info {
    display: flex;
    justify-content: space-between;
    margin-bottom: var(--space-2);
  }

  .rkey {
    font-family: monospace;
    font-weight: var(--font-medium);
    color: var(--accent);
  }

  .cid {
    font-family: monospace;
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .record-preview {
    margin: 0;
    padding: var(--space-2);
    background: var(--bg-secondary);
    border-radius: var(--radius-md);
    font-family: monospace;
    font-size: var(--text-xs);
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 100px;
    overflow: hidden;
  }

  .skeleton-records {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin-top: var(--space-2);
  }

  .skeleton-record {
    padding: var(--space-4);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
  }

  .skeleton-record-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: var(--space-2);
  }

  .skeleton-line {
    height: 14px;
    background: var(--bg-tertiary);
    border-radius: var(--radius-sm);
    animation: skeleton-pulse 1.5s ease-in-out infinite;
  }

  .skeleton-line.short {
    width: 120px;
  }

  .skeleton-line.tiny {
    width: 80px;
  }

  .skeleton-preview {
    height: 60px;
    background: var(--bg-secondary);
    border-radius: var(--radius-md);
    animation: skeleton-pulse 1.5s ease-in-out infinite;
  }

  @keyframes skeleton-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  .record-detail {
    display: flex;
    flex-direction: column;
    gap: var(--space-6);
  }

  .record-meta {
    background: var(--bg-secondary);
    padding: var(--space-4);
    border-radius: var(--radius-xl);
  }

  .record-meta dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: var(--space-2) var(--space-4);
    margin: 0;
  }

  .record-meta dt {
    font-weight: var(--font-medium);
    color: var(--text-secondary);
  }

  .record-meta dd {
    margin: 0;
  }

  .mono {
    font-family: monospace;
    font-size: var(--text-xs);
    word-break: break-all;
  }

  .field {
    margin-bottom: var(--space-4);
  }

  .field label {
    display: block;
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
    margin-bottom: var(--space-1);
  }

  .field input {
    width: 100%;
    padding: var(--space-3);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-size: var(--text-base);
    background: var(--bg-input);
    color: var(--text-primary);
    box-sizing: border-box;
  }

  .field input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .hint {
    font-size: var(--text-xs);
    color: var(--text-muted);
    margin: var(--space-1) 0 0 0;
  }

  .editor-container {
    margin-bottom: var(--space-4);
  }

  .editor-container label {
    display: block;
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
    margin-bottom: var(--space-1);
  }

  textarea {
    width: 100%;
    min-height: 300px;
    padding: var(--space-4);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-family: monospace;
    font-size: var(--text-sm);
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
    margin: var(--space-1) 0 0 0;
    font-size: var(--text-xs);
    color: var(--error-text);
  }

  .actions {
    display: flex;
    gap: var(--space-2);
  }

  .create-form {
    background: var(--bg-secondary);
    padding: var(--space-6);
    border-radius: var(--radius-xl);
  }

  .page ::selection {
    background: var(--accent);
    color: var(--text-inverse);
  }

  .page ::-moz-selection {
    background: var(--accent);
    color: var(--text-inverse);
  }
</style>
