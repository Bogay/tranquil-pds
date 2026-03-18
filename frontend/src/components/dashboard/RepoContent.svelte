<script lang="ts">
  import { onMount } from 'svelte'
  import { _ } from '../../lib/i18n'
  import { locale } from 'svelte-i18n'
  import { api, ApiError } from '../../lib/api'
  import type { Session } from '../../lib/types/api'
  import { unsafeAsNsid, unsafeAsRkey } from '../../lib/types/branded'
  import LoadMoreSentinel from '../LoadMoreSentinel.svelte'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

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

  onMount(async () => {
    await loadCollections()
  })

  async function loadCollections() {
    loading = true
    error = null
    try {
      const result = await api.describeRepo(session.accessJwt, session.did)
      collections = result.collections.sort()
    } catch (e) {
      setError(e)
    } finally {
      loading = false
    }
  }

  async function selectCollection(collection: string) {
    selectedCollection = collection
    records = []
    recordsCursor = undefined
    view = 'records'
    loading = true
    error = null
    try {
      const result = await api.listRecords(session.accessJwt, session.did, unsafeAsNsid(collection), { limit: 50 })
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
    if (!selectedCollection || !recordsCursor || loadingMore) return
    loadingMore = true
    try {
      const result = await api.listRecords(session.accessJwt, session.did, unsafeAsNsid(selectedCollection), {
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
        session.accessJwt,
        session.did,
        unsafeAsNsid(newCollection.trim()),
        record,
        newRkey.trim() ? unsafeAsRkey(newRkey.trim()) : undefined
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
    if (!selectedRecord || !selectedCollection) return
    const record = validateJson()
    if (!record) return
    saving = true
    error = null
    try {
      await api.putRecord(
        session.accessJwt,
        session.did,
        unsafeAsNsid(selectedCollection),
        unsafeAsRkey(selectedRecord.rkey),
        record
      )
      success = $_('repoExplorer.recordUpdated')
      const updated = await api.getRecord(
        session.accessJwt,
        session.did,
        unsafeAsNsid(selectedCollection),
        unsafeAsRkey(selectedRecord.rkey)
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
    if (!selectedRecord || !selectedCollection) return
    if (!confirm($_('repoExplorer.deleteConfirm', { values: { rkey: selectedRecord.rkey } }))) return
    saving = true
    error = null
    try {
      await api.deleteRecord(
        session.accessJwt,
        session.did,
        unsafeAsNsid(selectedCollection),
        unsafeAsRkey(selectedRecord.rkey)
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
    return cols.reduce((groups, col) => {
      const parts = col.split('.')
      const authority = parts.slice(0, -1).join('.')
      const name = parts[parts.length - 1]
      return groups.set(authority, [...(groups.get(authority) ?? []), name])
    }, new Map<string, string[]>())
  }

  let groupedCollections = $derived(groupCollectionsByAuthority(filteredCollections))
</script>

<div class="repo-explorer">
  <nav class="breadcrumb">
    {#if view === 'collections'}
      <span class="breadcrumb-current">{$_('repoExplorer.collections')}</span>
    {:else}
      <button type="button" class="breadcrumb-link" onclick={() => { selectedCollection = null; view = 'collections' }}>
        {$_('repoExplorer.collections')}
      </button>
      <span class="breadcrumb-sep">/</span>
      {#if view === 'records' && selectedCollection}
        <span class="breadcrumb-current">{selectedCollection}</span>
      {:else if (view === 'record' || view === 'create') && selectedCollection}
        <button type="button" class="breadcrumb-link" onclick={() => view = 'records'}>{selectedCollection}</button>
        <span class="breadcrumb-sep">/</span>
        {#if view === 'record' && selectedRecord}
          <span class="breadcrumb-current">{selectedRecord.rkey}</span>
        {:else}
          <span class="breadcrumb-current">{$_('repoExplorer.newRecord')}</span>
        {/if}
      {:else if view === 'create'}
        <span class="breadcrumb-current">{$_('repoExplorer.newRecord')}</span>
      {/if}
    {/if}
  </nav>

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
    <div class="loading">{$_('common.loading')}</div>
  {:else if view === 'collections'}
    <div class="toolbar">
      <input
        type="text"
        placeholder={$_('repoExplorer.filterCollections')}
        bind:value={filter}
        class="filter-input"
      />
      <button type="button" class="sm" onclick={() => startCreate()}>{$_('repoExplorer.createRecord')}</button>
    </div>

    {#if collections.length === 0}
      <p class="empty">{$_('repoExplorer.noCollectionsYet')}</p>
    {:else}
      <div class="collections">
        {#each [...groupedCollections.entries()] as [authority, nsids]}
          <div class="collection-group">
            <h4 class="authority">{authority}</h4>
            <ul class="nsid-list">
              {#each nsids as nsid}
                <li>
                  <button type="button" class="collection-link" onclick={() => selectCollection(`${authority}.${nsid}`)}>
                    <span class="nsid">{nsid}</span>
                    <span class="arrow">→</span>
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
      <button type="button" class="sm" onclick={() => startCreate(selectedCollection!)}>{$_('repoExplorer.createRecord')}</button>
    </div>

    {#if records.length === 0}
      <p class="empty">{$_('repoExplorer.noRecords')}</p>
    {:else}
      <ul class="record-list">
        {#each filteredRecords as record}
          <li>
            <button type="button" class="record-item" onclick={() => selectRecord(record)}>
              <div class="record-info">
                <span class="rkey">{record.rkey}</span>
                <span class="cid" title={record.cid}>{record.cid.slice(0, 12)}...</span>
              </div>
              <pre class="record-preview">{JSON.stringify(record.value, null, 2).slice(0, 200)}{JSON.stringify(record.value).length > 200 ? '...' : ''}</pre>
            </button>
          </li>
        {/each}
      </ul>
      <LoadMoreSentinel hasMore={!!recordsCursor} loading={loadingMore} onLoadMore={loadMoreRecords} />
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
          <button type="submit" class="sm" disabled={saving || !!jsonError}>
            {saving ? $_('common.saving') : $_('repoExplorer.updateRecord')}
          </button>
          <button type="button" class="danger-outline sm" onclick={handleDelete} disabled={saving}>
            {$_('common.delete')}
          </button>
        </div>
      </form>
    </div>

  {:else if view === 'create'}
    <form class="create-form" onsubmit={handleCreate}>
      <div>
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
      <div>
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
        <button type="submit" class="sm" disabled={saving || !!jsonError || !newCollection.trim()}>
          {saving ? $_('common.creating') : $_('repoExplorer.createRecord')}
        </button>
        <button type="button" class="ghost sm" onclick={goBack}>
          {$_('common.cancel')}
        </button>
      </div>
    </form>
  {/if}
</div>
