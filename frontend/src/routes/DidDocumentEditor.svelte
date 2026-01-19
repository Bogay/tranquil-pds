<script lang="ts">
  import { onMount } from 'svelte'
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { api, ApiError, type VerificationMethod, type DidDocument } from '../lib/api'
  import { _ } from '../lib/i18n'
  import type { Session } from '../lib/types/api'
  import { toast } from '../lib/toast.svelte'

  const auth = $derived(getAuthState())

  function getSession(): Session | null {
    return auth.kind === 'authenticated' ? auth.session : null
  }

  function isLoading(): boolean {
    return auth.kind === 'loading'
  }

  const session = $derived(getSession())
  const authLoading = $derived(isLoading())

  let loading = $state(true)
  let saving = $state(false)
  let didDocument = $state<DidDocument | null>(null)
  let verificationMethods = $state<VerificationMethod[]>([])
  let alsoKnownAs = $state<string[]>([])
  let serviceEndpoint = $state('')
  let newKeyId = $state('#atproto')
  let newKeyPublic = $state('')
  let newHandle = $state('')

  $effect(() => {
    if (!authLoading && !session) {
      navigate(routes.login)
    }
  })

  onMount(async () => {
    if (!session) return
    try {
      didDocument = await api.getDidDocument(session.accessJwt)
      verificationMethods = didDocument.verificationMethod.map(vm => ({
        id: vm.id.replace(didDocument!.id, ''),
        type: vm.type,
        publicKeyMultibase: vm.publicKeyMultibase
      }))
      alsoKnownAs = [...didDocument.alsoKnownAs]
      const pdsService = didDocument.service.find(s => s.id === '#atproto_pds')
      serviceEndpoint = pdsService?.serviceEndpoint || ''
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('didEditor.loadFailed'))
    } finally {
      loading = false
    }
  })

  function addVerificationMethod() {
    if (!newKeyId || !newKeyPublic) return
    if (!newKeyPublic.startsWith('z')) {
      toast.error($_('didEditor.invalidMultibase'))
      return
    }
    verificationMethods = [...verificationMethods, {
      id: newKeyId.startsWith('#') ? newKeyId : `#${newKeyId}`,
      type: 'Multikey',
      publicKeyMultibase: newKeyPublic
    }]
    newKeyId = '#atproto'
    newKeyPublic = ''
  }

  function removeVerificationMethod(index: number) {
    verificationMethods = verificationMethods.filter((_, i) => i !== index)
  }

  function addHandle() {
    if (!newHandle) return
    if (!newHandle.startsWith('at://')) {
      toast.error($_('didEditor.invalidHandle'))
      return
    }
    alsoKnownAs = [...alsoKnownAs, newHandle]
    newHandle = ''
  }

  function removeHandle(index: number) {
    alsoKnownAs = alsoKnownAs.filter((_, i) => i !== index)
  }

  async function handleSave() {
    if (!session) return
    saving = true
    try {
      await api.updateDidDocument(session.accessJwt, {
        verificationMethods: verificationMethods.length > 0 ? verificationMethods : undefined,
        alsoKnownAs: alsoKnownAs.length > 0 ? alsoKnownAs : undefined,
        serviceEndpoint: serviceEndpoint || undefined
      })
      toast.success($_('didEditor.success'))
      didDocument = await api.getDidDocument(session.accessJwt)
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('didEditor.saveFailed'))
    } finally {
      saving = false
    }
  }
</script>

<div class="page">
  <header>
    <a href="/app/dashboard" class="back">{$_('common.backToDashboard')}</a>
    <h1>{$_('didEditor.title')}</h1>
  </header>

  {#if loading}
    <div class="skeleton-sections">
      <div class="skeleton-section small"></div>
      <div class="skeleton-section large"></div>
      <div class="skeleton-section"></div>
      <div class="skeleton-section"></div>
    </div>
  {:else}
    <div class="help-section">
      <h3>{$_('didEditor.helpTitle')}</h3>
      <p>{$_('didEditor.helpText')}</p>
    </div>

    <section>
      <h2>{$_('didEditor.preview')}</h2>
      <pre class="did-preview">{JSON.stringify(didDocument, null, 2)}</pre>
    </section>

    <section>
      <h2>{$_('didEditor.verificationMethods')}</h2>
      <p class="description">{$_('didEditor.verificationMethodsDesc')}</p>

      {#if verificationMethods.length > 0}
        <ul class="key-list">
          {#each verificationMethods as method, index}
            <li class="key-item">
              <div class="key-info">
                <span class="key-id">{method.id}</span>
                <span class="key-type">{method.type}</span>
                <code class="key-value">{method.publicKeyMultibase}</code>
              </div>
              <button type="button" class="danger-link" onclick={() => removeVerificationMethod(index)}>
                {$_('didEditor.removeKey')}
              </button>
            </li>
          {/each}
        </ul>
      {:else}
        <p class="empty-state">{$_('didEditor.noKeys')}</p>
      {/if}

      <div class="add-form">
        <h4>{$_('didEditor.addKey')}</h4>
        <div class="field-row">
          <div class="field small">
            <label for="key-id">{$_('didEditor.keyId')}</label>
            <input
              id="key-id"
              type="text"
              bind:value={newKeyId}
              placeholder={$_('didEditor.keyIdPlaceholder')}
            />
          </div>
          <div class="field large">
            <label for="key-public">{$_('didEditor.publicKey')}</label>
            <input
              id="key-public"
              type="text"
              bind:value={newKeyPublic}
              placeholder={$_('didEditor.publicKeyPlaceholder')}
            />
          </div>
          <button type="button" class="add-btn" onclick={addVerificationMethod} disabled={!newKeyId || !newKeyPublic}>
            {$_('didEditor.addKey')}
          </button>
        </div>
      </div>
    </section>

    <section>
      <h2>{$_('didEditor.alsoKnownAs')}</h2>
      <p class="description">{$_('didEditor.alsoKnownAsDesc')}</p>

      {#if alsoKnownAs.length > 0}
        <ul class="handle-list">
          {#each alsoKnownAs as handle, index}
            <li class="handle-item">
              <span>{handle}</span>
              <button type="button" class="danger-link" onclick={() => removeHandle(index)}>
                {$_('didEditor.removeHandle')}
              </button>
            </li>
          {/each}
        </ul>
      {:else}
        <p class="empty-state">{$_('didEditor.noHandles')}</p>
      {/if}

      <div class="add-form">
        <div class="field-row">
          <div class="field large">
            <label for="new-handle">{$_('didEditor.handle')}</label>
            <input
              id="new-handle"
              type="text"
              bind:value={newHandle}
              placeholder={$_('didEditor.handlePlaceholder')}
            />
          </div>
          <button type="button" class="add-btn" onclick={addHandle} disabled={!newHandle}>
            {$_('didEditor.addHandle')}
          </button>
        </div>
      </div>
    </section>

    <section>
      <h2>{$_('didEditor.serviceEndpoint')}</h2>
      <p class="description">{$_('didEditor.serviceEndpointDesc')}</p>
      <div class="field">
        <label for="service-endpoint">{$_('didEditor.currentPds')}</label>
        <input
          id="service-endpoint"
          type="url"
          bind:value={serviceEndpoint}
          placeholder="https://pds.example.com"
        />
      </div>
    </section>

    <div class="actions">
      <button onclick={handleSave} disabled={saving}>
        {saving ? $_('common.saving') : $_('common.save')}
      </button>
    </div>
  {/if}
</div>

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

  .help-section {
    background: var(--info-bg, #e0f2fe);
    border: 1px solid var(--info-border, #7dd3fc);
    border-radius: var(--radius-xl);
    padding: var(--space-5) var(--space-6);
    margin-bottom: var(--space-6);
  }

  .help-section h3 {
    margin: 0 0 var(--space-2) 0;
    color: var(--info-text, #0369a1);
    font-size: var(--text-base);
  }

  .help-section p {
    margin: 0;
    color: var(--info-text, #0369a1);
    font-size: var(--text-sm);
  }

  section {
    padding: var(--space-6);
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-6);
  }

  section h2 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-lg);
  }

  .description {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin-bottom: var(--space-4);
  }

  .did-preview {
    background: var(--bg-input);
    padding: var(--space-4);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 300px;
    overflow-y: auto;
  }

  .key-list, .handle-list {
    list-style: none;
    padding: 0;
    margin: 0 0 var(--space-4) 0;
  }

  .key-item, .handle-item {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    padding: var(--space-3) var(--space-4);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-2);
    gap: var(--space-4);
  }

  .key-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    flex: 1;
    min-width: 0;
  }

  .key-id {
    font-weight: var(--font-medium);
    font-size: var(--text-sm);
  }

  .key-type {
    color: var(--text-secondary);
    font-size: var(--text-xs);
  }

  .key-value {
    font-size: var(--text-xs);
    background: var(--bg-input);
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-sm);
    word-break: break-all;
  }

  .handle-item span {
    font-family: var(--font-mono);
    font-size: var(--text-sm);
  }

  .danger-link {
    background: none;
    border: none;
    color: var(--error-text);
    cursor: pointer;
    font-size: var(--text-xs);
    padding: var(--space-1) var(--space-2);
    white-space: nowrap;
  }

  .danger-link:hover {
    text-decoration: underline;
  }

  .empty-state {
    color: var(--text-muted);
    font-size: var(--text-sm);
    font-style: italic;
    padding: var(--space-4);
    text-align: center;
    background: var(--bg-card);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-4);
  }

  .add-form {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
  }

  .add-form h4 {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .field-row {
    display: flex;
    gap: var(--space-3);
    align-items: flex-end;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .field.small {
    flex: 0 0 120px;
  }

  .field.large {
    flex: 1;
  }

  .field label {
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .add-btn {
    white-space: nowrap;
  }

  .actions {
    display: flex;
    gap: var(--space-3);
    justify-content: flex-end;
    margin-top: var(--space-6);
  }

  @media (max-width: 600px) {
    .field-row {
      flex-direction: column;
      align-items: stretch;
    }

    .field.small, .field.large {
      flex: none;
    }

    .add-btn {
      width: 100%;
    }
  }

  .skeleton-sections {
    display: flex;
    flex-direction: column;
    gap: var(--space-6);
  }

  .skeleton-section {
    height: 180px;
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
    animation: skeleton-pulse 1.5s ease-in-out infinite;
  }

  .skeleton-section.small {
    height: 80px;
  }

  .skeleton-section.large {
    height: 250px;
  }

</style>
