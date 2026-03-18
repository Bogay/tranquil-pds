<script lang="ts">
  import { onMount } from 'svelte'
  import { _ } from '../../lib/i18n'
  import { api, ApiError } from '../../lib/api'
  import { toast } from '../../lib/toast.svelte'
  import type { Session } from '../../lib/types/api'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  interface VerificationMethod {
    id: string
    type: string
    controller: string
    publicKeyMultibase: string
  }

  let loading = $state(true)
  let saving = $state(false)
  let verificationMethods = $state<VerificationMethod[]>([])
  let alsoKnownAs = $state<string[]>([])
  let serviceEndpoint = $state('')
  let previewJson = $state('')

  let newKeyId = $state('#atproto')
  let newKeyValue = $state('')
  let newHandle = $state('')

  onMount(async () => {
    await loadDidDocument()
  })

  async function loadDidDocument() {
    loading = true
    try {
      const result = await api.getDidDocument(session.accessJwt)
      verificationMethods = result.verificationMethod || []
      alsoKnownAs = result.alsoKnownAs || []
      const pdsService = result.service?.find(s => s.type === 'AtprotoPersonalDataServer')
      serviceEndpoint = pdsService?.serviceEndpoint || ''
      updatePreview()
    } catch {
      toast.error($_('didEditor.loadFailed'))
    } finally {
      loading = false
    }
  }

  function updatePreview() {
    const doc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: session.did,
      alsoKnownAs,
      verificationMethod: verificationMethods.map(vm => ({
        id: vm.id.startsWith(session.did) ? vm.id : `${session.did}${vm.id}`,
        type: vm.type || 'Multikey',
        controller: vm.controller || session.did,
        publicKeyMultibase: vm.publicKeyMultibase
      })),
      service: serviceEndpoint ? [{
        id: '#atproto_pds',
        type: 'AtprotoPersonalDataServer',
        serviceEndpoint
      }] : []
    }
    previewJson = JSON.stringify(doc, null, 2)
  }

  function addVerificationMethod() {
    if (!newKeyId.trim() || !newKeyValue.trim()) return
    const trimmedValue = newKeyValue.trim()
    if (!trimmedValue.startsWith('z')) {
      toast.error($_('didEditor.invalidMultibase'))
      return
    }
    const id = newKeyId.startsWith('#') ? newKeyId : `#${newKeyId}`
    verificationMethods = [...verificationMethods, {
      id,
      type: 'Multikey',
      controller: session.did,
      publicKeyMultibase: trimmedValue
    }]
    newKeyId = '#atproto'
    newKeyValue = ''
    updatePreview()
  }

  function removeVerificationMethod(id: string) {
    verificationMethods = verificationMethods.filter(vm => vm.id !== id)
    updatePreview()
  }

  function addHandle() {
    if (!newHandle.trim()) return
    const handle = newHandle.startsWith('at://') ? newHandle : `at://${newHandle}`
    alsoKnownAs = [...alsoKnownAs, handle]
    newHandle = ''
    updatePreview()
  }

  function removeHandle(handle: string) {
    alsoKnownAs = alsoKnownAs.filter(h => h !== handle)
    updatePreview()
  }

  async function handleSave() {
    saving = true
    try {
      await api.updateDidDocument(session.accessJwt, {
        verificationMethods,
        alsoKnownAs,
        serviceEndpoint
      })
      toast.success($_('didEditor.success'))
      await loadDidDocument()
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('didEditor.saveFailed'))
    } finally {
      saving = false
    }
  }
</script>

<div class="did-editor">
  {#if loading}
    <div class="loading">{$_('common.loading')}</div>
  {:else}
    <section class="help-section">
      <h3>{$_('didEditor.helpTitle')}</h3>
      <p class="help-text">{$_('didEditor.helpText')}</p>
    </section>

    <section>
      <h3>{$_('didEditor.verificationMethods')}</h3>
      <p class="description">{$_('didEditor.verificationMethodsDesc')}</p>

      {#if verificationMethods.length === 0}
        <p class="empty">{$_('didEditor.noKeys')}</p>
      {:else}
        <ul class="list">
          {#each verificationMethods as vm}
            <li class="list-item">
              <div class="item-info">
                <div class="item-header">
                  <span class="item-id">{vm.id}</span>
                  <span class="item-type">{vm.type}</span>
                </div>
                <code class="item-key">{vm.publicKeyMultibase}</code>
              </div>
              <button type="button" class="sm danger-outline" onclick={() => removeVerificationMethod(vm.id)}>
                {$_('didEditor.removeKey')}
              </button>
            </li>
          {/each}
        </ul>
      {/if}

      <div class="add-form">
        <div class="field">
          <label for="key-id">{$_('didEditor.keyId')}</label>
          <input
            id="key-id"
            type="text"
            bind:value={newKeyId}
            placeholder={$_('didEditor.keyIdPlaceholder')}
          />
        </div>
        <div class="field">
          <label for="key-public">{$_('didEditor.publicKey')}</label>
          <input
            id="key-public"
            type="text"
            bind:value={newKeyValue}
            placeholder={$_('didEditor.publicKeyPlaceholder')}
          />
        </div>
        <button type="button" onclick={addVerificationMethod} disabled={!newKeyId.trim() || !newKeyValue.trim()}>
          {$_('didEditor.addKey')}
        </button>
      </div>
    </section>

    <section>
      <h3>{$_('didEditor.alsoKnownAs')}</h3>
      <p class="description">{$_('didEditor.alsoKnownAsDesc')}</p>

      {#if alsoKnownAs.length === 0}
        <p class="empty">{$_('didEditor.noHandles')}</p>
      {:else}
        <ul class="list">
          {#each alsoKnownAs as handle}
            <li class="list-item">
              <span class="item-handle">{handle}</span>
              <button type="button" class="sm danger-outline" onclick={() => removeHandle(handle)}>
                {$_('didEditor.removeHandle')}
              </button>
            </li>
          {/each}
        </ul>
      {/if}

      <div class="add-form single">
        <div class="field">
          <label for="new-handle">{$_('didEditor.handle')}</label>
          <input
            id="new-handle"
            type="text"
            bind:value={newHandle}
            placeholder={$_('didEditor.handlePlaceholder')}
          />
        </div>
        <button type="button" onclick={addHandle} disabled={!newHandle.trim()}>
          {$_('didEditor.addHandle')}
        </button>
      </div>
    </section>

    <section>
      <h3>{$_('didEditor.serviceEndpoint')}</h3>
      <p class="description">{$_('didEditor.serviceEndpointDesc')}</p>
      <div class="field">
        <label for="service-endpoint">{$_('didEditor.currentPds')}</label>
        <input
          id="service-endpoint"
          type="url"
          bind:value={serviceEndpoint}
          oninput={updatePreview}
          placeholder="https://pds.example.com"
        />
      </div>
    </section>

    <section class="preview-section">
      <h3>{$_('didEditor.preview')}</h3>
      <pre class="preview-json">{previewJson}</pre>
    </section>

    <div class="actions">
      <button onclick={handleSave} disabled={saving}>
        {saving ? $_('common.saving') : $_('didEditor.save')}
      </button>
    </div>
  {/if}
</div>
