<script lang="ts">
  import { onMount } from 'svelte'
  import { api, ApiError } from '../../lib/api'
  import { _ } from '../../lib/i18n'
  import { formatDate } from '../../lib/date'
  import { toast } from '../../lib/toast.svelte'
  import type { Session } from '../../lib/types/api'
  import {
    prepareCreationOptions,
    serializeAttestationResponse,
    type WebAuthnCreationOptionsResponse,
  } from '../../lib/webauthn'

  interface Props {
    session: Session
    hasPassword: boolean
    onPasskeysChanged?: (count: number) => void
  }

  let { session, hasPassword, onPasskeysChanged }: Props = $props()

  interface Passkey {
    id: string
    credentialId: string
    friendlyName: string | null
    createdAt: string
    lastUsed: string | null
  }

  let passkeys = $state<Passkey[]>([])
  let loading = $state(true)
  let addingPasskey = $state(false)
  let newPasskeyName = $state('')
  let editingPasskeyId = $state<string | null>(null)
  let editPasskeyName = $state('')

  onMount(async () => {
    await loadPasskeys()
  })

  async function loadPasskeys() {
    loading = true
    try {
      const result = await api.listPasskeys(session.accessJwt)
      passkeys = result.passkeys
      onPasskeysChanged?.(passkeys.length)
    } catch {
      toast.error($_('security.failedToLoadPasskeys'))
    } finally {
      loading = false
    }
  }

  async function handleAddPasskey() {
    if (!window.PublicKeyCredential) {
      toast.error($_('security.passkeysNotSupported'))
      return
    }
    addingPasskey = true
    try {
      const { options } = await api.startPasskeyRegistration(session.accessJwt, newPasskeyName || undefined)
      const publicKeyOptions = prepareCreationOptions(options as unknown as WebAuthnCreationOptionsResponse)
      const credential = await navigator.credentials.create({ publicKey: publicKeyOptions })
      if (!credential) {
        toast.error($_('security.passkeyCreationCancelled'))
        return
      }
      const credentialResponse = serializeAttestationResponse(credential as PublicKeyCredential)
      await api.finishPasskeyRegistration(session.accessJwt, credentialResponse, newPasskeyName || undefined)
      await loadPasskeys()
      newPasskeyName = ''
      toast.success($_('security.passkeyAddedSuccess'))
    } catch (e) {
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        toast.error($_('security.passkeyCreationCancelled'))
      } else {
        toast.error(e instanceof ApiError ? e.message : 'Failed to add passkey')
      }
    } finally {
      addingPasskey = false
    }
  }

  async function handleDeletePasskey(id: string) {
    const passkey = passkeys.find(p => p.id === id)
    if (!confirm($_('security.deletePasskeyConfirm', { values: { name: passkey?.friendlyName || 'this passkey' } }))) return
    try {
      await api.deletePasskey(session.accessJwt, id)
      await loadPasskeys()
      toast.success($_('security.passkeyDeleted'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to delete passkey')
    }
  }

  async function handleSavePasskeyName() {
    if (!editingPasskeyId || !editPasskeyName.trim()) return
    try {
      await api.updatePasskey(session.accessJwt, editingPasskeyId, editPasskeyName.trim())
      await loadPasskeys()
      editingPasskeyId = null
      editPasskeyName = ''
      toast.success($_('security.passkeyRenamed'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to rename passkey')
    }
  }

  function startEditPasskey(passkey: Passkey) {
    editingPasskeyId = passkey.id
    editPasskeyName = passkey.friendlyName || ''
  }

  function cancelEditPasskey() {
    editingPasskeyId = null
    editPasskeyName = ''
  }
</script>

<section>
  <h3>{$_('security.passkeys')}</h3>

  {#if !loading}
    {#if passkeys.length > 0}
      <ul class="passkey-list">
        {#each passkeys as passkey}
          <li class="passkey-item">
            {#if editingPasskeyId === passkey.id}
              <div class="passkey-edit">
                <input type="text" bind:value={editPasskeyName} placeholder={$_('security.passkeyName')} />
                <button type="button" class="sm" onclick={handleSavePasskeyName}>{$_('common.save')}</button>
                <button type="button" class="sm secondary" onclick={cancelEditPasskey}>{$_('common.cancel')}</button>
              </div>
            {:else}
              <div class="passkey-info">
                <span class="passkey-name">{passkey.friendlyName || $_('security.unnamedPasskey')}</span>
                <span class="passkey-meta">
                  {$_('security.added')} {formatDate(passkey.createdAt)}
                  {#if passkey.lastUsed}
                    - {$_('security.lastUsed')} {formatDate(passkey.lastUsed)}
                  {/if}
                </span>
              </div>
              <div class="passkey-actions">
                <button type="button" class="sm secondary" onclick={() => startEditPasskey(passkey)}>{$_('security.rename')}</button>
                {#if hasPassword || passkeys.length > 1}
                  <button type="button" class="sm danger-outline" onclick={() => handleDeletePasskey(passkey.id)}>{$_('security.deletePasskey')}</button>
                {/if}
              </div>
            {/if}
          </li>
        {/each}
      </ul>
    {:else}
      <div class="status warning">{$_('security.noPasskeys')}</div>
    {/if}

    <div class="add-passkey">
      <input type="text" bind:value={newPasskeyName} placeholder={$_('security.passkeyNamePlaceholder')} disabled={addingPasskey} />
      <button onclick={handleAddPasskey} disabled={addingPasskey}>
        {addingPasskey ? $_('security.adding') : $_('security.addPasskey')}
      </button>
    </div>

  {/if}
</section>
