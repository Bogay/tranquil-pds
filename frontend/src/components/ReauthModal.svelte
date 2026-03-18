<script lang="ts">
  import { getAuthState, getValidToken } from '../lib/auth.svelte'
  import { api, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import type { Session } from '../lib/types/api'
  import {
    prepareRequestOptions,
    serializeAssertionResponse,
    type WebAuthnRequestOptionsResponse,
  } from '../lib/webauthn'

  interface Props {
    show: boolean
    availableMethods?: string[]
    onSuccess: () => void
    onCancel: () => void
  }

  let { show = $bindable(), availableMethods = ['password'], onSuccess, onCancel }: Props = $props()

  const auth = $derived(getAuthState())

  function getSession(): Session | null {
    return auth.kind === 'authenticated' ? auth.session : null
  }

  const session = $derived(getSession())
  let activeMethod = $state<'password' | 'totp' | 'passkey'>('password')
  let password = $state('')
  let totpCode = $state('')
  let loading = $state(false)
  let error = $state('')

  $effect(() => {
    if (show) {
      password = ''
      totpCode = ''
      error = ''
      if (availableMethods.includes('password')) {
        activeMethod = 'password'
      } else if (availableMethods.includes('totp')) {
        activeMethod = 'totp'
      } else if (availableMethods.includes('passkey')) {
        activeMethod = 'passkey'
        if (availableMethods.length === 1) {
          handlePasskeyAuth()
        }
      }
    }
  })

  async function handlePasswordSubmit(e: Event) {
    e.preventDefault()
    if (!session || !password) return
    loading = true
    error = ''
    try {
      const token = await getValidToken()
      if (!token) {
        error = 'Session expired. Please log in again.'
        return
      }
      await api.reauthPassword(token, password)
      show = false
      onSuccess()
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Authentication failed'
    } finally {
      loading = false
    }
  }

  async function handleTotpSubmit(e: Event) {
    e.preventDefault()
    if (!session || !totpCode) return
    loading = true
    error = ''
    try {
      const token = await getValidToken()
      if (!token) {
        error = 'Session expired. Please log in again.'
        return
      }
      await api.reauthTotp(token, totpCode)
      show = false
      onSuccess()
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Invalid code'
    } finally {
      loading = false
    }
  }

  async function handlePasskeyAuth() {
    if (!session) return
    if (!window.PublicKeyCredential) {
      error = 'Passkeys are not supported in this browser'
      return
    }
    loading = true
    error = ''
    try {
      const token = await getValidToken()
      if (!token) {
        error = 'Session expired. Please log in again.'
        return
      }
      const { options } = await api.reauthPasskeyStart(token)
      const publicKeyOptions = prepareRequestOptions(options as unknown as WebAuthnRequestOptionsResponse)
      const credential = await navigator.credentials.get({
        publicKey: publicKeyOptions
      })
      if (!credential) {
        error = 'Passkey authentication was cancelled'
        return
      }
      const credentialResponse = serializeAssertionResponse(credential as PublicKeyCredential)
      await api.reauthPasskeyFinish(token, credentialResponse)
      show = false
      onSuccess()
    } catch (e) {
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        error = 'Passkey authentication was cancelled'
      } else {
        error = e instanceof ApiError ? e.message : 'Passkey authentication failed'
      }
    } finally {
      loading = false
    }
  }

  function handleClose() {
    show = false
    onCancel()
  }
</script>

{#if show}
  <div class="modal-backdrop" onclick={handleClose} onkeydown={(e) => e.key === 'Escape' && handleClose()} role="presentation">
    <div class="modal" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="dialog" aria-modal="true" tabindex="-1">
      <div class="modal-header">
        <h2>{$_('reauth.title')}</h2>
        <button class="close-btn" onclick={handleClose} aria-label="Close">&times;</button>
      </div>

      {#if error}
        <div class="error-message">{error}</div>
      {/if}

      {#if availableMethods.length > 1}
        <div class="tabs">
          {#if availableMethods.includes('password')}
            <button
              class="tab"
              class:active={activeMethod === 'password'}
              onclick={() => activeMethod = 'password'}
            >
              {$_('reauth.password')}
            </button>
          {/if}
          {#if availableMethods.includes('totp')}
            <button
              class="tab"
              class:active={activeMethod === 'totp'}
              onclick={() => activeMethod = 'totp'}
            >
              {$_('reauth.totp')}
            </button>
          {/if}
          {#if availableMethods.includes('passkey')}
            <button
              class="tab"
              class:active={activeMethod === 'passkey'}
              onclick={() => activeMethod = 'passkey'}
            >
              {$_('reauth.passkey')}
            </button>
          {/if}
        </div>
      {/if}

      <div class="modal-content">
        {#if activeMethod === 'password'}
          <form onsubmit={handlePasswordSubmit}>
            <div>
              <label for="reauth-password">{$_('reauth.password')}</label>
              <input
                id="reauth-password"
                type="password"
                bind:value={password}
                required
                autocomplete="current-password"
              />
            </div>
            <button type="submit" disabled={loading || !password}>
              {loading ? $_('common.verifying') : $_('common.verify')}
            </button>
          </form>
        {:else if activeMethod === 'totp'}
          <form onsubmit={handleTotpSubmit}>
            <div>
              <label for="reauth-totp">{$_('reauth.authenticatorCode')}</label>
              <input
                id="reauth-totp"
                type="text"
                bind:value={totpCode}
                required
                autocomplete="one-time-code"
                inputmode="numeric"
                pattern="[0-9]*"
                maxlength="6"
              />
            </div>
            <button type="submit" disabled={loading || !totpCode}>
              {loading ? $_('common.verifying') : $_('common.verify')}
            </button>
          </form>
        {:else if activeMethod === 'passkey'}
          <div class="passkey-auth">
            <button onclick={handlePasskeyAuth} disabled={loading}>
              {loading ? $_('reauth.authenticating') : $_('reauth.usePasskey')}
            </button>
          </div>
        {/if}
      </div>

      <div class="modal-footer">
        <button class="secondary" onclick={handleClose} disabled={loading}>
          {$_('reauth.cancel')}
        </button>
      </div>
    </div>
  </div>
{/if}
