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

      <p class="modal-description">
        {$_('reauth.subtitle')}
      </p>

      {#if error}
        <div class="error-message">{error}</div>
      {/if}

      {#if availableMethods.length > 1}
        <div class="method-tabs">
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
            <div class="field">
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
            <div class="field">
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
            <p>{$_('reauth.passkeyPrompt')}</p>
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

<style>
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: var(--z-modal);
  }

  .modal {
    background: var(--bg-card);
    border-radius: var(--radius-xl);
    box-shadow: var(--shadow-lg);
    max-width: var(--width-sm);
    width: 90%;
    max-height: 90vh;
    overflow-y: auto;
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-4) var(--space-6);
    border-bottom: 1px solid var(--border-color);
  }

  .modal-header h2 {
    margin: 0;
    font-size: var(--text-lg);
  }

  .close-btn {
    background: none;
    border: none;
    font-size: var(--text-xl);
    cursor: pointer;
    color: var(--text-secondary);
    padding: 0;
    line-height: 1;
  }

  .close-btn:hover {
    color: var(--text-primary);
  }

  .modal-description {
    padding: var(--space-4) var(--space-6) 0;
    margin: 0;
    color: var(--text-secondary);
  }

  .error-message {
    margin: var(--space-4) var(--space-6) 0;
    padding: var(--space-3);
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: var(--radius-md);
    color: var(--error-text);
    font-size: var(--text-sm);
  }

  .method-tabs {
    display: flex;
    gap: var(--space-2);
    padding: var(--space-4) var(--space-6) 0;
  }

  .tab {
    flex: 1;
    padding: var(--space-2) var(--space-4);
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    cursor: pointer;
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  .tab:hover {
    background: var(--bg-secondary);
  }

  .tab.active {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--text-inverse);
  }

  .modal-content {
    padding: var(--space-6);
  }

  .modal-content .field {
    margin-bottom: var(--space-4);
  }

  .passkey-auth {
    text-align: center;
  }

  .passkey-auth p {
    margin-bottom: var(--space-4);
    color: var(--text-secondary);
  }

  .modal-content button:not(.tab) {
    width: 100%;
  }

  .modal-footer {
    padding: 0 var(--space-6) var(--space-6);
    display: flex;
    justify-content: flex-end;
  }
</style>
