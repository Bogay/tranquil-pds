<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { api, ApiError } from '../lib/api'

  interface Props {
    show: boolean
    availableMethods?: string[]
    onSuccess: () => void
    onCancel: () => void
  }

  let { show = $bindable(), availableMethods = ['password'], onSuccess, onCancel }: Props = $props()

  const auth = getAuthState()
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

  function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer)
    let binary = ''
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  }

  function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
    const padded = base64 + '='.repeat((4 - base64.length % 4) % 4)
    const binary = atob(padded)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i)
    }
    return bytes.buffer
  }

  function prepareAuthOptions(options: any): PublicKeyCredentialRequestOptions {
    return {
      ...options.publicKey,
      challenge: base64UrlToArrayBuffer(options.publicKey.challenge),
      allowCredentials: options.publicKey.allowCredentials?.map((cred: any) => ({
        ...cred,
        id: base64UrlToArrayBuffer(cred.id)
      })) || []
    }
  }

  async function handlePasswordSubmit(e: Event) {
    e.preventDefault()
    if (!auth.session || !password) return
    loading = true
    error = ''
    try {
      await api.reauthPassword(auth.session.accessJwt, password)
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
    if (!auth.session || !totpCode) return
    loading = true
    error = ''
    try {
      await api.reauthTotp(auth.session.accessJwt, totpCode)
      show = false
      onSuccess()
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Invalid code'
    } finally {
      loading = false
    }
  }

  async function handlePasskeyAuth() {
    if (!auth.session) return
    if (!window.PublicKeyCredential) {
      error = 'Passkeys are not supported in this browser'
      return
    }
    loading = true
    error = ''
    try {
      const { options } = await api.reauthPasskeyStart(auth.session.accessJwt)
      const publicKeyOptions = prepareAuthOptions(options)
      const credential = await navigator.credentials.get({
        publicKey: publicKeyOptions
      })
      if (!credential) {
        error = 'Passkey authentication was cancelled'
        return
      }
      const pkCredential = credential as PublicKeyCredential
      const response = pkCredential.response as AuthenticatorAssertionResponse
      const credentialResponse = {
        id: pkCredential.id,
        type: pkCredential.type,
        rawId: arrayBufferToBase64Url(pkCredential.rawId),
        response: {
          clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
          authenticatorData: arrayBufferToBase64Url(response.authenticatorData),
          signature: arrayBufferToBase64Url(response.signature),
          userHandle: response.userHandle ? arrayBufferToBase64Url(response.userHandle) : null,
        },
      }
      await api.reauthPasskeyFinish(auth.session.accessJwt, credentialResponse)
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
  <div class="modal-backdrop" onclick={handleClose} role="presentation">
    <div class="modal" onclick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
      <div class="modal-header">
        <h2>Re-authentication Required</h2>
        <button class="close-btn" onclick={handleClose} aria-label="Close">&times;</button>
      </div>

      <p class="modal-description">
        This action requires you to verify your identity.
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
              Password
            </button>
          {/if}
          {#if availableMethods.includes('totp')}
            <button
              class="tab"
              class:active={activeMethod === 'totp'}
              onclick={() => activeMethod = 'totp'}
            >
              TOTP
            </button>
          {/if}
          {#if availableMethods.includes('passkey')}
            <button
              class="tab"
              class:active={activeMethod === 'passkey'}
              onclick={() => activeMethod = 'passkey'}
            >
              Passkey
            </button>
          {/if}
        </div>
      {/if}

      <div class="modal-content">
        {#if activeMethod === 'password'}
          <form onsubmit={handlePasswordSubmit}>
            <div class="form-group">
              <label for="reauth-password">Password</label>
              <input
                id="reauth-password"
                type="password"
                bind:value={password}
                required
                autocomplete="current-password"
              />
            </div>
            <button type="submit" class="btn-primary" disabled={loading || !password}>
              {loading ? 'Verifying...' : 'Verify'}
            </button>
          </form>
        {:else if activeMethod === 'totp'}
          <form onsubmit={handleTotpSubmit}>
            <div class="form-group">
              <label for="reauth-totp">Authenticator Code</label>
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
            <button type="submit" class="btn-primary" disabled={loading || !totpCode}>
              {loading ? 'Verifying...' : 'Verify'}
            </button>
          </form>
        {:else if activeMethod === 'passkey'}
          <div class="passkey-auth">
            <p>Click the button below to authenticate with your passkey.</p>
            <button
              class="btn-primary"
              onclick={handlePasskeyAuth}
              disabled={loading}
            >
              {loading ? 'Authenticating...' : 'Use Passkey'}
            </button>
          </div>
        {/if}
      </div>

      <div class="modal-footer">
        <button class="btn-secondary" onclick={handleClose} disabled={loading}>
          Cancel
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .modal {
    background: var(--bg-card);
    border-radius: 8px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
    max-width: 400px;
    width: 90%;
    max-height: 90vh;
    overflow-y: auto;
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--border-color);
  }

  .modal-header h2 {
    margin: 0;
    font-size: 1.25rem;
  }

  .close-btn {
    background: none;
    border: none;
    font-size: 1.5rem;
    cursor: pointer;
    color: var(--text-secondary);
    padding: 0;
    line-height: 1;
  }

  .close-btn:hover {
    color: var(--text-primary);
  }

  .modal-description {
    padding: 1rem 1.5rem 0;
    margin: 0;
    color: var(--text-secondary);
  }

  .error-message {
    margin: 1rem 1.5rem 0;
    padding: 0.75rem;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: 4px;
    color: var(--error-text);
    font-size: 0.875rem;
  }

  .method-tabs {
    display: flex;
    gap: 0.5rem;
    padding: 1rem 1.5rem 0;
  }

  .tab {
    flex: 1;
    padding: 0.5rem 1rem;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    cursor: pointer;
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .tab:hover {
    background: var(--bg-secondary);
  }

  .tab.active {
    background: var(--accent);
    border-color: var(--accent);
    color: white;
  }

  .modal-content {
    padding: 1.5rem;
  }

  .form-group {
    margin-bottom: 1rem;
  }

  .form-group label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 500;
  }

  .form-group input {
    width: 100%;
    padding: 0.75rem;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 1rem;
  }

  .form-group input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .passkey-auth {
    text-align: center;
  }

  .passkey-auth p {
    margin-bottom: 1rem;
    color: var(--text-secondary);
  }

  .btn-primary {
    width: 100%;
    padding: 0.75rem 1.5rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
  }

  .btn-primary:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .btn-primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .modal-footer {
    padding: 0 1.5rem 1.5rem;
    display: flex;
    justify-content: flex-end;
  }

  .btn-secondary {
    padding: 0.5rem 1rem;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 0.875rem;
  }

  .btn-secondary:hover:not(:disabled) {
    background: var(--bg-secondary);
  }

  .btn-secondary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
</style>
