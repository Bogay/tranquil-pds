<script lang="ts">
  import { navigate } from '../lib/router.svelte'

  let loading = $state(false)
  let error = $state<string | null>(null)
  let autoStarted = $state(false)

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.hash.split('?')[1] || '')
    return params.get('request_uri')
  }

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

  async function startPasskeyAuth() {
    const requestUri = getRequestUri()
    if (!requestUri) {
      error = 'Missing request_uri parameter'
      return
    }

    if (!window.PublicKeyCredential) {
      error = 'Passkeys are not supported in this browser'
      return
    }

    loading = true
    error = null

    try {
      const startResponse = await fetch(`/oauth/authorize/passkey?request_uri=${encodeURIComponent(requestUri)}`, {
        method: 'GET',
        headers: {
          'Accept': 'application/json'
        }
      })

      if (!startResponse.ok) {
        const data = await startResponse.json()
        error = data.error_description || data.error || 'Failed to start passkey authentication'
        loading = false
        return
      }

      const { options } = await startResponse.json()
      const publicKeyOptions = prepareAuthOptions(options)

      const credential = await navigator.credentials.get({
        publicKey: publicKeyOptions
      })

      if (!credential) {
        error = 'Passkey authentication was cancelled'
        loading = false
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

      const finishResponse = await fetch('/oauth/authorize/passkey', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          request_uri: requestUri,
          credential: credentialResponse
        })
      })

      const finishData = await finishResponse.json()

      if (!finishResponse.ok) {
        error = finishData.error_description || finishData.error || 'Passkey verification failed'
        loading = false
        return
      }

      if (finishData.redirect_uri) {
        window.location.href = finishData.redirect_uri
        return
      }

      error = 'Unexpected response from server'
      loading = false
    } catch (e) {
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        error = 'Passkey authentication was cancelled'
      } else {
        error = 'Failed to authenticate with passkey'
      }
      loading = false
    }
  }

  function handleCancel() {
    const requestUri = getRequestUri()
    if (requestUri) {
      navigate(`/oauth/login?request_uri=${encodeURIComponent(requestUri)}`)
    } else {
      window.history.back()
    }
  }

  $effect(() => {
    if (!autoStarted) {
      autoStarted = true
      startPasskeyAuth()
    }
  })
</script>

<div class="oauth-passkey-container">
  <h1>Sign In with Passkey</h1>
  <p class="subtitle">
    Your account uses a passkey for authentication. Use your fingerprint, face, or security key to sign in.
  </p>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <div class="passkey-status">
    {#if loading}
      <div class="loading-indicator">
        <div class="spinner"></div>
        <p>Waiting for passkey...</p>
      </div>
    {:else}
      <button type="button" class="passkey-btn" onclick={startPasskeyAuth} disabled={loading}>
        Use Passkey
      </button>
    {/if}
  </div>

  <div class="actions">
    <button type="button" class="cancel-btn" onclick={handleCancel} disabled={loading}>
      Cancel
    </button>
  </div>

  <p class="help-text">
    If you've lost access to your passkey, you can recover your account using email.
  </p>
</div>

<style>
  .oauth-passkey-container {
    max-width: 400px;
    margin: 4rem auto;
    padding: 2rem;
    text-align: center;
  }

  h1 {
    margin: 0 0 0.5rem 0;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0 0 2rem 0;
  }

  .error {
    padding: 0.75rem;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: 4px;
    color: var(--error-text);
    margin-bottom: 1.5rem;
    text-align: left;
  }

  .passkey-status {
    padding: 2rem;
    background: var(--bg-secondary);
    border-radius: 8px;
    margin-bottom: 1.5rem;
  }

  .loading-indicator {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
  }

  .spinner {
    width: 40px;
    height: 40px;
    border: 3px solid var(--border-color);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .loading-indicator p {
    margin: 0;
    color: var(--text-secondary);
  }

  .passkey-btn {
    width: 100%;
    padding: 1rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    transition: background-color 0.15s;
  }

  .passkey-btn:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .passkey-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .actions {
    display: flex;
    justify-content: center;
    margin-bottom: 1.5rem;
  }

  .cancel-btn {
    padding: 0.75rem 2rem;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    transition: background-color 0.15s;
  }

  .cancel-btn:hover:not(:disabled) {
    background: var(--error-bg);
    border-color: var(--error-border);
    color: var(--error-text);
  }

  .cancel-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .help-text {
    font-size: 0.875rem;
    color: var(--text-muted);
    margin: 0;
  }
</style>
