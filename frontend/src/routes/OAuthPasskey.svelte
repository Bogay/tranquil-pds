<script lang="ts">
  import { navigate, routes } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'
  import {
    prepareRequestOptions,
    serializeAssertionResponse,
    type WebAuthnRequestOptionsResponse,
  } from '../lib/webauthn'

  let loading = $state(false)
  let error = $state<string | null>(null)
  let autoStarted = $state(false)

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('request_uri')
  }

  const t = $_

  async function startPasskeyAuth() {
    const requestUri = getRequestUri()
    if (!requestUri) {
      error = t('common.error')
      return
    }

    if (!window.PublicKeyCredential) {
      error = t('common.error')
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
        error = data.error_description || data.error || t('common.error')
        loading = false
        return
      }

      const { options } = await startResponse.json()
      const publicKeyOptions = prepareRequestOptions(options as WebAuthnRequestOptionsResponse)

      const credential = await navigator.credentials.get({
        publicKey: publicKeyOptions
      })

      if (!credential) {
        error = t('common.error')
        loading = false
        return
      }

      const credentialResponse = serializeAssertionResponse(credential as PublicKeyCredential)

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
        error = finishData.error_description || finishData.error || t('common.error')
        loading = false
        return
      }

      if (finishData.redirect_uri) {
        window.location.href = finishData.redirect_uri
        return
      }

      error = t('common.error')
      loading = false
    } catch (e) {
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        error = t('common.error')
      } else {
        error = t('common.error')
      }
      loading = false
    }
  }

  function handleCancel() {
    const requestUri = getRequestUri()
    if (requestUri) {
      navigate(routes.oauthLogin, { params: { request_uri: requestUri } })
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
  <h1>{t('oauth.passkey.title')}</h1>
  <p class="subtitle">
    {t('oauth.passkey.subtitle')}
  </p>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <div class="passkey-status">
    {#if loading}
      <div class="loading-indicator">
        <div class="spinner"></div>
        <p>{t('oauth.passkey.waiting')}</p>
      </div>
    {:else}
      <button type="button" class="passkey-btn" onclick={startPasskeyAuth} disabled={loading}>
        {t('oauth.passkey.title')}
      </button>
    {/if}
  </div>

  <div class="actions">
    <button type="button" class="cancel-btn" onclick={handleCancel} disabled={loading}>
      {t('common.cancel')}
    </button>
  </div>
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
</style>
