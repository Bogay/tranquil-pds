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

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <div class="passkey-status">
    {#if loading}
      <div class="loading-indicator">
        <p>{t('oauth.passkey.waiting')}</p>
      </div>
    {:else}
      <button type="button" style="width: 100%" onclick={startPasskeyAuth} disabled={loading}>
        {t('oauth.passkey.title')}
      </button>
    {/if}
  </div>

  <div class="actions">
    <button type="button" class="secondary" onclick={handleCancel} disabled={loading}>
      {t('common.cancel')}
    </button>
  </div>
</div>
