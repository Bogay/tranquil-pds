<script lang="ts">
  import { navigate, routes } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'

  let code = $state('')
  let submitting = $state(false)
  let error = $state<string | null>(null)

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('request_uri')
  }

  function getChannel(): string {
    const params = new URLSearchParams(window.location.search)
    return params.get('channel') || 'email'
  }

  async function handleSubmit(e: Event) {
    e.preventDefault()
    const requestUri = getRequestUri()
    if (!requestUri) {
      error = $_('oauth.twoFactorCode.errors.missingRequestUri')
      return
    }

    submitting = true
    error = null

    try {
      const response = await fetch('/oauth/authorize/2fa', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          request_uri: requestUri,
          code: code.trim()
        })
      })

      const data = await response.json()

      if (!response.ok) {
        error = data.error_description || data.error || $_('oauth.twoFactorCode.errors.verificationFailed')
        submitting = false
        return
      }

      if (data.redirect_uri) {
        window.location.href = data.redirect_uri
        return
      }

      error = $_('oauth.twoFactorCode.errors.unexpectedResponse')
      submitting = false
    } catch {
      error = $_('oauth.twoFactorCode.errors.connectionFailed')
      submitting = false
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

  let channel = $derived(getChannel())
</script>

<div class="oauth-2fa-container">
  <h1>{$_('oauth.twoFactorCode.title')}</h1>
  <p class="subtitle">
    {$_('oauth.twoFactorCode.subtitle', { values: { channel } })}
  </p>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <form onsubmit={handleSubmit}>
    <div>
      <label for="code">{$_('oauth.twoFactorCode.codeLabel')}</label>
      <input
        id="code"
        type="text"
        bind:value={code}
        placeholder={$_('oauth.twoFactorCode.codePlaceholder')}
        disabled={submitting}
        required
        maxlength="6"
        pattern="[0-9]{6}"
        autocomplete="one-time-code"
        inputmode="numeric"
      />
    </div>

    <div class="actions">
      <button type="button" class="cancel" onclick={handleCancel} disabled={submitting}>
        {$_('common.cancel')}
      </button>
      <button type="submit" disabled={submitting || code.trim().length !== 6}>
        {submitting ? $_('common.verifying') : $_('common.verify')}
      </button>
    </div>
  </form>
</div>
