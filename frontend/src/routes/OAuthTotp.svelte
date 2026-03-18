<script lang="ts">
  import { navigate, routes } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'

  let code = $state('')
  let trustDevice = $state(false)
  let submitting = $state(false)
  let error = $state<string | null>(null)

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('request_uri')
  }

  async function handleSubmit(e: Event) {
    e.preventDefault()
    const requestUri = getRequestUri()
    if (!requestUri) {
      error = $_('common.error')
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
          code: code.trim().toUpperCase(),
          trust_device: trustDevice
        })
      })

      const data = await response.json()

      if (!response.ok) {
        error = data.error_description || data.error || $_('common.error')
        submitting = false
        return
      }

      if (data.redirect_uri) {
        window.location.href = data.redirect_uri
        return
      }

      error = $_('common.error')
      submitting = false
    } catch {
      error = $_('common.error')
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

  let isBackupCode = $derived(code.trim().length === 8 && /^[A-Z0-9]+$/i.test(code.trim()))
  let isTotpCode = $derived(code.trim().length === 6 && /^[0-9]+$/.test(code.trim()))
  let canSubmit = $derived(isBackupCode || isTotpCode)
</script>

<div class="oauth-totp-container">
  <h1>{$_('oauth.totp.title')}</h1>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <form onsubmit={handleSubmit}>
    <div>
      <label for="code">{$_('oauth.totp.codePlaceholder')}</label>
      <input
        id="code"
        type="text"
        bind:value={code}
        placeholder={isBackupCode ? $_('oauth.totp.backupCodePlaceholder') : $_('oauth.totp.codePlaceholder')}
        disabled={submitting}
        required
        maxlength="8"
        autocomplete="one-time-code"
        autocapitalize="characters"
      />
      {#if isBackupCode || isTotpCode}
        <p class="hint">
          {isBackupCode ? $_('oauth.totp.hintBackupCode') : $_('oauth.totp.hintTotpCode')}
        </p>
      {/if}
    </div>

    <label class="trust-device-label">
      <input
        type="checkbox"
        bind:checked={trustDevice}
        disabled={submitting}
      />
      <span>{$_('oauth.totp.trustDevice')}</span>
    </label>

    <div class="actions">
      <button type="button" class="cancel" onclick={handleCancel} disabled={submitting}>
        {$_('common.cancel')}
      </button>
      <button type="submit" disabled={submitting || !canSubmit}>
        {submitting ? $_('common.verifying') : $_('common.verify')}
      </button>
    </div>
  </form>
</div>
