<script lang="ts">
  import { navigate, routes } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'

  import { getCurrentPath } from '../lib/router.svelte'

  let mode = $derived(getCurrentPath().includes('totp') ? 'totp' as const : '2fa' as const)

  let code = $state('')
  let trustDevice = $state(false)
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

  let isBackupCode = $derived(mode === 'totp' && code.trim().length === 8 && /^[A-Z0-9]+$/i.test(code.trim()))
  let isTotpCode = $derived(mode === 'totp' && code.trim().length === 6 && /^[0-9]+$/.test(code.trim()))
  let is2faCode = $derived(mode === '2fa' && code.trim().length === 6)
  let canSubmit = $derived(isBackupCode || isTotpCode || is2faCode)

  async function handleSubmit(e: Event) {
    e.preventDefault()
    const requestUri = getRequestUri()
    if (!requestUri) {
      error = mode === 'totp' ? $_('common.error') : $_('oauth.twoFactorCode.errors.missingRequestUri')
      return
    }

    submitting = true
    error = null

    try {
      const body: Record<string, unknown> = {
        request_uri: requestUri,
        code: mode === 'totp' ? code.trim().toUpperCase() : code.trim(),
      }
      if (mode === 'totp') {
        body.trust_device = trustDevice
      }

      const response = await fetch('/oauth/authorize/2fa', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(body)
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

      error = mode === '2fa' ? $_('oauth.twoFactorCode.errors.unexpectedResponse') : $_('common.error')
      submitting = false
    } catch {
      error = mode === '2fa' ? $_('oauth.twoFactorCode.errors.connectionFailed') : $_('common.error')
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

<div class={mode === 'totp' ? 'oauth-totp-container' : 'oauth-2fa-container'}>
  <h1>{mode === 'totp' ? $_('oauth.totp.title') : $_('oauth.twoFactorCode.title')}</h1>
  {#if mode === '2fa'}
    <p class="subtitle">
      {$_('oauth.twoFactorCode.subtitle', { values: { channel } })}
    </p>
  {/if}

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <form onsubmit={handleSubmit}>
    <div>
      <label for="code">
        {mode === 'totp' ? $_('oauth.totp.codePlaceholder') : $_('oauth.twoFactorCode.codeLabel')}
      </label>
      {#if mode === 'totp'}
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
      {:else}
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
      {/if}
    </div>

    {#if mode === 'totp'}
      <label class="trust-device-label">
        <input
          type="checkbox"
          bind:checked={trustDevice}
          disabled={submitting}
        />
        <span>{$_('oauth.totp.trustDevice')}</span>
      </label>
    {/if}

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
