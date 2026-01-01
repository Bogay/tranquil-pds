<script lang="ts">
  import { navigate } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'

  let code = $state('')
  let trustDevice = $state(false)
  let submitting = $state(false)
  let error = $state<string | null>(null)

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.hash.split('?')[1] || '')
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
      navigate(`/oauth/login?request_uri=${encodeURIComponent(requestUri)}`)
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
  <p class="subtitle">
    {$_('oauth.totp.subtitle')}
  </p>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <form onsubmit={handleSubmit}>
    <div class="field">
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
      <p class="hint">
        {#if isBackupCode}
          {$_('oauth.totp.hintBackupCode')}
        {:else if isTotpCode}
          {$_('oauth.totp.hintTotpCode')}
        {:else}
          {$_('oauth.totp.hintDefault')}
        {/if}
      </p>
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
      <button type="button" class="cancel-btn" onclick={handleCancel} disabled={submitting}>
        {$_('common.cancel')}
      </button>
      <button type="submit" class="submit-btn" disabled={submitting || !canSubmit}>
        {submitting ? $_('common.verifying') : $_('common.verify')}
      </button>
    </div>
  </form>
</div>

<style>
  .oauth-totp-container {
    max-width: var(--width-sm);
    margin: var(--space-9) auto;
    padding: var(--space-7);
  }

  h1 {
    margin: 0 0 var(--space-2) 0;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0 0 var(--space-7) 0;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  label {
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
  }

  input {
    padding: var(--space-3);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-size: var(--text-xl);
    letter-spacing: 0.25em;
    text-align: center;
    background: var(--bg-input);
    color: var(--text-primary);
    text-transform: uppercase;
  }

  input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .hint {
    font-size: var(--text-xs);
    color: var(--text-muted);
    margin: var(--space-1) 0 0 0;
    text-align: center;
  }

  .error {
    padding: var(--space-3);
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: var(--radius-md);
    color: var(--error-text);
    margin-bottom: var(--space-4);
  }

  .actions {
    display: flex;
    gap: var(--space-4);
    margin-top: var(--space-2);
  }

  .actions button {
    flex: 1;
    padding: var(--space-3);
    border: none;
    border-radius: var(--radius-md);
    font-size: var(--text-base);
    cursor: pointer;
    transition: background-color var(--transition-fast);
  }

  .actions button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .cancel-btn {
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
  }

  .cancel-btn:hover:not(:disabled) {
    background: var(--error-bg);
    border-color: var(--error-border);
    color: var(--error-text);
  }

  .submit-btn {
    background: var(--accent);
    color: var(--text-inverse);
  }

  .submit-btn:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .trust-device-label {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    cursor: pointer;
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin-top: var(--space-2);
  }

  .trust-device-label input[type="checkbox"] {
    width: auto;
    margin: 0;
  }
</style>
