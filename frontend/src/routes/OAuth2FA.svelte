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
    <div class="field">
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
      <button type="button" class="cancel-btn" onclick={handleCancel} disabled={submitting}>
        {$_('common.cancel')}
      </button>
      <button type="submit" class="submit-btn" disabled={submitting || code.trim().length !== 6}>
        {submitting ? $_('common.verifying') : $_('common.verify')}
      </button>
    </div>
  </form>
</div>

<style>
  .oauth-2fa-container {
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
    letter-spacing: 0.5em;
    text-align: center;
    background: var(--bg-input);
    color: var(--text-primary);
  }

  input:focus {
    outline: none;
    border-color: var(--accent);
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
</style>
