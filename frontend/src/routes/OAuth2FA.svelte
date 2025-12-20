<script lang="ts">
  import { navigate } from '../lib/router.svelte'

  let code = $state('')
  let submitting = $state(false)
  let error = $state<string | null>(null)

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.hash.split('?')[1] || '')
    return params.get('request_uri')
  }

  function getChannel(): string {
    const params = new URLSearchParams(window.location.hash.split('?')[1] || '')
    return params.get('channel') || 'email'
  }

  async function handleSubmit(e: Event) {
    e.preventDefault()
    const requestUri = getRequestUri()
    if (!requestUri) {
      error = 'Missing request_uri parameter'
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
        error = data.error_description || data.error || 'Verification failed'
        submitting = false
        return
      }

      if (data.redirect_uri) {
        window.location.href = data.redirect_uri
        return
      }

      error = 'Unexpected response from server'
      submitting = false
    } catch {
      error = 'Failed to connect to server'
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

  let channel = $derived(getChannel())
</script>

<div class="oauth-2fa-container">
  <h1>Two-Factor Authentication</h1>
  <p class="subtitle">
    A verification code has been sent to your {channel}.
    Enter the code below to continue.
  </p>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <form onsubmit={handleSubmit}>
    <div class="field">
      <label for="code">Verification Code</label>
      <input
        id="code"
        type="text"
        bind:value={code}
        placeholder="Enter 6-digit code"
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
        Cancel
      </button>
      <button type="submit" class="submit-btn" disabled={submitting || code.trim().length !== 6}>
        {submitting ? 'Verifying...' : 'Verify'}
      </button>
    </div>
  </form>
</div>

<style>
  .oauth-2fa-container {
    max-width: 400px;
    margin: 4rem auto;
    padding: 2rem;
  }

  h1 {
    margin: 0 0 0.5rem 0;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0 0 2rem 0;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  label {
    font-size: 0.875rem;
    font-weight: 500;
  }

  input {
    padding: 0.75rem;
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    font-size: 1.5rem;
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
    padding: 0.75rem;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: 4px;
    color: var(--error-text);
    margin-bottom: 1rem;
  }

  .actions {
    display: flex;
    gap: 1rem;
    margin-top: 0.5rem;
  }

  .actions button {
    flex: 1;
    padding: 0.75rem;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    transition: background-color 0.15s;
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
    color: white;
  }

  .submit-btn:hover:not(:disabled) {
    background: var(--accent-hover);
  }
</style>
