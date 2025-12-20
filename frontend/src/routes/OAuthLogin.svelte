<script lang="ts">
  import { navigate } from '../lib/router.svelte'

  let username = $state('')
  let password = $state('')
  let rememberDevice = $state(false)
  let submitting = $state(false)
  let error = $state<string | null>(null)

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.hash.split('?')[1] || '')
    return params.get('request_uri')
  }

  function getErrorFromUrl(): string | null {
    const params = new URLSearchParams(window.location.hash.split('?')[1] || '')
    return params.get('error')
  }

  $effect(() => {
    const urlError = getErrorFromUrl()
    if (urlError) {
      error = urlError
    }
  })

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
      const response = await fetch('/oauth/authorize', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          request_uri: requestUri,
          username,
          password,
          remember_device: rememberDevice
        })
      })

      const data = await response.json()

      if (!response.ok) {
        error = data.error_description || data.error || 'Login failed'
        submitting = false
        return
      }

      if (data.needs_2fa) {
        navigate(`/oauth/2fa?request_uri=${encodeURIComponent(requestUri)}&channel=${encodeURIComponent(data.channel || '')}`)
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

  async function handleCancel() {
    const requestUri = getRequestUri()
    if (!requestUri) {
      window.history.back()
      return
    }

    submitting = true
    try {
      const response = await fetch('/oauth/authorize/deny', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ request_uri: requestUri })
      })

      const data = await response.json()
      if (data.redirect_uri) {
        window.location.href = data.redirect_uri
      }
    } catch {
      window.history.back()
    }
  }
</script>

<div class="oauth-login-container">
  <h1>Sign In</h1>
  <p class="subtitle">Sign in to continue to the application</p>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <form onsubmit={handleSubmit}>
    <div class="field">
      <label for="username">Handle or Email</label>
      <input
        id="username"
        type="text"
        bind:value={username}
        placeholder="you@example.com or handle"
        disabled={submitting}
        required
        autocomplete="username"
      />
    </div>

    <div class="field">
      <label for="password">Password</label>
      <input
        id="password"
        type="password"
        bind:value={password}
        disabled={submitting}
        required
        autocomplete="current-password"
      />
    </div>

    <label class="remember-device">
      <input type="checkbox" bind:checked={rememberDevice} disabled={submitting} />
      <span>Remember this device</span>
    </label>

    <div class="actions">
      <button type="button" class="cancel-btn" onclick={handleCancel} disabled={submitting}>
        Cancel
      </button>
      <button type="submit" class="submit-btn" disabled={submitting || !username || !password}>
        {submitting ? 'Signing in...' : 'Sign In'}
      </button>
    </div>
  </form>
</div>

<style>
  .oauth-login-container {
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

  input[type="text"],
  input[type="password"] {
    padding: 0.75rem;
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    font-size: 1rem;
    background: var(--bg-input);
    color: var(--text-primary);
  }

  input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .remember-device {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .remember-device input {
    width: 16px;
    height: 16px;
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
