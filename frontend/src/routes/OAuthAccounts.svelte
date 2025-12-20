<script lang="ts">
  import { navigate } from '../lib/router.svelte'

  interface AccountInfo {
    did: string
    handle: string
    email: string
  }

  let loading = $state(true)
  let error = $state<string | null>(null)
  let submitting = $state(false)
  let accounts = $state<AccountInfo[]>([])

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.hash.split('?')[1] || '')
    return params.get('request_uri')
  }

  async function fetchAccounts() {
    const requestUri = getRequestUri()
    if (!requestUri) {
      error = 'Missing request_uri parameter'
      loading = false
      return
    }

    try {
      const response = await fetch(`/oauth/authorize/accounts?request_uri=${encodeURIComponent(requestUri)}`)
      if (!response.ok) {
        const data = await response.json()
        error = data.error_description || data.error || 'Failed to load accounts'
        loading = false
        return
      }
      const data = await response.json()
      accounts = data.accounts || []
    } catch {
      error = 'Failed to connect to server'
    } finally {
      loading = false
    }
  }

  async function handleSelectAccount(did: string) {
    const requestUri = getRequestUri()
    if (!requestUri) {
      error = 'Missing request_uri parameter'
      return
    }

    submitting = true
    error = null

    try {
      const response = await fetch('/oauth/authorize/select', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          request_uri: requestUri,
          did
        })
      })

      const data = await response.json()

      if (!response.ok) {
        error = data.error_description || data.error || 'Selection failed'
        submitting = false
        return
      }

      if (data.needs_totp) {
        navigate(`/oauth/totp?request_uri=${encodeURIComponent(requestUri)}`)
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

  function handleDifferentAccount() {
    const requestUri = getRequestUri()
    if (requestUri) {
      navigate(`/oauth/login?request_uri=${encodeURIComponent(requestUri)}`)
    } else {
      navigate('/oauth/login')
    }
  }

  $effect(() => {
    fetchAccounts()
  })
</script>

<div class="oauth-accounts-container">
  {#if loading}
    <div class="loading">
      <p>Loading accounts...</p>
    </div>
  {:else if error}
    <div class="error-container">
      <h1>Error</h1>
      <div class="error">{error}</div>
      <button type="button" onclick={handleDifferentAccount}>
        Sign in with different account
      </button>
    </div>
  {:else}
    <h1>Choose an Account</h1>
    <p class="subtitle">Select an account to continue</p>

    <div class="accounts-list">
      {#each accounts as account}
        <button
          type="button"
          class="account-item"
          class:disabled={submitting}
          onclick={() => !submitting && handleSelectAccount(account.did)}
        >
          <div class="account-info">
            <span class="account-handle">@{account.handle}</span>
            <span class="account-email">{account.email}</span>
          </div>
        </button>
      {/each}
    </div>

    <button type="button" class="secondary different-account" onclick={handleDifferentAccount}>
      Sign in to different account
    </button>
  {/if}
</div>

<style>
  .oauth-accounts-container {
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

  .loading {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 200px;
    color: var(--text-secondary);
  }

  .error-container {
    text-align: center;
  }

  .error {
    padding: 0.75rem;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: 4px;
    color: var(--error-text);
    margin-bottom: 1rem;
  }

  .accounts-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }

  .account-item {
    display: flex;
    align-items: center;
    padding: 1rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    cursor: pointer;
    text-align: left;
    width: 100%;
    transition: border-color 0.15s, box-shadow 0.15s;
  }

  .account-item:hover:not(.disabled) {
    border-color: var(--accent);
    box-shadow: 0 2px 8px rgba(77, 166, 255, 0.15);
  }

  .account-item.disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .account-info {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .account-handle {
    font-weight: 500;
    color: var(--text-primary);
  }

  .account-email {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  button {
    padding: 0.75rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
  }

  button:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  button.secondary {
    background: transparent;
    color: var(--accent);
    border: 1px solid var(--accent);
    width: 100%;
  }

  button.secondary:hover:not(:disabled) {
    background: var(--accent);
    color: white;
  }

  .different-account {
    margin-top: 1rem;
  }
</style>
