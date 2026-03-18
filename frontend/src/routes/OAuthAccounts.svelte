<script lang="ts">
  import { navigate, routes } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'

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
    const params = new URLSearchParams(window.location.search)
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
        navigate(routes.oauthTotp, { params: { request_uri: requestUri } })
        return
      }

      if (data.needs_2fa) {
        navigate(routes.oauth2fa, { params: { request_uri: requestUri, channel: data.channel || '' } })
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
      navigate(routes.oauthLogin, { params: { request_uri: requestUri } })
    } else {
      navigate(routes.oauthLogin)
    }
  }

  $effect(() => {
    fetchAccounts()
  })
</script>

<div class="oauth-accounts-container">
  {#if loading}
    <div class="loading"></div>
  {:else if error}
    <div class="error-container">
      <h1>Error</h1>
      <div class="error">{error}</div>
      <button type="button" onclick={handleDifferentAccount}>
        {$_('oauth.accounts.useAnother')}
      </button>
    </div>
  {:else}
    <h1>{$_('oauth.accounts.title')}</h1>

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
      {$_('oauth.accounts.useAnother')}
    </button>
  {/if}
</div>
