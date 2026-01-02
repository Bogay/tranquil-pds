<script lang="ts">
  import { getAuthState, logout } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { generateCodeVerifier, generateCodeChallenge, saveOAuthState, generateState } from '../lib/oauth'
  import { _ } from '../lib/i18n'

  const auth = getAuthState()
  let error = $state<string | null>(null)
  let loading = $state(true)
  let actAsInProgress = $state(false)

  function getDid(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('did')
  }

  $effect(() => {
    if (!auth.loading && !auth.session && !actAsInProgress) {
      navigate('/login')
    }
  })

  $effect(() => {
    if (auth.session && !actAsInProgress) {
      actAsInProgress = true
      initiateActAs()
    }
  })

  async function initiateActAs() {
    const did = getDid()
    if (!did) {
      error = $_('actAs.noAccountSpecified')
      loading = false
      return
    }

    try {
      const response = await fetch(
        `/xrpc/_delegation.listControlledAccounts`,
        {
          headers: { 'Authorization': `Bearer ${auth.session!.accessJwt}` }
        }
      )

      if (!response.ok) {
        error = $_('actAs.failedToVerify')
        loading = false
        return
      }

      const data = await response.json()
      const account = data.accounts?.find((a: { did: string }) => a.did === did)

      if (!account) {
        error = $_('actAs.noAccess')
        loading = false
        return
      }

      await logout()

      const hostname = window.location.origin
      const state = generateState()
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)
      saveOAuthState({ state, codeVerifier })

      const parResponse = await fetch('/oauth/par', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: `${hostname}/oauth/client-metadata.json`,
          redirect_uri: `${hostname}/`,
          response_type: 'code',
          scope: 'atproto',
          state: state,
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          login_hint: account.handle
        })
      })

      if (!parResponse.ok) {
        error = $_('actAs.failedToInitiate')
        loading = false
        return
      }

      const parData = await parResponse.json()
      if (parData.request_uri) {
        window.location.href = `/app/oauth/login?request_uri=${encodeURIComponent(parData.request_uri)}`
      } else {
        error = $_('actAs.invalidResponse')
        loading = false
      }
    } catch (e) {
      error = $_('actAs.failedError', { values: { error: e instanceof Error ? e.message : String(e) } })
      loading = false
    }
  }

  function goBack() {
    navigate('/controllers')
  }
</script>

<div class="page">
  {#if loading}
    <div class="loading">
      <p>{$_('actAs.preparing')}</p>
    </div>
  {:else}
    <header>
      <h1>{$_('actAs.title')}</h1>
    </header>

    {#if error}
      <div class="message error">{error}</div>
    {/if}

    <div class="actions">
      <button class="back-btn" onclick={goBack}>
        {$_('actAs.backToControllers')}
      </button>
    </div>
  {/if}
</div>

<style>
  .page {
    max-width: var(--width-md);
    margin: var(--space-9) auto;
    padding: var(--space-7);
  }

  .loading {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 200px;
    color: var(--text-secondary);
  }

  header {
    margin-bottom: var(--space-6);
  }

  h1 {
    margin: 0;
  }

  .message.error {
    padding: var(--space-3);
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: var(--radius-md);
    color: var(--error-text);
    margin-bottom: var(--space-4);
  }

  .actions {
    margin-top: var(--space-4);
  }

  .back-btn {
    padding: var(--space-3) var(--space-5);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--text-primary);
    cursor: pointer;
  }

  .back-btn:hover {
    background: var(--bg-card);
    border-color: var(--accent);
  }
</style>
