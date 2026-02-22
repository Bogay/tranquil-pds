<script lang="ts">
  import AuthenticatedRoute from '../components/AuthenticatedRoute.svelte'
  import { navigate } from '../lib/router.svelte'
  import { generateCodeVerifier, generateCodeChallenge, saveOAuthState, generateState, createDPoPProofForRequest, setDPoPNonce } from '../lib/oauth'
  import { _ } from '../lib/i18n'
  import type { Session, DelegationControlledAccount } from '../lib/types/api'
  import type { AuthenticatedClient } from '../lib/authenticated-client'

  let error = $state<string | null>(null)
  let loading = $state(true)
  let actAsStarted = $state(false)

  function getDid(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('did')
  }

  async function initiateActAs(session: Session, client: AuthenticatedClient) {
    if (actAsStarted) return
    actAsStarted = true

    const did = getDid()
    if (!did) {
      error = $_('actAs.noAccountSpecified')
      loading = false
      return
    }

    const result = await client.listDelegationControlledAccounts()
    if (!result.ok) {
      error = $_('actAs.failedToInitiate')
      loading = false
      return
    }

    const account = result.value.accounts?.find((a: DelegationControlledAccount) => a.did === did)

    if (!account) {
      error = $_('actAs.noAccess')
      loading = false
      return
    }

    const hostname = window.location.origin
    const state = generateState()
    const codeVerifier = generateCodeVerifier()
    const codeChallenge = await generateCodeChallenge(codeVerifier)
    saveOAuthState({ state, codeVerifier })

    const parResponse = await fetch('/oauth/par', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: `${hostname}/oauth-client-metadata.json`,
        redirect_uri: `${hostname}/app/`,
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
    if (!parData.request_uri) {
      error = $_('actAs.invalidResponse')
      loading = false
      return
    }

    const authUrl = `${window.location.origin}/oauth/delegation/auth-token`
    const body = JSON.stringify({
      request_uri: parData.request_uri,
      delegated_did: did
    })

    async function callAuthToken(retry: boolean): Promise<Response> {
      const dpopProof = await createDPoPProofForRequest('POST', authUrl, session.accessJwt)
      const response = await fetch('/oauth/delegation/auth-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `DPoP ${session.accessJwt}`,
          'DPoP': dpopProof
        },
        body
      })

      if (!response.ok && retry) {
        const nonce = response.headers.get('DPoP-Nonce')
        if (nonce) {
          setDPoPNonce(nonce)
          return callAuthToken(false)
        }
      }
      return response
    }

    const authResponse = await callAuthToken(true)
    const authData = await authResponse.json()
    if (authData.success && authData.redirect_uri) {
      window.location.href = authData.redirect_uri
    } else {
      error = authData.error || $_('actAs.failedToInitiate')
      loading = false
    }
  }

  function goBack() {
    navigate('/controllers')
  }

  function handleReady(session: Session, client: AuthenticatedClient) {
    initiateActAs(session, client)
  }
</script>

<AuthenticatedRoute onReady={handleReady}>
  {#snippet children({ session, client })}
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
  {/snippet}
</AuthenticatedRoute>

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
