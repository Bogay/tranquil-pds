<script lang="ts">
  import { _ } from '../lib/i18n'

  let delegatedDid = $state<string | null>(null)
  let delegatedHandle = $state<string | null>(null)
  let controllerIdentifier = $state('')
  let submitting = $state(false)
  let loading = $state(true)
  let error = $state<string | null>(null)

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('request_uri')
  }

  function getDelegatedDid(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('delegated_did')
  }

  $effect(() => {
    loadDelegationInfo()
  })

  async function loadDelegationInfo() {
    const requestUri = getRequestUri()
    delegatedDid = getDelegatedDid()

    if (!requestUri || !delegatedDid) {
      error = $_('oauthDelegation.missingParams')
      loading = false
      return
    }

    try {
      const response = await fetch(`/xrpc/com.atproto.repo.describeRepo?repo=${encodeURIComponent(delegatedDid)}`)
      if (response.ok) {
        const data = await response.json()
        delegatedHandle = data.handle || delegatedDid
      } else {
        delegatedHandle = delegatedDid
      }
    } catch {
      delegatedHandle = delegatedDid
    } finally {
      loading = false
    }
  }

  async function handleSubmit(e: Event) {
    e.preventDefault()
    if (!controllerIdentifier.trim()) return

    submitting = true
    error = null

    try {
      let resolvedDid = controllerIdentifier.trim()
      if (!resolvedDid.startsWith('did:')) {
        resolvedDid = resolvedDid.replace(/^@/, '')
        const response = await fetch(`/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(resolvedDid)}`)
        if (!response.ok) {
          error = $_('oauthDelegation.controllerNotFound')
          submitting = false
          return
        }
        const data = await response.json()
        resolvedDid = data.did
      }

      const requestUri = getRequestUri()
      if (!requestUri || !delegatedDid) {
        error = $_('oauthDelegation.missingInfo')
        submitting = false
        return
      }

      const response = await fetch('/oauth/delegation/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          request_uri: requestUri,
          delegated_did: delegatedDid,
          controller_did: resolvedDid,
          auth_method: 'cross_pds'
        })
      })

      const data = await response.json()

      if (!response.ok || data.success === false || data.error) {
        error = data.error || $_('oauthDelegation.authFailed')
        submitting = false
        return
      }

      if (data.redirect_uri) {
        window.location.href = data.redirect_uri
        return
      }

      error = $_('oauthDelegation.unexpectedResponse')
      submitting = false
    } catch {
      error = $_('oauthDelegation.controllerNotFound')
    } finally {
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

<div class="delegation-container">
  {#if loading}
    <div class="loading">
      <p>{$_('oauthDelegation.loading')}</p>
    </div>
  {:else}
    <header class="page-header">
      <h1>{$_('oauthDelegation.title')}</h1>
      <p class="subtitle">
        {$_('oauthDelegation.isDelegated', { values: { handle: delegatedHandle } })}
        <br />{$_('oauthDelegation.enterControllerHandle')}
      </p>
    </header>

    {#if error}
      <div class="error">{error}</div>
    {/if}

    <form onsubmit={handleSubmit}>
      <div class="field">
        <label for="controller-identifier">{$_('oauthDelegation.controllerHandle')}</label>
        <input
          id="controller-identifier"
          type="text"
          bind:value={controllerIdentifier}
          disabled={submitting}
          required
          autocomplete="username"
          placeholder={$_('oauthDelegation.handlePlaceholder')}
        />
      </div>

      <div class="actions">
        <button type="button" class="cancel-btn" onclick={handleCancel} disabled={submitting}>
          {$_('common.cancel')}
        </button>
        <button type="submit" class="submit-btn" disabled={submitting || !controllerIdentifier.trim()}>
          {submitting ? $_('oauthDelegation.checking') : $_('common.continue')}
        </button>
      </div>
    </form>
  {/if}
</div>

<style>
  .delegation-container {
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

  .page-header {
    margin-bottom: var(--space-6);
  }

  h1 {
    margin: 0 0 var(--space-2) 0;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0;
    line-height: 1.6;
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

  input[type="text"] {
    padding: var(--space-3);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-size: var(--text-base);
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
