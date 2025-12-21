<script lang="ts">
  import { navigate } from '../lib/router.svelte'

  interface ScopeInfo {
    scope: string
    category: string
    required: boolean
    description: string
    display_name: string
    granted: boolean | null
  }

  interface ConsentData {
    request_uri: string
    client_id: string
    client_name: string | null
    client_uri: string | null
    logo_uri: string | null
    scopes: ScopeInfo[]
    show_consent: boolean
    did: string
  }

  let loading = $state(true)
  let error = $state<string | null>(null)
  let submitting = $state(false)
  let consentData = $state<ConsentData | null>(null)
  let scopeSelections = $state<Record<string, boolean>>({})
  let rememberChoice = $state(false)

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.hash.split('?')[1] || '')
    return params.get('request_uri')
  }

  async function fetchConsentData() {
    const requestUri = getRequestUri()
    if (!requestUri) {
      error = 'Missing request_uri parameter'
      loading = false
      return
    }

    try {
      const response = await fetch(`/oauth/authorize/consent?request_uri=${encodeURIComponent(requestUri)}`)
      if (!response.ok) {
        const data = await response.json()
        error = data.error_description || data.error || 'Failed to load consent data'
        loading = false
        return
      }
      const data: ConsentData = await response.json()
      consentData = data

      for (const scope of data.scopes) {
        if (scope.required) {
          scopeSelections[scope.scope] = true
        } else if (scope.granted !== null) {
          scopeSelections[scope.scope] = scope.granted
        } else {
          scopeSelections[scope.scope] = true
        }
      }

      if (!data.show_consent) {
        await submitConsent()
      }
    } catch {
      error = 'Failed to connect to server'
    } finally {
      loading = false
    }
  }

  async function submitConsent() {
    if (!consentData) return

    submitting = true
    const approvedScopes = Object.entries(scopeSelections)
      .filter(([_, approved]) => approved)
      .map(([scope]) => scope)

    try {
      const response = await fetch('/oauth/authorize/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          request_uri: consentData.request_uri,
          approved_scopes: approvedScopes,
          remember: rememberChoice
        })
      })

      if (!response.ok) {
        const data = await response.json()
        error = data.error_description || data.error || 'Authorization failed'
        submitting = false
        return
      }

      const data = await response.json()
      if (data.redirect_uri) {
        window.location.href = data.redirect_uri
      }
    } catch {
      error = 'Failed to complete authorization'
      submitting = false
    }
  }

  async function handleDeny() {
    if (!consentData) return

    submitting = true
    try {
      const response = await fetch('/oauth/authorize/deny', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request_uri: consentData.request_uri })
      })

      if (response.redirected) {
        window.location.href = response.url
      }
    } catch {
      error = 'Failed to deny authorization'
      submitting = false
    }
  }

  function handleScopeToggle(scope: string) {
    const scopeInfo = consentData?.scopes.find(s => s.scope === scope)
    if (scopeInfo?.required) return
    scopeSelections[scope] = !scopeSelections[scope]
  }

  function groupScopesByCategory(scopes: ScopeInfo[]): Record<string, ScopeInfo[]> {
    const groups: Record<string, ScopeInfo[]> = {}
    for (const scope of scopes) {
      if (!groups[scope.category]) {
        groups[scope.category] = []
      }
      groups[scope.category].push(scope)
    }
    return groups
  }

  $effect(() => {
    fetchConsentData()
  })

  let scopeGroups = $derived(consentData ? groupScopesByCategory(consentData.scopes) : {})
</script>

<div class="consent-container">
  {#if loading}
    <div class="loading">
      <p>Loading...</p>
    </div>
  {:else if error}
    <div class="error-container">
      <h1>Authorization Error</h1>
      <div class="error">{error}</div>
      <button type="button" onclick={() => navigate('/login')}>
        Return to Login
      </button>
    </div>
  {:else if consentData}
    <div class="client-info">
      {#if consentData.logo_uri}
        <img src={consentData.logo_uri} alt="" class="client-logo" />
      {/if}
      <h1>{consentData.client_name || 'Application'}</h1>
      <p class="subtitle">wants to access your account</p>
      {#if consentData.client_uri}
        <a href={consentData.client_uri} target="_blank" rel="noopener noreferrer" class="client-link">
          {consentData.client_uri}
        </a>
      {/if}
    </div>

    <div class="account-info">
      <span class="label">Signing in as:</span>
      <span class="did">{consentData.did}</span>
    </div>

    <div class="scopes-section">
      <h2>Permissions Requested</h2>
      {#each Object.entries(scopeGroups) as [category, scopes]}
        <div class="scope-group">
          <h3 class="category-title">{category}</h3>
          {#each scopes as scope}
            <label class="scope-item" class:required={scope.required}>
              <input
                type="checkbox"
                checked={scopeSelections[scope.scope]}
                disabled={scope.required || submitting}
                onchange={() => handleScopeToggle(scope.scope)}
              />
              <div class="scope-info">
                <span class="scope-name">{scope.display_name}</span>
                <span class="scope-description">{scope.description}</span>
                {#if scope.required}
                  <span class="required-badge">Required</span>
                {/if}
              </div>
            </label>
          {/each}
        </div>
      {/each}
    </div>

    <label class="remember-choice">
      <input type="checkbox" bind:checked={rememberChoice} disabled={submitting} />
      <span>Remember my choice for this application</span>
    </label>

    <div class="actions">
      <button type="button" class="deny-btn" onclick={handleDeny} disabled={submitting}>
        Deny
      </button>
      <button type="button" class="approve-btn" onclick={submitConsent} disabled={submitting}>
        {submitting ? 'Authorizing...' : 'Authorize'}
      </button>
    </div>
  {/if}
</div>

<style>
  .consent-container {
    max-width: 480px;
    margin: 2rem auto;
    padding: 2rem;
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

  .client-info {
    text-align: center;
    margin-bottom: 1.5rem;
  }

  .client-logo {
    width: 64px;
    height: 64px;
    border-radius: 12px;
    margin-bottom: 1rem;
  }

  .client-info h1 {
    margin: 0 0 0.25rem 0;
    font-size: 1.5rem;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0;
  }

  .client-link {
    display: inline-block;
    margin-top: 0.5rem;
    font-size: 0.875rem;
    color: var(--accent);
    text-decoration: none;
  }

  .client-link:hover {
    text-decoration: underline;
  }

  .account-info {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    padding: 1rem;
    background: var(--bg-secondary);
    border-radius: 8px;
    margin-bottom: 1.5rem;
  }

  .account-info .label {
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .account-info .did {
    font-family: monospace;
    font-size: 0.875rem;
    color: var(--text-primary);
    word-break: break-all;
  }

  .scopes-section {
    margin-bottom: 1.5rem;
  }

  .scopes-section h2 {
    font-size: 1rem;
    margin: 0 0 1rem 0;
    color: var(--text-secondary);
  }

  .scope-group {
    margin-bottom: 1rem;
  }

  .category-title {
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--text-primary);
    margin: 0 0 0.5rem 0;
    padding-bottom: 0.25rem;
    border-bottom: 1px solid var(--border-color);
  }

  .scope-item {
    display: flex;
    gap: 0.75rem;
    padding: 0.75rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    margin-bottom: 0.5rem;
    cursor: pointer;
    transition: border-color 0.15s;
  }

  .scope-item:hover:not(.required) {
    border-color: var(--accent);
  }

  .scope-item.required {
    background: var(--bg-secondary);
  }

  .scope-item input[type="checkbox"] {
    flex-shrink: 0;
    width: 18px;
    height: 18px;
    margin-top: 2px;
  }

  .scope-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 0.125rem;
  }

  .scope-name {
    font-weight: 500;
    color: var(--text-primary);
  }

  .scope-description {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  .required-badge {
    display: inline-block;
    font-size: 0.625rem;
    padding: 0.125rem 0.375rem;
    background: var(--warning-bg);
    color: var(--warning-text);
    border-radius: 3px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 0.25rem;
    width: fit-content;
  }

  .remember-choice {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 1.5rem;
    cursor: pointer;
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .remember-choice input {
    width: 16px;
    height: 16px;
  }

  .actions {
    display: flex;
    gap: 1rem;
  }

  .actions button {
    flex: 1;
    padding: 0.875rem;
    border: none;
    border-radius: 6px;
    font-size: 1rem;
    font-weight: 500;
    cursor: pointer;
    transition: background-color 0.15s;
  }

  .actions button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .deny-btn {
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
  }

  .deny-btn:hover:not(:disabled) {
    background: var(--error-bg);
    border-color: var(--error-border);
    color: var(--error-text);
  }

  .approve-btn {
    background: var(--accent);
    color: white;
  }

  .approve-btn:hover:not(:disabled) {
    background: var(--accent-hover);
  }
</style>
