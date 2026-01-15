<script lang="ts">
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'

  interface ScopeInfo {
    scope: string
    category: string
    required: boolean
    description: string
    display_name: string
    granted: boolean | null
  }

  const SCOPE_LOCALE_MAP: Record<string, string> = {
    'atproto': 'atproto',
    'transition:generic': 'transitionGeneric',
    'transition:chat.bsky': 'transitionChat',
    'transition:email': 'transitionEmail',
    'repo:*?action=create': 'repoCreate',
    'repo:*?action=update': 'repoUpdate',
    'repo:*?action=delete': 'repoDelete',
    'blob:*/*': 'blobAll',
    'repo:*': 'repoFull',
    'account:*?action=manage': 'accountManage',
  }

  function isGranularScope(scope: string): boolean {
    return scope.startsWith('repo:') ||
           scope.startsWith('blob') ||
           scope.startsWith('rpc:') ||
           scope.startsWith('account:') ||
           scope.startsWith('identity:')
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
    handle?: string
    is_delegation?: boolean
    controller_did?: string
    controller_handle?: string
    delegation_level?: string
  }

  let loading = $state(true)
  let showSpinner = $state(false)
  let loadingTimer: ReturnType<typeof setTimeout> | null = null
  let error = $state<string | null>(null)
  let submitting = $state(false)
  let consentData = $state<ConsentData | null>(null)
  let scopeSelections = $state<Record<string, boolean>>({})
  let rememberChoice = $state(false)

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('request_uri')
  }

  async function fetchConsentData() {
    const requestUri = getRequestUri()
    if (!requestUri) {
      error = $_('oauth.error.genericError')
      loading = false
      return
    }

    try {
      const response = await fetch(`/oauth/authorize/consent?request_uri=${encodeURIComponent(requestUri)}`)
      if (!response.ok) {
        const data = await response.json()
        error = data.error_description || data.error || $_('oauth.error.genericError')
        loading = false
        return
      }
      const data: ConsentData = await response.json()
      consentData = data

      scopeSelections = Object.fromEntries(
        data.scopes.map((scope) => [
          scope.scope,
          scope.required ? true : scope.granted ?? true,
        ])
      )

      if (!data.show_consent) {
        await submitConsent()
      }
    } catch {
      error = $_('oauth.error.genericError')
    } finally {
      loading = false
      showSpinner = false
      if (loadingTimer) {
        clearTimeout(loadingTimer)
        loadingTimer = null
      }
    }
  }

  async function submitConsent() {
    if (!consentData) return

    submitting = true
    let approvedScopes = Object.entries(scopeSelections)
      .filter(([_, approved]) => approved)
      .map(([scope]) => scope)

    if (approvedScopes.length === 0 && consentData.scopes.length === 0) {
      approvedScopes = ['atproto']
    }

    try {
      const response = await fetch('/oauth/authorize/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          request_uri: consentData.request_uri,
          approved_scopes: approvedScopes,
          remember: rememberChoice,
        }),
      })

      if (!response.ok) {
        const data = await response.json()
        error = data.error_description || data.error || $_('oauth.error.genericError')
        submitting = false
        return
      }

      const data = await response.json()
      if (data.redirect_uri) {
        window.location.href = data.redirect_uri
      }
    } catch {
      error = $_('oauth.error.genericError')
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
      error = $_('oauth.error.genericError')
      submitting = false
    }
  }

  function handleScopeToggle(scope: string) {
    const scopeInfo = consentData?.scopes.find(s => s.scope === scope)
    if (scopeInfo?.required) return
    scopeSelections[scope] = !scopeSelections[scope]
  }

  const CATEGORY_ORDER = [
    'Core Access',
    'Transition',
    'Account',
    'Repository',
    'Media',
    'API Access',
    'Reference',
    'Other'
  ]

  function groupScopesByCategory(scopes: ScopeInfo[]): [string, ScopeInfo[]][] {
    const groups = scopes.reduce(
      (acc, scope) => ({
        ...acc,
        [scope.category]: [...(acc[scope.category] ?? []), scope],
      }),
      {} as Record<string, ScopeInfo[]>
    )
    return Object.entries(groups).sort(([a], [b]) => {
      const aIndex = CATEGORY_ORDER.indexOf(a)
      const bIndex = CATEGORY_ORDER.indexOf(b)
      const aOrder = aIndex === -1 ? CATEGORY_ORDER.length : aIndex
      const bOrder = bIndex === -1 ? CATEGORY_ORDER.length : bIndex
      return aOrder - bOrder
    })
  }

  $effect(() => {
    loadingTimer = setTimeout(() => {
      if (loading) {
        showSpinner = true
      }
    }, 5000)
    fetchConsentData()
    return () => {
      if (loadingTimer) {
        clearTimeout(loadingTimer)
      }
    }
  })

  let scopeGroups = $derived(consentData ? groupScopesByCategory(consentData.scopes) : [])
  let hasGranularScopes = $derived(consentData?.scopes.some(s => isGranularScope(s.scope)) ?? false)

  function getLocalizedScopeName(scope: ScopeInfo): string {
    const localeKey = SCOPE_LOCALE_MAP[scope.scope]
    if (!localeKey) return scope.display_name

    if (scope.scope === 'atproto' && hasGranularScopes) {
      const localized = $_(`oauth.consent.scopes.atprotoWithGranular.name`)
      return localized !== `oauth.consent.scopes.atprotoWithGranular.name` ? localized : scope.display_name
    }

    const localized = $_(`oauth.consent.scopes.${localeKey}.name`)
    return localized !== `oauth.consent.scopes.${localeKey}.name` ? localized : scope.display_name
  }

  function getLocalizedScopeDescription(scope: ScopeInfo): string {
    const localeKey = SCOPE_LOCALE_MAP[scope.scope]
    if (!localeKey) return scope.description

    if (scope.scope === 'atproto' && hasGranularScopes) {
      const localized = $_(`oauth.consent.scopes.atprotoWithGranular.description`)
      return localized !== `oauth.consent.scopes.atprotoWithGranular.description` ? localized : scope.description
    }

    const localized = $_(`oauth.consent.scopes.${localeKey}.description`)
    return localized !== `oauth.consent.scopes.${localeKey}.description` ? localized : scope.description
  }
</script>

<div class="consent-container">
  {#if loading}
    <div class="loading">
      {#if showSpinner}
        <div class="loading-content">
          <div class="spinner"></div>
          <p>{$_('common.loading')}</p>
        </div>
      {/if}
    </div>
  {:else if error}
    <div class="error-container">
      <h1>{$_('oauth.error.title')}</h1>
      <div class="error">{error}</div>
      <button type="button" onclick={() => navigate(routes.login)}>
        {$_('common.backToLogin')}
      </button>
    </div>
  {:else if consentData}
    <div class="split-layout sidebar-left">
      <div class="client-panel">
        <div class="client-info">
          {#if consentData.logo_uri}
            <img src={consentData.logo_uri} alt="" class="client-logo" />
          {/if}
          <h1>{consentData.client_name || $_('oauth.consent.title')}</h1>
          <p class="subtitle">{$_('oauth.consent.appWantsAccess', { values: { app: '' } })}</p>
          {#if consentData.client_uri}
            <a href={consentData.client_uri} target="_blank" rel="noopener noreferrer" class="client-link">
              {consentData.client_uri}
            </a>
          {/if}
        </div>

        <div class="account-info">
          {#if consentData.is_delegation}
            <div class="delegation-badge">{$_('oauthConsent.delegatedAccess')}</div>
            <div class="delegation-info">
              <div class="info-row">
                <span class="label">{$_('oauthConsent.actingAs')}</span>
                <span class="did">{consentData.did}</span>
              </div>
              <div class="info-row">
                <span class="label">{$_('oauthConsent.controller')}</span>
                <span class="handle">@{consentData.controller_handle || consentData.controller_did}</span>
              </div>
              <div class="info-row">
                <span class="label">{$_('oauthConsent.accessLevel')}</span>
                <span class="level-badge level-{consentData.delegation_level?.toLowerCase()}">{consentData.delegation_level}</span>
              </div>
            </div>
            {#if consentData.delegation_level && consentData.delegation_level !== 'Owner'}
              <div class="permissions-notice">
                <div class="notice-header">
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                  <span>{$_('oauthConsent.permissionsLimited')}</span>
                </div>
                <p class="notice-text">
                  {#if consentData.delegation_level === 'Viewer'}
                    {$_('oauthConsent.viewerLimitedDesc')}
                  {:else if consentData.delegation_level === 'Editor'}
                    {$_('oauthConsent.editorLimitedDesc')}
                  {:else}
                    {$_('oauthConsent.permissionsLimitedDesc', { values: { level: consentData.delegation_level } })}
                  {/if}
                </p>
              </div>
            {/if}
          {:else}
            <span class="label">{$_('oauth.consent.signingInAs')}</span>
            {#if consentData.handle}
              <span class="handle">@{consentData.handle}</span>
            {/if}
            <span class="did">{consentData.did}</span>
          {/if}
        </div>
      </div>

      <div class="permissions-panel">
        <div class="scopes-section">
          <h2>{$_('oauth.consent.permissionsRequested')}</h2>
          {#if consentData.scopes.length === 0}
            <div class="read-only-notice">
              <div class="scope-item read-only">
                <div class="scope-info">
                  <span class="scope-name">{$_('oauthConsent.readOnlyAccess')}</span>
                  <span class="scope-description">{$_('oauthConsent.readOnlyDesc')}</span>
                </div>
              </div>
            </div>
          {:else}
            {#each scopeGroups as [category, scopes]}
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
                      <span class="scope-name">{getLocalizedScopeName(scope)}</span>
                      <span class="scope-description">{getLocalizedScopeDescription(scope)}</span>
                      {#if scope.required}
                        <span class="required-badge">{$_('oauth.consent.required')}</span>
                      {/if}
                    </div>
                  </label>
                {/each}
              </div>
            {/each}
          {/if}
        </div>

        <label class="remember-choice">
          <input type="checkbox" bind:checked={rememberChoice} disabled={submitting} />
          <span>{$_('oauth.consent.rememberChoiceLabel')}</span>
        </label>
      </div>
    </div>

    <div class="actions">
      <button type="button" class="deny-btn" onclick={handleDeny} disabled={submitting}>
        {$_('oauth.consent.deny')}
      </button>
      <button type="button" class="approve-btn" onclick={submitConsent} disabled={submitting}>
        {submitting ? $_('oauth.consent.authorizing') : $_('oauth.consent.authorize')}
      </button>
    </div>
  {/if}
</div>

<style>
  .consent-container {
    max-width: var(--width-lg);
    margin: var(--space-7) auto;
    padding: var(--space-7);
  }

  .loading {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 200px;
    color: var(--text-secondary);
  }

  .loading-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-4);
  }

  .loading-content p {
    margin: 0;
    color: var(--text-secondary);
  }

  .error-container {
    text-align: center;
    max-width: var(--width-sm);
    margin: 0 auto;
  }

  .error {
    padding: var(--space-3);
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: var(--radius-md);
    color: var(--error-text);
    margin-bottom: var(--space-4);
  }

  .client-panel {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }

  .permissions-panel {
    min-width: 0;
  }

  .client-info {
    text-align: center;
    padding: var(--space-6);
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
  }

  @media (min-width: 800px) {
    .client-info {
      text-align: left;
    }
  }

  .client-logo {
    width: 64px;
    height: 64px;
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-4);
  }

  .client-info h1 {
    margin: 0 0 var(--space-1) 0;
    font-size: var(--text-xl);
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0;
  }

  .client-link {
    display: inline-block;
    margin-top: var(--space-2);
    font-size: var(--text-sm);
    color: var(--accent);
    text-decoration: none;
  }

  .client-link:hover {
    text-decoration: underline;
  }

  .account-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    padding: var(--space-4);
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-6);
  }

  .account-info .label {
    font-size: var(--text-xs);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .account-info .did {
    font-family: monospace;
    font-size: var(--text-sm);
    color: var(--text-secondary);
    word-break: break-all;
  }

  .account-info .handle {
    font-size: var(--text-base);
    font-weight: var(--font-medium);
    color: var(--text-primary);
  }

  .delegation-badge {
    display: inline-block;
    padding: var(--space-1) var(--space-2);
    background: var(--accent);
    color: var(--text-inverse);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
    font-weight: var(--font-semibold);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: var(--space-3);
  }

  .delegation-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .delegation-info .info-row {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .delegation-info .handle {
    font-weight: var(--font-medium);
    color: var(--text-primary);
  }

  .level-badge {
    display: inline-block;
    padding: 2px var(--space-2);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border-radius: var(--radius-sm);
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
  }

  .level-badge.level-owner {
    background: var(--success-bg);
    color: var(--success-text);
  }

  .level-badge.level-admin {
    background: var(--accent);
    color: var(--text-inverse);
  }

  .level-badge.level-editor {
    background: var(--warning-bg);
    color: var(--warning-text);
  }

  .level-badge.level-viewer {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
  }

  .permissions-notice {
    margin-top: var(--space-3);
    padding: var(--space-3);
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius-md);
  }

  .notice-header {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-weight: var(--font-semibold);
    color: var(--warning-text);
    margin-bottom: var(--space-2);
  }

  .notice-header svg {
    flex-shrink: 0;
  }

  .notice-text {
    margin: 0;
    font-size: var(--text-sm);
    color: var(--warning-text);
    line-height: 1.5;
  }

  .scopes-section {
    margin-bottom: var(--space-6);
  }

  .scopes-section h2 {
    font-size: var(--text-base);
    margin: 0 0 var(--space-4) 0;
    color: var(--text-secondary);
  }

  .scope-group {
    margin-bottom: var(--space-4);
  }

  .category-title {
    font-size: var(--text-sm);
    font-weight: var(--font-semibold);
    color: var(--text-primary);
    margin: 0 0 var(--space-2) 0;
    padding-bottom: var(--space-1);
    border-bottom: 1px solid var(--border-color);
  }

  .scope-item {
    display: flex;
    gap: var(--space-3);
    padding: var(--space-3);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-2);
    cursor: pointer;
    transition: border-color var(--transition-fast);
    overflow: hidden;
  }

  .scope-item:hover:not(.required) {
    border-color: var(--accent);
  }

  .scope-item.required {
    background: var(--bg-secondary);
  }

  .scope-item.read-only {
    background: var(--bg-secondary);
    border-style: dashed;
  }

  .scope-item input[type="checkbox"] {
    flex-shrink: 0;
    width: 18px;
    height: 18px;
    margin-top: 2px;
  }

  .scope-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
    overflow: hidden;
  }

  .scope-name {
    font-weight: var(--font-medium);
    color: var(--text-primary);
    word-break: break-all;
  }

  .scope-description {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    word-break: break-all;
  }

  .required-badge {
    display: inline-block;
    font-size: 0.625rem;
    padding: 2px var(--space-2);
    background: var(--warning-bg);
    color: var(--warning-text);
    border-radius: var(--radius-sm);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: var(--space-1);
    width: fit-content;
  }

  .remember-choice {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-top: var(--space-5);
    cursor: pointer;
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  .remember-choice input {
    width: 16px;
    height: 16px;
  }

  .actions {
    display: flex;
    gap: var(--space-4);
    margin-top: var(--space-6);
  }

  @media (min-width: 800px) {
    .actions {
      max-width: 400px;
      margin-left: auto;
    }
  }

  .actions button {
    flex: 1;
    padding: var(--space-3);
    border: none;
    border-radius: var(--radius-lg);
    font-size: var(--text-base);
    font-weight: var(--font-medium);
    cursor: pointer;
    transition: background-color var(--transition-fast);
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
    color: var(--text-inverse);
  }

  .approve-btn:hover:not(:disabled) {
    background: var(--accent-hover);
  }
</style>
