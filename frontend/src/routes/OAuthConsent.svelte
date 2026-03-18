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
  let error = $state<string | null>(null)
  let submitting = $state(false)
  let consentData = $state<ConsentData | null>(null)
  let scopeSelections = $state<Record<string, boolean>>({})
  let rememberChoice = $state(false)

  function getRequestUri(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('request_uri')
  }

  async function tryRenewRequest(requestUri: string): Promise<boolean> {
    try {
      const response = await fetch('/oauth/authorize/renew', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request_uri: requestUri }),
      })
      if (!response.ok) return false
      const data = await response.json()
      return data.renewed === true
    } catch {
      return false
    }
  }

  async function fetchConsentData() {
    const requestUri = getRequestUri()
    if (!requestUri) {
      console.error('[OAuthConsent] No request_uri in URL')
      error = $_('oauth.error.genericError')
      loading = false
      return
    }

    try {
      let response = await fetch(`/oauth/authorize/consent?request_uri=${encodeURIComponent(requestUri)}`)
      if (!response.ok) {
        const data = await response.json()
        if (data.error === 'expired_request') {
          const renewed = await tryRenewRequest(requestUri)
          if (renewed) {
            response = await fetch(`/oauth/authorize/consent?request_uri=${encodeURIComponent(requestUri)}`)
            if (!response.ok) {
              const retryData = await response.json()
              console.error('[OAuthConsent] Consent fetch failed after renewal:', retryData)
              error = retryData.error_description || retryData.error || $_('oauth.error.genericError')
              loading = false
              return
            }
          } else {
            console.error('[OAuthConsent] Consent fetch failed:', data)
            error = data.error_description || data.error || $_('oauth.error.genericError')
            loading = false
            return
          }
        } else {
          console.error('[OAuthConsent] Consent fetch failed:', data)
          error = data.error_description || data.error || $_('oauth.error.genericError')
          loading = false
          return
        }
      }
      const data: ConsentData = await response.json()

      if (!data.scopes || !Array.isArray(data.scopes)) {
        console.error('[OAuthConsent] Invalid scopes data:', data.scopes)
        error = 'Invalid consent data received'
        loading = false
        return
      }

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
    } catch (e) {
      console.error('[OAuthConsent] Error during consent fetch:', e)
      error = $_('oauth.error.genericError')
    } finally {
      loading = false
    }
  }

  async function submitConsent() {
    if (!consentData) {
      console.error('[OAuthConsent] submitConsent called but no consentData')
      return
    }

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
        console.error('[OAuthConsent] Submit failed:', data)
        error = data.error_description || data.error || $_('oauth.error.genericError')
        submitting = false
        return
      }

      const data = await response.json()
      if (data.redirect_uri) {
        window.location.href = data.redirect_uri
      } else {
        console.error('[OAuthConsent] No redirect_uri in response')
        error = 'Authorization failed - no redirect received'
        submitting = false
      }
    } catch (e) {
      console.error('[OAuthConsent] Submit error:', e)
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
    fetchConsentData()
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
    <div class="loading"></div>
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
                <span class="consent-account-label">{$_('oauthConsent.actingAs')}</span>
                <span class="consent-account-did">{consentData.did}</span>
              </div>
              <div class="info-row">
                <span class="consent-account-label">{$_('oauthConsent.controller')}</span>
                <span class="consent-account-handle">@{consentData.controller_handle || consentData.controller_did}</span>
              </div>
              <div class="info-row">
                <span class="consent-account-label">{$_('oauthConsent.accessLevel')}</span>
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
            <span class="consent-account-label">{$_('oauth.consent.signingInAs')}</span>
            {#if consentData.handle}
              <span class="consent-account-handle">@{consentData.handle}</span>
            {/if}
            <span class="consent-account-did">{consentData.did}</span>
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
      <button type="button" class="cancel" onclick={handleDeny} disabled={submitting}>
        {$_('oauth.consent.deny')}
      </button>
      <button type="button" onclick={submitConsent} disabled={submitting}>
        {submitting ? $_('oauth.consent.authorizing') : $_('oauth.consent.authorize')}
      </button>
    </div>
  {:else}
    <div class="error-container">
      <h1>{$_('oauth.consent.unexpectedState.title')}</h1>
      <p style="color: var(--text-secondary);">
        {$_('oauth.consent.unexpectedState.description')}
      </p>
      <p style="color: var(--text-muted); font-size: 0.75rem; font-family: monospace;">
        loading={loading}, error={error ? 'set' : 'null'}, consentData={consentData ? 'set' : 'null'}, submitting={submitting}
      </p>
      <button type="button" onclick={() => window.location.reload()}>
        {$_('oauth.consent.unexpectedState.reload')}
      </button>
    </div>
  {/if}
</div>
