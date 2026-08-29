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
    restricted?: boolean
    superseded?: boolean
    effective_scope?: string
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

  interface PermissionSetInfo {
    nsid: string
    aud?: string
    title?: string
    detail?: string
    include_scope: string
    expanded: ScopeInfo[]
    granted: boolean | null
    restricted?: boolean
    superseded?: boolean
  }

  type SetFailureReason =
    | 'unreachable'
    | 'not_found'
    | 'malformed'
    | 'not_a_permission_set'
    | 'malformed_lexicon'
    | 'empty_permissions'

  const SET_FAILURE_LOCALE_KEYS: Record<SetFailureReason, string> = {
    unreachable: 'oauth.consent.setFailureReason.unreachable',
    not_found: 'oauth.consent.setFailureReason.not_found',
    malformed: 'oauth.consent.setFailureReason.malformed',
    not_a_permission_set: 'oauth.consent.setFailureReason.not_a_permission_set',
    malformed_lexicon: 'oauth.consent.setFailureReason.malformed_lexicon',
    empty_permissions: 'oauth.consent.setFailureReason.empty_permissions',
  }

  function setFailureLocaleKey(reason: string): string {
    const known: Partial<Record<string, string>> = SET_FAILURE_LOCALE_KEYS
    return known[reason] ?? 'oauth.consent.setFailureReason.unknown'
  }

  interface FailedSetInfo {
    nsid: string
    aud?: string
    reason: string
  }

  interface ConsentData {
    request_uri: string
    client_id: string
    client_name: string | null
    client_uri: string | null
    logo_uri: string | null
    scopes: ScopeInfo[]
    permission_sets: PermissionSetInfo[]
    transition_supersedes?: boolean
    failed_sets: FailedSetInfo[]
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
        data.scopes
          .filter((scope) => !scope.restricted)
          .map((scope) => [
            scope.scope,
            scope.required ? true : scope.granted ?? true,
          ])
      )

      for (const set of data.permission_sets ?? []) {
        if (set.restricted) continue
        scopeSelections[set.include_scope] = set.granted ?? true
      }

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

    if (
      approvedScopes.length === 0 &&
      consentData.scopes.length === 0 &&
      (consentData.permission_sets?.length ?? 0) === 0
    ) {
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

  const TRANSITION_GENERIC = 'transition:generic'

  let transitionGenericSelected = $derived(scopeSelections[TRANSITION_GENERIC] === true)

  let anyDeselected = $derived(
    Object.values(scopeSelections).some((selected) => selected === false)
  )

  function isSupersededNow(item: { superseded?: boolean }): boolean {
    return Boolean(consentData?.transition_supersedes && item.superseded && transitionGenericSelected)
  }

  function handleScopeToggle(scope: string) {
    const scopeInfo = consentData?.scopes.find(s => s.scope === scope)
    if (scopeInfo?.required) return
    if (scopeInfo && isSupersededNow(scopeInfo)) return
    const next = !scopeSelections[scope]
    scopeSelections[scope] = next
    if (scope === TRANSITION_GENERIC && next) {
      for (const s of consentData?.scopes ?? []) {
        if (s.superseded && !s.restricted) scopeSelections[s.scope] = true
      }
      for (const set of consentData?.permission_sets ?? []) {
        if (set.superseded && !set.restricted) scopeSelections[set.include_scope] = true
      }
    }
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

  let grantedScopes = $derived(consentData ? consentData.scopes.filter(s => !s.restricted) : [])
  let approvableSets = $derived(consentData ? (consentData.permission_sets ?? []).filter(s => !s.restricted) : [])
  let scopeGroups = $derived(groupScopesByCategory(grantedScopes))

  let restrictedScopes = $derived(consentData ? consentData.scopes.filter(s => s.restricted) : [])
  let limitedBundles = $derived(
    consentData ? (consentData.permission_sets ?? []).filter(s => s.expanded.some(e => e.restricted)) : []
  )
  let failedSets = $derived(consentData?.failed_sets ?? [])
  let hasUnavailable = $derived(
    restrictedScopes.length > 0 || limitedBundles.length > 0 || failedSets.length > 0
  )

  let hasGranularScopes = $derived(
    (consentData?.scopes.some(s => isGranularScope(s.scope)) ?? false) ||
    ((consentData?.permission_sets?.length ?? 0) > 0)
  )

  function getLocalizedScopeName(scope: ScopeInfo): string {
    const localeKey = SCOPE_LOCALE_MAP[scope.effective_scope ?? scope.scope]
    if (!localeKey) return scope.display_name

    if (scope.scope === 'atproto' && hasGranularScopes) {
      const localized = $_(`oauth.consent.scopes.atprotoWithGranular.name`)
      return localized !== `oauth.consent.scopes.atprotoWithGranular.name` ? localized : scope.display_name
    }

    const localized = $_(`oauth.consent.scopes.${localeKey}.name`)
    return localized !== `oauth.consent.scopes.${localeKey}.name` ? localized : scope.display_name
  }

  function getLocalizedScopeDescription(scope: ScopeInfo): string {
    const localeKey = SCOPE_LOCALE_MAP[scope.effective_scope ?? scope.scope]
    if (!localeKey) return scope.description

    if (scope.scope === 'atproto' && hasGranularScopes) {
      const localized = $_(`oauth.consent.scopes.atprotoWithGranular.description`)
      return localized !== `oauth.consent.scopes.atprotoWithGranular.description` ? localized : scope.description
    }

    const localized = $_(`oauth.consent.scopes.${localeKey}.description`)
    return localized !== `oauth.consent.scopes.${localeKey}.description` ? localized : scope.description
  }

  type RepoRow = { collection: string; create: boolean; update: boolean; delete: boolean }
  function describeExpanded(expanded: ScopeInfo[]): {
    repo: RepoRow[]
    rpc: string[]
    other: ScopeInfo[]
  } {
    const repo = new Map<string, RepoRow>()
    const rpc: string[] = []
    const other: ScopeInfo[] = []
    for (const s of expanded) {
      const [base, query = ''] = (s.effective_scope ?? s.scope).split('?')
      const params = new URLSearchParams(query)
      if (base.startsWith('repo:')) {
        const collection = base.slice('repo:'.length) || '*'
        const requested = params.getAll('action')
        const actions = requested.length > 0 ? requested : ['create', 'update', 'delete']
        const row = repo.get(collection) ?? { collection, create: false, update: false, delete: false }
        for (const a of actions) {
          if (a === 'create' || a === 'update' || a === 'delete') row[a] = true
        }
        repo.set(collection, row)
      } else if (base.startsWith('rpc:')) {
        rpc.push(base.slice('rpc:'.length))
      } else {
        other.push(s)
      }
    }
    return { repo: [...repo.values()], rpc, other }
  }

  const grantedExpanded = (set: PermissionSetInfo) => set.expanded.filter(s => !s.restricted)
  const withheldExpanded = (set: PermissionSetInfo) => set.expanded.filter(s => s.restricted)
  function scopeLabel(scope: string): string {
    const base = scope.split('?')[0]
    if (base.startsWith('repo:')) {
      const params = new URLSearchParams(scope.split('?')[1] ?? '')
      const actions = params.getAll('action')
      const coll = base.slice('repo:'.length) || '*'
      return actions.length ? `${coll} (${actions.join(', ')})` : coll
    }
    if (base.startsWith('rpc:')) return base.slice('rpc:'.length)
    return base
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

        {#if transitionGenericSelected}
          <div class="permissions-notice" role="status">
            <div class="notice-header">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
              <span>{$_('oauth.consent.supersedeWarningTitle')}</span>
            </div>
            <p class="notice-text">
              {consentData.transition_supersedes
                ? $_('oauth.consent.supersedeWarningBodyMixed')
                : $_('oauth.consent.supersedeWarningBody')}
            </p>
          </div>
        {/if}

        {#if anyDeselected}
          <div class="permissions-notice" role="status">
            <div class="notice-header">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
              <span>{$_('oauth.consent.deselectedWarningTitle')}</span>
            </div>
            <p class="notice-text">{$_('oauth.consent.deselectedWarningBody')}</p>
          </div>
        {/if}
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
                      checked={isSupersededNow(scope) ? true : scopeSelections[scope.scope]}
                      disabled={scope.required || submitting || isSupersededNow(scope)}
                      onchange={() => handleScopeToggle(scope.scope)}
                    />
                    <div class="scope-info">
                      <span class="scope-name">{getLocalizedScopeName(scope)}</span>
                      <span class="scope-description">{getLocalizedScopeDescription(scope)}</span>
                      {#if scope.required}
                        <span class="required-badge">{$_('oauth.consent.required')}</span>
                      {/if}
                      {#if isSupersededNow(scope)}
                        <span class="superseded-note">{$_('oauth.consent.supersededNote')}</span>
                      {/if}
                    </div>
                  </label>
                {/each}
              </div>
            {/each}
          {/if}

          {#if approvableSets.length}
            <div class="scope-group">
              <h3 class="category-title">{$_('oauth.consent.permissionSets')}</h3>
              {#each approvableSets as set}
                {@const granted = grantedExpanded(set)}
                {@const desc = describeExpanded(granted)}
                {@const partiallyLimited = set.expanded.some(s => s.restricted)}
                <label class="scope-item">
                  <input
                    type="checkbox"
                    checked={isSupersededNow(set) ? true : scopeSelections[set.include_scope]}
                    disabled={submitting}
                    onchange={() => handleScopeToggle(set.include_scope)}
                  />
                  <div class="scope-info">
                    <span class="scope-name">{set.title ?? set.nsid}</span>
                    {#if set.detail}<span class="scope-description">{set.detail}</span>{/if}
                    {#if partiallyLimited}
                      <span class="restricted-note">{$_('oauth.consent.setPartiallyLimited')}</span>
                    {/if}
                    <details class="scope-set-details">
                      <summary>{$_('oauth.consent.showIncludedScopes', { values: { count: granted.length } })}</summary>
                      {#if desc.repo.length}
                        <table class="perm-table">
                          <thead>
                            <tr>
                              <th scope="col">{$_('oauth.consent.permTable.data')}</th>
                              <th scope="col" class="perm-col">{$_('oauth.consent.permTable.create')}</th>
                              <th scope="col" class="perm-col">{$_('oauth.consent.permTable.update')}</th>
                              <th scope="col" class="perm-col">{$_('oauth.consent.permTable.delete')}</th>
                            </tr>
                          </thead>
                          <tbody>
                            {#each desc.repo as r}
                              <tr>
                                <td class="perm-nsid">{r.collection === '*' ? $_('oauth.consent.permTable.allData') : r.collection}</td>
                                <td class="perm-col" class:on={r.create} aria-label={r.create ? $_('oauth.consent.permTable.create') : undefined}>{r.create ? '✓' : ''}</td>
                                <td class="perm-col" class:on={r.update} aria-label={r.update ? $_('oauth.consent.permTable.update') : undefined}>{r.update ? '✓' : ''}</td>
                                <td class="perm-col" class:on={r.delete} aria-label={r.delete ? $_('oauth.consent.permTable.delete') : undefined}>{r.delete ? '✓' : ''}</td>
                              </tr>
                            {/each}
                          </tbody>
                        </table>
                      {/if}
                      {#if desc.rpc.length}
                        <div class="perm-rpc">
                          <span class="perm-subhead">{$_('oauth.consent.permTable.apiAccess')}</span>
                          <ul class="scope-set-list">
                            {#each desc.rpc as lxm}<li><span class="scope-raw">{lxm}</span></li>{/each}
                          </ul>
                        </div>
                      {/if}
                      {#if desc.other.length}
                        <ul class="scope-set-list">
                          {#each desc.other as s}<li>{getLocalizedScopeName(s)} <span class="scope-raw">{s.scope}</span></li>{/each}
                        </ul>
                      {/if}
                    </details>
                  </div>
                </label>
              {/each}
            </div>
          {/if}

          {#if hasUnavailable}
            <div class="scope-group unavailable">
              <h3 class="category-title">{$_('oauth.consent.unavailablePermissions')}</h3>

              {#if restrictedScopes.length || limitedBundles.length}
                <p class="unavailable-subhead">{$_('oauth.consent.unavailableLimited')}</p>
                {#each restrictedScopes as scope}
                  <div class="scope-item restricted">
                    <div class="scope-info">
                      <span class="scope-name">{getLocalizedScopeName(scope)}</span>
                      <span class="scope-description scope-raw">{scope.scope}</span>
                    </div>
                  </div>
                {/each}
                {#each limitedBundles as set}
                  <div class="scope-item restricted">
                    <div class="scope-info">
                      <span class="scope-name">{set.title ?? set.nsid}</span>
                      <ul class="scope-set-list">
                        {#each withheldExpanded(set) as s}<li><span class="scope-raw">{scopeLabel(s.scope)}</span></li>{/each}
                      </ul>
                    </div>
                  </div>
                {/each}
              {/if}

              {#if failedSets.length}
                <p class="unavailable-subhead">{$_('oauth.consent.unavailableFailed')}</p>
                {#each failedSets as f}
                  <div class="scope-item failed">
                    <div class="scope-info">
                      <span class="scope-name">{f.nsid}{#if f.aud} ({f.aud}){/if}</span>
                      <span class="scope-description">{$_(setFailureLocaleKey(f.reason))}</span>
                    </div>
                  </div>
                {/each}
              {/if}
            </div>
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
