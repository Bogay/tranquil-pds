<script lang="ts">
  import { _ } from '../lib/i18n'
  import { getFullUrl } from '../lib/router.svelte'
  import { routes } from '../lib/types/routes'
  import { toast } from '../lib/toast.svelte'
  import AccountTypeSwitcher from '../components/AccountTypeSwitcher.svelte'
  import SsoIcon from '../components/SsoIcon.svelte'
  import { ensureRequestUri, getRequestUriFromUrl, getOAuthRequestUri } from '../lib/oauth'

  interface SsoProvider {
    provider: string
    name: string
    icon: string
  }

  let providers = $state<SsoProvider[]>([])
  let loading = $state(true)
  let initiating = $state<string | null>(null)
  let initialized = false

  $effect(() => {
    if (!initialized) {
      initialized = true
      ensureRequestUri().then((requestUri) => {
        if (!requestUri) return
        fetchProviders()
      }).catch((err) => {
        console.error('Failed to ensure OAuth request URI:', err)
        toast.error($_('common.error'))
      })
    }
  })

  async function fetchProviders() {
    try {
      const response = await fetch('/oauth/sso/providers')
      if (response.ok) {
        const data = await response.json()
        providers = (data.providers || []).toSorted((a: SsoProvider, b: SsoProvider) => a.name.localeCompare(b.name))
      }
    } catch (err) {
      console.error('Failed to fetch SSO providers:', err)
      toast.error(err instanceof Error ? err.message : $_('common.error'))
    } finally {
      loading = false
    }
  }

  async function initiateRegistration(provider: string) {
    initiating = provider
    let requestUri = getRequestUriFromUrl()

    try {
      let response = await fetch('/oauth/sso/initiate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          provider,
          action: 'register',
          request_uri: requestUri,
        }),
      })

      let data = await response.json()

      if (!response.ok) {
        console.log('SSO initiate failed, restarting OAuth flow', data)
        try {
          const newRequestUri = await getOAuthRequestUri('create')
          const url = new URL(window.location.href)
          url.searchParams.set('request_uri', newRequestUri)
          window.location.href = url.toString()
        } catch (e) {
          console.error('Failed to restart OAuth flow:', e)
          toast.error(data.message || data.error || $_('common.error'))
          initiating = null
        }
        return
      }

      if (data.redirect_url) {
        window.location.href = data.redirect_url
        return
      }

      toast.error($_('common.error'))
      initiating = null
    } catch (err) {
      console.error('SSO registration initiation failed:', err)
      toast.error(err instanceof Error ? err.message : $_('common.error'))
      initiating = null
    }
  }

  async function handleCancel() {
    const requestUri = getRequestUriFromUrl()
    if (!requestUri) {
      window.history.back()
      return
    }

    try {
      const response = await fetch('/oauth/authorize/deny', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ request_uri: requestUri })
      })

      if (!response.ok) {
        window.history.back()
        return
      }

      const data = await response.json()
      if (data.redirect_uri) {
        window.location.href = data.redirect_uri
      } else {
        window.history.back()
      }
    } catch {
      window.history.back()
    }
  }
</script>

<div class="page">
  <header class="page-header">
    <h1>{$_('register.title')}</h1>
  </header>

  <div class="migrate-callout">
    <div class="migrate-icon">↗</div>
    <div class="migrate-content">
      <strong>{$_('register.migrateTitle')}</strong>
      <p>{$_('register.migrateDescription')}</p>
      <a href={getFullUrl(routes.migrate)} class="migrate-link">
        {$_('register.migrateLink')} →
      </a>
    </div>
  </div>

  <AccountTypeSwitcher active="sso" ssoAvailable={providers.length > 0} oauthRequestUri={getRequestUriFromUrl()} />

  {#if loading}
    <div class="loading"></div>
  {:else if providers.length === 0}
    <div class="no-providers">
      <p>{$_('register.noSsoProviders')}</p>
    </div>
  {:else}
    <div class="provider-list">
      <div class="provider-grid">
        {#each providers as provider}
          <button
            class="provider-button"
            onclick={() => initiateRegistration(provider.provider)}
            disabled={initiating !== null}
          >
            <SsoIcon provider={provider.provider} size={24} />
            <span class="provider-name">
              {#if initiating === provider.provider}
                {$_('common.loading')}
              {:else}
                {$_('register.continueWith', { values: { provider: provider.name } })}
              {/if}
            </span>
          </button>
        {/each}
      </div>
    </div>
  {/if}

  <div class="form-actions">
    <button type="button" class="secondary" onclick={handleCancel} disabled={initiating !== null}>
      {$_('common.cancel')}
    </button>
  </div>
</div>
