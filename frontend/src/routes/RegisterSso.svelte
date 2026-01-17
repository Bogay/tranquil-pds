<script lang="ts">
  import { onMount } from 'svelte'
  import { _ } from '../lib/i18n'
  import { getFullUrl } from '../lib/router.svelte'
  import { routes } from '../lib/types/routes'
  import { toast } from '../lib/toast.svelte'
  import AccountTypeSwitcher from '../components/AccountTypeSwitcher.svelte'
  import SsoIcon from '../components/SsoIcon.svelte'

  interface SsoProvider {
    provider: string
    name: string
    icon: string
  }

  let providers = $state<SsoProvider[]>([])
  let loading = $state(true)
  let initiating = $state<string | null>(null)

  onMount(() => {
    fetchProviders()
  })

  async function fetchProviders() {
    try {
      const response = await fetch('/oauth/sso/providers')
      if (response.ok) {
        const data = await response.json()
        providers = data.providers || []
      }
    } catch {
      toast.error($_('common.error'))
    } finally {
      loading = false
    }
  }

  async function initiateRegistration(provider: string) {
    initiating = provider

    try {
      const response = await fetch('/oauth/sso/initiate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          provider,
          action: 'register',
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        toast.error(data.error_description || data.error || $_('common.error'))
        initiating = null
        return
      }

      if (data.redirect_url) {
        window.location.href = data.redirect_url
        return
      }

      toast.error($_('common.error'))
      initiating = null
    } catch {
      toast.error($_('common.error'))
      initiating = null
    }
  }
</script>

<div class="register-sso-page">
  <header class="page-header">
    <h1>{$_('register.title')}</h1>
    <p class="subtitle">{$_('register.ssoSubtitle')}</p>
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

  <AccountTypeSwitcher active="sso" ssoAvailable={providers.length > 0} />

  {#if loading}
    <div class="loading">
      <div class="spinner"></div>
    </div>
  {:else if providers.length === 0}
    <div class="no-providers">
      <p>{$_('register.noSsoProviders')}</p>
    </div>
  {:else}
    <div class="provider-list">
      <p class="provider-hint">{$_('register.ssoHint')}</p>
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

  <div class="form-links">
    <p class="link-text">
      {$_('register.alreadyHaveAccount')} <a href={getFullUrl(routes.login)}>{$_('register.signIn')}</a>
    </p>
  </div>
</div>

<style>
  .register-sso-page {
    max-width: var(--width-lg);
    margin: var(--space-9) auto;
    padding: var(--space-7);
  }

  .page-header {
    margin-bottom: var(--space-6);
  }

  .page-header h1 {
    margin: 0 0 var(--space-3) 0;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0;
  }

  .migrate-callout {
    display: flex;
    gap: var(--space-4);
    padding: var(--space-5);
    background: var(--accent-muted);
    border: 1px solid var(--accent);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-6);
  }

  .migrate-icon {
    font-size: var(--text-2xl);
    line-height: 1;
    color: var(--accent);
  }

  .migrate-content {
    flex: 1;
  }

  .migrate-content strong {
    display: block;
    color: var(--text-primary);
    margin-bottom: var(--space-2);
  }

  .migrate-content p {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-sm);
    color: var(--text-secondary);
    line-height: var(--leading-relaxed);
  }

  .migrate-link {
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
    color: var(--accent);
    text-decoration: none;
  }

  .migrate-link:hover {
    text-decoration: underline;
  }

  .loading {
    display: flex;
    justify-content: center;
    padding: var(--space-8);
  }

  .spinner {
    width: 32px;
    height: 32px;
    border: 3px solid var(--border-color);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .no-providers {
    text-align: center;
    padding: var(--space-8);
    color: var(--text-secondary);
  }

  .provider-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    max-width: var(--width-md);
  }

  .provider-hint {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin: 0 0 var(--space-4) 0;
  }

  .provider-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: var(--space-3);
  }

  @media (min-width: 500px) {
    .provider-grid {
      grid-template-columns: repeat(2, 1fr);
    }
  }

  .provider-button {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-4);
    background: var(--bg-card);
    border: 1px solid var(--border-dark);
    border-radius: var(--radius-lg);
    cursor: pointer;
    transition: all var(--transition-normal);
    font-size: var(--text-base);
    font-weight: var(--font-medium);
    color: var(--text-primary);
    text-align: left;
    width: 100%;
  }

  .provider-button:hover:not(:disabled) {
    background: var(--bg-secondary);
    border-color: var(--accent);
  }

  .provider-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .provider-name {
    flex: 1;
  }

  .form-links {
    margin-top: var(--space-8);
  }

  .link-text {
    text-align: center;
    color: var(--text-secondary);
  }

  .link-text a {
    color: var(--accent);
  }
</style>
