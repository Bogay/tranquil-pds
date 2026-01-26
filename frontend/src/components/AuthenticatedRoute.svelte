<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate, routes } from '../lib/router.svelte'
  import type { Snippet } from 'svelte'
  import type { Session } from '../lib/types/api'
  import { createAuthenticatedClient, type AuthenticatedClient } from '../lib/authenticated-client'

  interface Props {
    children: Snippet<[{ session: Session; client: AuthenticatedClient }]>
    requireAdmin?: boolean
    onReady?: (session: Session, client: AuthenticatedClient) => void
  }

  let { children, requireAdmin = false, onReady }: Props = $props()
  const auth = $derived(getAuthState())
  let readyCalled = $state(false)

  $effect(() => {
    if (auth.kind === 'unauthenticated' || auth.kind === 'error') {
      navigate(routes.login)
    }
    if (requireAdmin && auth.kind === 'authenticated' && !auth.session.isAdmin) {
      navigate(routes.dashboard)
    }
    if (auth.kind === 'authenticated' && onReady && !readyCalled) {
      readyCalled = true
      onReady(auth.session, createAuthenticatedClient(auth.session))
    }
  })
</script>

{#if auth.kind === 'authenticated'}
  {@render children({ session: auth.session, client: createAuthenticatedClient(auth.session) })}
{:else}
  <div class="loading-container"><div class="loading-spinner"></div></div>
{/if}

<style>
  .loading-container {
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 200px;
    padding: var(--space-7);
  }

  .loading-spinner {
    width: 32px;
    height: 32px;
    border: 3px solid var(--border-color);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>
