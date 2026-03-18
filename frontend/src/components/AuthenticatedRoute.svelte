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
  <div class="loading-container"></div>
{/if}
