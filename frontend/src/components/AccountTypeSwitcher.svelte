<script lang="ts">
  import { _ } from '../lib/i18n'
  import { getFullUrl } from '../lib/router.svelte'
  import { routes } from '../lib/types/routes'

  interface Props {
    active: 'passkey' | 'password' | 'sso'
    ssoAvailable?: boolean
    oauthRequestUri?: string | null
  }

  let { active, ssoAvailable = true, oauthRequestUri = null }: Props = $props()

  function buildOauthUrl(route: string): string {
    const url = getFullUrl(route)
    return oauthRequestUri ? `${url}?request_uri=${encodeURIComponent(oauthRequestUri)}` : url
  }

  const passkeyUrl = $derived(buildOauthUrl(routes.oauthRegister))
  const passwordUrl = $derived(buildOauthUrl(routes.oauthRegisterPassword))
  const ssoUrl = $derived(buildOauthUrl(routes.oauthRegisterSso))
</script>

<div class="account-type-switcher">
  <a href={passkeyUrl} class="switcher-option" class:active={active === 'passkey'}>
    {$_('register.passkeyAccount')}
  </a>
  <a href={passwordUrl} class="switcher-option" class:active={active === 'password'}>
    {$_('register.passwordAccount')}
  </a>
  {#if ssoAvailable || active === 'sso'}
    <a href={ssoUrl} class="switcher-option" class:active={active === 'sso'}>
      {$_('register.ssoAccount')}
    </a>
  {:else}
    <span class="switcher-option disabled">
      {$_('register.ssoAccount')}
    </span>
  {/if}
</div>

<style>
  .account-type-switcher {
    display: flex;
    gap: var(--space-2);
    padding: var(--space-1);
    background: var(--bg-secondary);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-6);
  }

  .switcher-option {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: var(--space-2);
    padding: var(--space-3) var(--space-4);
    border-radius: var(--radius-md);
    text-decoration: none;
    color: var(--text-secondary);
    font-weight: var(--font-medium);
    transition: all 0.15s ease;
  }

  .switcher-option:hover {
    color: var(--text-primary);
    background: var(--bg-tertiary);
  }

  .switcher-option.active {
    background: var(--bg-primary);
    color: var(--text-primary);
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  }

  .switcher-option.disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .switcher-option.disabled:hover {
    color: var(--text-secondary);
    background: transparent;
  }
</style>
