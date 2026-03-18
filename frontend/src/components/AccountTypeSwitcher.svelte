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
