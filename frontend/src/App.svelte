<script lang="ts">
  import { getCurrentPath, navigate } from './lib/router.svelte'
  import { initAuth, getAuthState } from './lib/auth.svelte'
  import { initServerConfig } from './lib/serverConfig.svelte'
  import { initI18n } from './lib/i18n'
  import { isLoading as i18nLoading } from 'svelte-i18n'
  import Toast from './components/Toast.svelte'
  import Login from './routes/Login.svelte'
  import RegisterSso from './routes/RegisterSso.svelte'
  import Verify from './routes/Verify.svelte'
  import ResetPassword from './routes/ResetPassword.svelte'
  import RecoverPasskey from './routes/RecoverPasskey.svelte'
  import RequestPasskeyRecovery from './routes/RequestPasskeyRecovery.svelte'
  import Dashboard from './routes/Dashboard.svelte'
  import OAuthConsent from './routes/OAuthConsent.svelte'
  import OAuthLogin from './routes/OAuthLogin.svelte'
  import OAuthAccounts from './routes/OAuthAccounts.svelte'
  import OAuth2FA from './routes/OAuth2FA.svelte'
  import OAuthTotp from './routes/OAuthTotp.svelte'
  import OAuthPasskey from './routes/OAuthPasskey.svelte'
  import OAuthDelegation from './routes/OAuthDelegation.svelte'
  import OAuthError from './routes/OAuthError.svelte'
  import SsoRegisterComplete from './routes/SsoRegisterComplete.svelte'
  import Register from './routes/Register.svelte'
  import RegisterPassword from './routes/RegisterPassword.svelte'
  import ActAs from './routes/ActAs.svelte'
  import Migration from './routes/Migration.svelte'
  import { _ } from './lib/i18n'
  initI18n()

  const auth = $derived(getAuthState())

  let oauthCallbackPending = $state(hasOAuthCallback())
  let showSpinner = $state(false)
  let loadingTimer: ReturnType<typeof setTimeout> | null = null

  function hasOAuthCallback(): boolean {
    if (window.location.pathname === '/app/migrate') {
      return false
    }
    const params = new URLSearchParams(window.location.search)
    return !!(params.get('code') && params.get('state'))
  }

  $effect(() => {
    loadingTimer = setTimeout(() => {
      showSpinner = true
    }, 5000)

    initServerConfig()
    initAuth().then(({ oauthLoginCompleted }) => {
      if (oauthLoginCompleted) {
        navigate('/dashboard', { replace: true })
      }
      oauthCallbackPending = false
      if (loadingTimer) {
        clearTimeout(loadingTimer)
        loadingTimer = null
      }
    })

    return () => {
      if (loadingTimer) {
        clearTimeout(loadingTimer)
      }
    }
  })

  const isLoading = $derived(
    auth.kind === 'loading' || $i18nLoading || oauthCallbackPending
  )

  $effect(() => {
    if (auth.kind === 'loading') return
    const path = getCurrentPath()
    if (path === '/') {
      if (auth.kind === 'authenticated') {
        navigate('/dashboard', { replace: true })
      } else {
        navigate('/login', { replace: true })
      }
    }
  })

  const dashboardRoutes = new Set([
    '/dashboard',
    '/settings',
    '/security',
    '/sessions',
    '/app-passwords',
    '/comms',
    '/repo',
    '/controllers',
    '/delegation-audit',
    '/invite-codes',
    '/did-document',
    '/admin',
  ])

  function getComponent(path: string) {
    const pathWithoutQuery = path.split('?')[0]
    if (dashboardRoutes.has(pathWithoutQuery)) {
      return Dashboard
    }
    switch (pathWithoutQuery) {
      case '/login':
        return Login
      case '/verify':
        return Verify
      case '/reset-password':
        return ResetPassword
      case '/recover-passkey':
        return RecoverPasskey
      case '/request-passkey-recovery':
        return RequestPasskeyRecovery
      case '/oauth/consent':
        return OAuthConsent
      case '/oauth/login':
        return OAuthLogin
      case '/oauth/accounts':
        return OAuthAccounts
      case '/oauth/2fa':
        return OAuth2FA
      case '/oauth/totp':
        return OAuthTotp
      case '/oauth/passkey':
        return OAuthPasskey
      case '/oauth/delegation':
        return OAuthDelegation
      case '/oauth/error':
        return OAuthError
      case '/oauth/sso-register':
        return SsoRegisterComplete
      case '/register':
      case '/oauth/register':
        return Register
      case '/oauth/register-sso':
        return RegisterSso
      case '/oauth/register-password':
        return RegisterPassword
      case '/act-as':
        return ActAs
      case '/migrate':
        return Migration
      default:
        return Login
    }
  }

  let currentPath = $derived(getCurrentPath())
  let CurrentComponent = $derived(getComponent(currentPath))

</script>

<main>
  {#if isLoading}
    <div class="loading">
      {#if showSpinner}
        <div class="loading-content">
          <div class="spinner"></div>
          <p>{$_('common.loading')}</p>
        </div>
      {/if}
    </div>
  {:else}
    <CurrentComponent />
  {/if}
</main>
<Toast />

<style>
  main {
    min-height: 100vh;
  }

  .loading {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
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
</style>
