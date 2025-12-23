<script lang="ts">
  import { getCurrentPath, navigate } from './lib/router.svelte'
  import { initAuth, getAuthState } from './lib/auth.svelte'
  import { initServerConfig } from './lib/serverConfig.svelte'
  import { initI18n, _ } from './lib/i18n'
  import { isLoading as i18nLoading } from 'svelte-i18n'
  import Login from './routes/Login.svelte'
  import Register from './routes/Register.svelte'
  import RegisterPasskey from './routes/RegisterPasskey.svelte'
  import Verify from './routes/Verify.svelte'
  import ResetPassword from './routes/ResetPassword.svelte'
  import RecoverPasskey from './routes/RecoverPasskey.svelte'
  import RequestPasskeyRecovery from './routes/RequestPasskeyRecovery.svelte'
  import Dashboard from './routes/Dashboard.svelte'
  import AppPasswords from './routes/AppPasswords.svelte'
  import InviteCodes from './routes/InviteCodes.svelte'
  import Settings from './routes/Settings.svelte'
  import Sessions from './routes/Sessions.svelte'
  import Comms from './routes/Comms.svelte'
  import RepoExplorer from './routes/RepoExplorer.svelte'
  import Admin from './routes/Admin.svelte'
  import OAuthConsent from './routes/OAuthConsent.svelte'
  import OAuthLogin from './routes/OAuthLogin.svelte'
  import OAuthAccounts from './routes/OAuthAccounts.svelte'
  import OAuth2FA from './routes/OAuth2FA.svelte'
  import OAuthTotp from './routes/OAuthTotp.svelte'
  import OAuthPasskey from './routes/OAuthPasskey.svelte'
  import OAuthError from './routes/OAuthError.svelte'
  import Security from './routes/Security.svelte'
  import TrustedDevices from './routes/TrustedDevices.svelte'
  import Home from './routes/Home.svelte'

  initI18n()

  const auth = getAuthState()

  let oauthCallbackPending = $state(hasOAuthCallback())

  function hasOAuthCallback(): boolean {
    const params = new URLSearchParams(window.location.search)
    return !!(params.get('code') && params.get('state'))
  }

  $effect(() => {
    initServerConfig()
    initAuth().then(({ oauthLoginCompleted }) => {
      if (oauthLoginCompleted) {
        navigate('/dashboard')
      }
      oauthCallbackPending = false
    })
  })

  function getComponent(path: string) {
    switch (path) {
      case '/login':
        return Login
      case '/register':
        return Register
      case '/register-passkey':
        return RegisterPasskey
      case '/verify':
        return Verify
      case '/reset-password':
        return ResetPassword
      case '/recover-passkey':
        return RecoverPasskey
      case '/request-passkey-recovery':
        return RequestPasskeyRecovery
      case '/dashboard':
        return Dashboard
      case '/app-passwords':
        return AppPasswords
      case '/invite-codes':
        return InviteCodes
      case '/settings':
        return Settings
      case '/sessions':
        return Sessions
      case '/comms':
        return Comms
      case '/repo':
        return RepoExplorer
      case '/admin':
        return Admin
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
      case '/oauth/error':
        return OAuthError
      case '/security':
        return Security
      case '/trusted-devices':
        return TrustedDevices
      default:
        return Home
    }
  }

  let currentPath = $derived(getCurrentPath())
  let CurrentComponent = $derived(getComponent(currentPath))
</script>

<main>
  {#if auth.loading || $i18nLoading || oauthCallbackPending}
    <div class="loading">
      <p>Loading...</p>
    </div>
  {:else}
    <CurrentComponent />
  {/if}
</main>

<style>
  main {
    min-height: 100vh;
  }

  .loading {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    color: var(--text-secondary);
  }
</style>
