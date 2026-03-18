<script lang="ts">
  import {
    loginWithOAuth,
    confirmSignup,
    resendVerification,
    getAuthState,
    switchAccount,
    forgetAccount,
    clearError,
    matchAuthState,
    type SavedAccount,
    type AuthError,
  } from '../lib/auth.svelte'
  import { navigate, routes } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'
  import { isOk, isErr } from '../lib/types/result'
  import { unsafeAsDid, type Did } from '../lib/types/branded'
  import { toast } from '../lib/toast.svelte'

  type PageState =
    | { kind: 'login' }
    | { kind: 'verification'; did: Did }

  let pageState = $state<PageState>({ kind: 'login' })
  let submitting = $state(false)
  let verificationCode = $state('')
  let resendingCode = $state(false)
  let resendMessage = $state<string | null>(null)
  let autoRedirectAttempted = $state(false)

  const auth = $derived(getAuthState())

  function getSavedAccounts(): readonly SavedAccount[] {
    return auth.savedAccounts
  }

  function isLoading(): boolean {
    return auth.kind === 'loading'
  }

  $effect(() => {
    if (auth.kind === 'error') {
      toast.error(auth.error.message)
      clearError()
    }
  })

  $effect(() => {
    const accounts = getSavedAccounts()
    const loading = isLoading()
    const hasError = auth.kind === 'error'

    if (!loading && !hasError && accounts.length === 0 && pageState.kind === 'login' && !autoRedirectAttempted) {
      autoRedirectAttempted = true
      loginWithOAuth()
    }
  })

  async function handleSwitchAccount(did: Did) {
    submitting = true
    const result = await switchAccount(did)
    if (isOk(result)) {
      navigate(routes.dashboard)
    } else {
      submitting = false
    }
  }

  function handleForgetAccount(did: Did, e: Event) {
    e.stopPropagation()
    forgetAccount(did)
  }

  async function handleOAuthLogin() {
    submitting = true
    const result = await loginWithOAuth()
    if (isErr(result)) {
      submitting = false
    }
  }

  async function handleVerification(e: Event) {
    e.preventDefault()
    if (pageState.kind !== 'verification' || !verificationCode.trim()) return

    submitting = true
    const result = await confirmSignup(pageState.did, verificationCode.trim())
    if (isOk(result)) {
      navigate(routes.dashboard)
    } else {
      submitting = false
    }
  }

  async function handleResendCode() {
    if (pageState.kind !== 'verification' || resendingCode) return

    resendingCode = true
    resendMessage = null
    const result = await resendVerification(pageState.did)
    if (isOk(result)) {
      resendMessage = $_('verification.resent')
    }
    resendingCode = false
  }

  function backToLogin() {
    pageState = { kind: 'login' }
    verificationCode = ''
    resendMessage = null
  }

  const savedAccounts = $derived(getSavedAccounts())
  const loading = $derived(isLoading())
</script>

<div class="login-page">
  {#if pageState.kind === 'verification'}
    <header class="page-header">
      <h1>{$_('verification.title')}</h1>
      <p class="subtitle">{$_('verification.subtitle')}</p>
    </header>

    {#if resendMessage}
      <div class="message success">{resendMessage}</div>
    {/if}

    <form onsubmit={(e) => { e.preventDefault(); handleVerification(e); }}>
      <div>
        <label for="verification-code">{$_('verification.codeLabel')}</label>
        <input
          id="verification-code"
          type="text"
          bind:value={verificationCode}
          placeholder={$_('verification.codePlaceholder')}
          disabled={submitting}
          required
          maxlength="6"
          pattern="[0-9]{6}"
          autocomplete="one-time-code"
        />
      </div>
      <div class="actions">
        <button type="submit" disabled={submitting || !verificationCode.trim()}>
          {submitting ? $_('common.verifying') : $_('common.verify')}
        </button>
        <button type="button" class="secondary" onclick={handleResendCode} disabled={resendingCode}>
          {resendingCode ? $_('common.sending') : $_('common.resendCode')}
        </button>
        <button type="button" class="tertiary" onclick={backToLogin}>
          {$_('common.backToLogin')}
        </button>
      </div>
    </form>

  {:else}
    <header class="page-header">
      <h1>{$_('login.title')}</h1>
      {#if savedAccounts.length > 0}
        <p class="subtitle">{$_('login.chooseAccount')}</p>
      {/if}
    </header>

    <div class="login-content">
      {#if savedAccounts.length > 0}
        <div class="saved-accounts" class:grid={savedAccounts.length > 1}>
          {#each savedAccounts as account}
            <div
              class="account-item"
              class:disabled={submitting}
              role="button"
              tabindex="0"
              onclick={() => !submitting && handleSwitchAccount(account.did)}
              onkeydown={(e) => e.key === 'Enter' && !submitting && handleSwitchAccount(account.did)}
            >
              <div class="account-info">
                <span class="account-handle">@{account.handle}</span>
                <span class="account-did">{account.did}</span>
              </div>
              <button
                type="button"
                class="forget-btn"
                onclick={(e) => handleForgetAccount(account.did, e)}
                title={$_('login.removeAccount')}
              >
                &times;
              </button>
            </div>
          {/each}
        </div>

        <p class="or-divider">{$_('login.signInToAnother')}</p>
      {/if}

      <button type="button" class="lg" style="width: 100%" onclick={handleOAuthLogin} disabled={submitting || loading}>
        {submitting ? $_('login.redirecting') : $_('login.button')}
      </button>

      <p class="forgot-links">
        <a href="/app/reset-password">{$_('login.forgotPassword')}</a>
        <span class="separator">&middot;</span>
        <a href="/app/request-passkey-recovery">{$_('login.lostPasskey')}</a>
      </p>

      <p class="link-text">
        {$_('login.noAccount')} <a href="/app/register">{$_('login.createAccount')}</a>
      </p>
    </div>
  {/if}
</div>

