<script lang="ts">
  import { loginWithOAuth, confirmSignup, resendVerification, getAuthState, switchAccount, forgetAccount } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'

  let submitting = $state(false)
  let pendingVerification = $state<{ did: string } | null>(null)
  let verificationCode = $state('')
  let resendingCode = $state(false)
  let resendMessage = $state<string | null>(null)
  let autoRedirectAttempted = $state(false)
  const auth = getAuthState()

  $effect(() => {
    if (!auth.loading && !auth.error && auth.savedAccounts.length === 0 && !pendingVerification && !autoRedirectAttempted) {
      autoRedirectAttempted = true
      loginWithOAuth()
    }
  })

  async function handleSwitchAccount(did: string) {
    submitting = true
    try {
      await switchAccount(did)
      navigate('/dashboard')
    } catch {
      submitting = false
    }
  }

  function handleForgetAccount(did: string, e: Event) {
    e.stopPropagation()
    forgetAccount(did)
  }

  async function handleOAuthLogin() {
    submitting = true
    try {
      await loginWithOAuth()
    } catch {
      submitting = false
    }
  }

  async function handleVerification(e: Event) {
    e.preventDefault()
    if (!pendingVerification || !verificationCode.trim()) return
    submitting = true
    try {
      await confirmSignup(pendingVerification.did, verificationCode.trim())
      navigate('/dashboard')
    } catch {
      submitting = false
    }
  }

  async function handleResendCode() {
    if (!pendingVerification || resendingCode) return
    resendingCode = true
    resendMessage = null
    try {
      await resendVerification(pendingVerification.did)
      resendMessage = $_('verification.resent')
    } catch {
      resendMessage = null
    } finally {
      resendingCode = false
    }
  }

  function backToLogin() {
    pendingVerification = null
    verificationCode = ''
    resendMessage = null
  }
</script>

<div class="login-page">
  {#if auth.error}
    <div class="message error">{auth.error}</div>
  {/if}

  {#if pendingVerification}
    <header class="page-header">
      <h1>{$_('verification.title')}</h1>
      <p class="subtitle">{$_('verification.subtitle')}</p>
    </header>

    {#if resendMessage}
      <div class="message success">{resendMessage}</div>
    {/if}

    <form onsubmit={(e) => { e.preventDefault(); handleVerification(e); }}>
      <div class="field">
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
          {submitting ? $_('verification.verifying') : $_('verification.verifyButton')}
        </button>
        <button type="button" class="secondary" onclick={handleResendCode} disabled={resendingCode}>
          {resendingCode ? $_('verification.resending') : $_('verification.resendButton')}
        </button>
        <button type="button" class="tertiary" onclick={backToLogin}>
          {$_('verification.backToLogin')}
        </button>
      </div>
    </form>

  {:else}
    <header class="page-header">
      <h1>{$_('login.title')}</h1>
      <p class="subtitle">{auth.savedAccounts.length > 0 ? $_('login.chooseAccount') : $_('login.subtitle')}</p>
    </header>

    <div class="split-layout sidebar-right">
      <div class="main-section">
        {#if auth.savedAccounts.length > 0}
          <div class="saved-accounts">
            {#each auth.savedAccounts as account}
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

        <button type="button" class="oauth-btn" onclick={handleOAuthLogin} disabled={submitting || auth.loading}>
          {submitting ? $_('login.redirecting') : $_('login.button')}
        </button>

        <p class="forgot-links">
          <a href="#/reset-password">{$_('login.forgotPassword')}</a>
          <span class="separator">&middot;</span>
          <a href="#/request-passkey-recovery">{$_('login.lostPasskey')}</a>
        </p>

        <p class="link-text">
          {$_('login.noAccount')} <a href="#/register">{$_('login.createAccount')}</a>
        </p>
      </div>

      <aside class="info-panel">
        {#if auth.savedAccounts.length > 0}
          <h3>{$_('login.infoSavedAccountsTitle')}</h3>
          <p>{$_('login.infoSavedAccountsDesc')}</p>

          <h3>{$_('login.infoNewAccountTitle')}</h3>
          <p>{$_('login.infoNewAccountDesc')}</p>
        {:else}
          <h3>{$_('login.infoSecureSignInTitle')}</h3>
          <p>{$_('login.infoSecureSignInDesc')}</p>

          <h3>{$_('login.infoStaySignedInTitle')}</h3>
          <p>{$_('login.infoStaySignedInDesc')}</p>
        {/if}

        <h3>{$_('login.infoRecoveryTitle')}</h3>
        <p>{$_('login.infoRecoveryDesc')}</p>
      </aside>
    </div>
  {/if}
</div>

<style>
  .login-page {
    max-width: var(--width-lg);
    margin: var(--space-9) auto;
    padding: var(--space-7);
  }

  .page-header {
    margin-bottom: var(--space-6);
  }

  h1 {
    margin: 0 0 var(--space-3) 0;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0;
  }

  .main-section {
    min-width: 0;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    max-width: var(--width-sm);
  }

  .actions {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    margin-top: var(--space-3);
  }

  @media (min-width: 600px) {
    .actions {
      flex-direction: row;
    }

    .actions button {
      flex: 1;
    }
  }

  .oauth-btn {
    width: 100%;
    padding: var(--space-5);
    font-size: var(--text-lg);
  }

  .forgot-links {
    margin-top: var(--space-4);
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .forgot-links a {
    color: var(--accent);
  }

  .separator {
    margin: 0 var(--space-2);
  }

  .link-text {
    margin-top: var(--space-6);
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .link-text a {
    color: var(--accent);
  }

  .saved-accounts {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    margin-bottom: var(--space-5);
  }

  .account-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--space-5);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-xl);
    cursor: pointer;
    transition: border-color var(--transition-normal), box-shadow var(--transition-normal);
  }

  .account-item:hover:not(.disabled) {
    border-color: var(--accent);
    box-shadow: var(--shadow-md);
  }

  .account-item.disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .account-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .account-handle {
    font-weight: var(--font-medium);
    color: var(--text-primary);
  }

  .account-did {
    font-size: var(--text-xs);
    color: var(--text-muted);
    font-family: ui-monospace, monospace;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 250px;
  }

  .forget-btn {
    padding: var(--space-2) var(--space-3);
    background: transparent;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font-size: var(--text-xl);
    line-height: 1;
    border-radius: var(--radius-md);
  }

  .forget-btn:hover {
    background: var(--error-bg);
    color: var(--error-text);
  }

  .or-divider {
    text-align: center;
    color: var(--text-muted);
    font-size: var(--text-sm);
    margin: var(--space-5) 0;
  }
</style>
