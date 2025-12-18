<script lang="ts">
  import { loginWithOAuth, confirmSignup, resendVerification, getAuthState, switchAccount, forgetAccount } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  let submitting = $state(false)
  let pendingVerification = $state<{ did: string } | null>(null)
  let verificationCode = $state('')
  let resendingCode = $state(false)
  let resendMessage = $state<string | null>(null)
  let showNewLogin = $state(false)
  const auth = getAuthState()
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
      resendMessage = 'Verification code resent!'
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
<div class="login-container">
  {#if auth.error}
    <div class="error">{auth.error}</div>
  {/if}
  {#if pendingVerification}
    <h1>Verify Your Account</h1>
    <p class="subtitle">
      Your account needs verification. Enter the code sent to your verification method.
    </p>
    {#if resendMessage}
      <div class="success">{resendMessage}</div>
    {/if}
    <form onsubmit={(e) => { e.preventDefault(); handleVerification(e); }}>
      <div class="field">
        <label for="verification-code">Verification Code</label>
        <input
          id="verification-code"
          type="text"
          bind:value={verificationCode}
          placeholder="Enter 6-digit code"
          disabled={submitting}
          required
          maxlength="6"
          pattern="[0-9]{6}"
          autocomplete="one-time-code"
        />
      </div>
      <button type="submit" disabled={submitting || !verificationCode.trim()}>
        {submitting ? 'Verifying...' : 'Verify Account'}
      </button>
      <button type="button" class="secondary" onclick={handleResendCode} disabled={resendingCode}>
        {resendingCode ? 'Resending...' : 'Resend Code'}
      </button>
      <button type="button" class="tertiary" onclick={backToLogin}>
        Back to Login
      </button>
    </form>
  {:else if auth.savedAccounts.length > 0 && !showNewLogin}
    <h1>Sign In</h1>
    <p class="subtitle">Choose an account</p>
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
            title="Remove from saved accounts"
          >
            ×
          </button>
        </div>
      {/each}
    </div>
    <button type="button" class="secondary add-account" onclick={() => showNewLogin = true}>
      Sign in to another account
    </button>
    <p class="register-link">
      Don't have an account? <a href="#/register">Create one</a>
    </p>
  {:else}
    <h1>Sign In</h1>
    <p class="subtitle">Sign in to manage your PDS account</p>
    {#if auth.savedAccounts.length > 0}
      <button type="button" class="tertiary back-btn" onclick={() => showNewLogin = false}>
        ← Back to saved accounts
      </button>
    {/if}
    <button type="button" class="oauth-btn" onclick={handleOAuthLogin} disabled={submitting || auth.loading}>
      {submitting ? 'Redirecting...' : 'Sign In'}
    </button>
    <p class="forgot-link">
      <a href="#/reset-password">Forgot password?</a>
    </p>
    <p class="register-link">
      Don't have an account? <a href="#/register">Create one</a>
    </p>
  {/if}
</div>
<style>
  .login-container {
    max-width: 400px;
    margin: 4rem auto;
    padding: 2rem;
  }
  h1 {
    margin: 0 0 0.5rem 0;
  }
  .subtitle {
    color: var(--text-secondary);
    margin: 0 0 2rem 0;
  }
  form {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  label {
    font-size: 0.875rem;
    font-weight: 500;
  }
  input {
    padding: 0.75rem;
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    font-size: 1rem;
    background: var(--bg-input);
    color: var(--text-primary);
  }
  input:focus {
    outline: none;
    border-color: var(--accent);
  }
  button {
    padding: 0.75rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    margin-top: 0.5rem;
  }
  button:hover:not(:disabled) {
    background: var(--accent-hover);
  }
  button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  button.secondary {
    background: transparent;
    color: var(--accent);
    border: 1px solid var(--accent);
  }
  button.secondary:hover:not(:disabled) {
    background: var(--accent);
    color: white;
  }
  button.tertiary {
    background: transparent;
    color: var(--text-secondary);
    border: none;
  }
  button.tertiary:hover:not(:disabled) {
    color: var(--text-primary);
  }
  .oauth-btn {
    width: 100%;
    padding: 1rem;
    font-size: 1.125rem;
    font-weight: 500;
  }
  .error {
    padding: 0.75rem;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: 4px;
    color: var(--error-text);
  }
  .success {
    padding: 0.75rem;
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    border-radius: 4px;
    color: var(--success-text);
  }
  .forgot-link {
    text-align: center;
    margin-top: 1rem;
    margin-bottom: 0;
    color: var(--text-secondary);
  }
  .forgot-link a {
    color: var(--accent);
  }
  .register-link {
    text-align: center;
    margin-top: 0.5rem;
    color: var(--text-secondary);
  }
  .register-link a {
    color: var(--accent);
  }
  .saved-accounts {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }
  .account-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    cursor: pointer;
    text-align: left;
    width: 100%;
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  .account-item:hover:not(.disabled) {
    border-color: var(--accent);
    box-shadow: 0 2px 8px rgba(77, 166, 255, 0.15);
  }
  .account-item.disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .account-info {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .account-handle {
    font-weight: 500;
    color: var(--text-primary);
  }
  .account-did {
    font-size: 0.75rem;
    color: var(--text-muted);
    font-family: monospace;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 250px;
  }
  .forget-btn {
    padding: 0.25rem 0.5rem;
    background: transparent;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 1.25rem;
    line-height: 1;
    border-radius: 4px;
    margin: 0;
  }
  .forget-btn:hover {
    background: var(--error-bg);
    color: var(--error-text);
  }
  .add-account {
    width: 100%;
    margin-bottom: 1rem;
  }
  .back-btn {
    margin-bottom: 1rem;
    padding: 0;
  }
</style>
