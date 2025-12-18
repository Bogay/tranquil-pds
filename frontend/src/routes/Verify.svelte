<script lang="ts">
  import { confirmSignup, resendVerification, getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'

  const STORAGE_KEY = 'tranquil_pds_pending_verification'

  interface PendingVerification {
    did: string
    handle: string
    channel: string
  }

  let pendingVerification = $state<PendingVerification | null>(null)
  let verificationCode = $state('')
  let submitting = $state(false)
  let resendingCode = $state(false)
  let error = $state<string | null>(null)
  let resendMessage = $state<string | null>(null)

  const auth = getAuthState()

  $effect(() => {
    if (auth.session) {
      clearPendingVerification()
      navigate('/dashboard')
    }
  })

  $effect(() => {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored) {
      try {
        pendingVerification = JSON.parse(stored)
      } catch {
        pendingVerification = null
      }
    }
  })

  function clearPendingVerification() {
    localStorage.removeItem(STORAGE_KEY)
    pendingVerification = null
  }

  async function handleVerification(e: Event) {
    e.preventDefault()
    if (!pendingVerification || !verificationCode.trim()) return

    submitting = true
    error = null

    try {
      await confirmSignup(pendingVerification.did, verificationCode.trim())
      clearPendingVerification()
      navigate('/dashboard')
    } catch (e: any) {
      error = e.message || 'Verification failed'
    } finally {
      submitting = false
    }
  }

  async function handleResendCode() {
    if (!pendingVerification || resendingCode) return

    resendingCode = true
    resendMessage = null
    error = null

    try {
      await resendVerification(pendingVerification.did)
      resendMessage = 'Verification code resent!'
    } catch (e: any) {
      error = e.message || 'Failed to resend code'
    } finally {
      resendingCode = false
    }
  }

  function channelLabel(ch: string): string {
    switch (ch) {
      case 'email': return 'Email'
      case 'discord': return 'Discord'
      case 'telegram': return 'Telegram'
      case 'signal': return 'Signal'
      default: return ch
    }
  }
</script>

<div class="verify-container">
  {#if error}
    <div class="error">{error}</div>
  {/if}

  {#if pendingVerification}
    <h1>Verify Your Account</h1>
    <p class="subtitle">
      We've sent a verification code to your {channelLabel(pendingVerification.channel)}.
      Enter it below to complete registration.
    </p>
    <p class="handle-info">Verifying account: <strong>@{pendingVerification.handle}</strong></p>

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
          inputmode="numeric"
          autocomplete="one-time-code"
        />
      </div>

      <button type="submit" disabled={submitting || !verificationCode.trim()}>
        {submitting ? 'Verifying...' : 'Verify Account'}
      </button>

      <button type="button" class="secondary" onclick={handleResendCode} disabled={resendingCode}>
        {resendingCode ? 'Resending...' : 'Resend Code'}
      </button>
    </form>

    <p class="cancel-link">
      <a href="#/register" onclick={() => clearPendingVerification()}>Start over with a different account</a>
    </p>
  {:else}
    <h1>Account Verification</h1>
    <p class="subtitle">No pending verification found.</p>
    <p class="no-pending-info">
      If you recently created an account and need to verify it, you may need to create a new account.
      If you already verified your account, you can sign in.
    </p>
    <div class="actions">
      <a href="#/register" class="btn">Create Account</a>
      <a href="#/login" class="btn secondary">Sign In</a>
    </div>
  {/if}
</div>

<style>
  .verify-container {
    max-width: 400px;
    margin: 4rem auto;
    padding: 2rem;
  }

  h1 {
    margin: 0 0 0.5rem 0;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0 0 1rem 0;
  }

  .handle-info {
    font-size: 0.9rem;
    color: var(--text-secondary);
    margin: 0 0 1.5rem 0;
  }

  .no-pending-info {
    color: var(--text-secondary);
    margin: 1rem 0 1.5rem 0;
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

  button, .btn {
    padding: 0.75rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    text-decoration: none;
    text-align: center;
    display: inline-block;
  }

  button:hover:not(:disabled), .btn:hover {
    background: var(--accent-hover);
  }

  button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  button.secondary, .btn.secondary {
    background: transparent;
    color: var(--accent);
    border: 1px solid var(--accent);
  }

  button.secondary:hover:not(:disabled), .btn.secondary:hover {
    background: var(--accent);
    color: white;
  }

  .error {
    padding: 0.75rem;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: 4px;
    color: var(--error-text);
    margin-bottom: 1rem;
  }

  .success {
    padding: 0.75rem;
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    border-radius: 4px;
    color: var(--success-text);
    margin-bottom: 1rem;
  }

  .cancel-link {
    text-align: center;
    margin-top: 1.5rem;
    font-size: 0.875rem;
  }

  .cancel-link a {
    color: var(--text-secondary);
  }

  .actions {
    display: flex;
    gap: 1rem;
  }

  .actions .btn {
    flex: 1;
  }
</style>
