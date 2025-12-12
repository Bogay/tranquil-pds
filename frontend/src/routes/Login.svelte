<script lang="ts">
  import { login, confirmSignup, resendVerification, getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { ApiError } from '../lib/api'

  let identifier = $state('')
  let password = $state('')
  let submitting = $state(false)
  let error = $state<string | null>(null)

  let pendingVerification = $state<{ did: string } | null>(null)
  let verificationCode = $state('')
  let resendingCode = $state(false)
  let resendMessage = $state<string | null>(null)

  const auth = getAuthState()

  $effect(() => {
    if (auth.session) {
      navigate('/dashboard')
    }
  })

  async function handleSubmit(e: Event) {
    e.preventDefault()
    if (!identifier || !password) return

    submitting = true
    error = null
    pendingVerification = null

    try {
      await login(identifier, password)
      navigate('/dashboard')
    } catch (e: any) {
      if (e instanceof ApiError && e.error === 'AccountNotVerified') {
        if (e.did) {
          pendingVerification = { did: e.did }
        } else {
          error = 'Account not verified. Please check your verification method for a code.'
        }
      } else {
        error = e.message || 'Login failed'
      }
    } finally {
      submitting = false
    }
  }

  async function handleVerification(e: Event) {
    e.preventDefault()

    if (!pendingVerification || !verificationCode.trim()) return

    submitting = true
    error = null

    try {
      await confirmSignup(pendingVerification.did, verificationCode.trim())
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

  function backToLogin() {
    pendingVerification = null
    verificationCode = ''
    error = null
    resendMessage = null
  }
</script>

<div class="login-container">
  {#if error}
    <div class="error">{error}</div>
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
  {:else}
    <h1>Sign In</h1>
    <p class="subtitle">Sign in to manage your PDS account</p>

    <form onsubmit={(e) => { e.preventDefault(); handleSubmit(e); }}>
      <div class="field">
        <label for="identifier">Handle or Email</label>
        <input
          id="identifier"
          type="text"
          bind:value={identifier}
          placeholder="you.bsky.social or you@example.com"
          disabled={submitting}
          required
        />
      </div>

      <div class="field">
        <label for="password">Password</label>
        <input
          id="password"
          type="password"
          bind:value={password}
          placeholder="Password"
          disabled={submitting}
          required
        />
      </div>

      <button type="submit" disabled={submitting || !identifier || !password}>
        {submitting ? 'Signing in...' : 'Sign In'}
      </button>
    </form>

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

  .register-link {
    text-align: center;
    margin-top: 1.5rem;
    color: var(--text-secondary);
  }

  .register-link a {
    color: var(--accent);
  }
</style>
