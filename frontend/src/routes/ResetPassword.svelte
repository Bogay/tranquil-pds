<script lang="ts">
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { getAuthState } from '../lib/auth.svelte'
  const auth = getAuthState()
  let email = $state('')
  let token = $state('')
  let newPassword = $state('')
  let confirmPassword = $state('')
  let submitting = $state(false)
  let error = $state<string | null>(null)
  let success = $state<string | null>(null)
  let tokenSent = $state(false)
  $effect(() => {
    if (auth.session) {
      navigate('/dashboard')
    }
  })
  async function handleRequestReset(e: Event) {
    e.preventDefault()
    if (!email) return
    submitting = true
    error = null
    success = null
    try {
      await api.requestPasswordReset(email)
      tokenSent = true
      success = 'Password reset code sent! Check your preferred notification channel.'
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to send reset code'
    } finally {
      submitting = false
    }
  }
  async function handleReset(e: Event) {
    e.preventDefault()
    if (!token || !newPassword || !confirmPassword) return
    if (newPassword !== confirmPassword) {
      error = 'Passwords do not match'
      return
    }
    if (newPassword.length < 8) {
      error = 'Password must be at least 8 characters'
      return
    }
    submitting = true
    error = null
    success = null
    try {
      await api.resetPassword(token, newPassword)
      success = 'Password reset successfully!'
      setTimeout(() => navigate('/login'), 2000)
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to reset password'
    } finally {
      submitting = false
    }
  }
</script>
<div class="reset-container">
  {#if error}
    <div class="message error">{error}</div>
  {/if}
  {#if success}
    <div class="message success">{success}</div>
  {/if}
  {#if tokenSent}
    <h1>Reset Password</h1>
    <p class="subtitle">Enter the code you received and choose a new password.</p>
    <form onsubmit={handleReset}>
      <div class="field">
        <label for="token">Reset Code</label>
        <input
          id="token"
          type="text"
          bind:value={token}
          placeholder="Enter reset code"
          disabled={submitting}
          required
        />
      </div>
      <div class="field">
        <label for="new-password">New Password</label>
        <input
          id="new-password"
          type="password"
          bind:value={newPassword}
          placeholder="At least 8 characters"
          disabled={submitting}
          required
          minlength="8"
        />
      </div>
      <div class="field">
        <label for="confirm-password">Confirm Password</label>
        <input
          id="confirm-password"
          type="password"
          bind:value={confirmPassword}
          placeholder="Confirm new password"
          disabled={submitting}
          required
        />
      </div>
      <button type="submit" disabled={submitting || !token || !newPassword || !confirmPassword}>
        {submitting ? 'Resetting...' : 'Reset Password'}
      </button>
      <button type="button" class="secondary" onclick={() => { tokenSent = false; token = ''; newPassword = ''; confirmPassword = '' }}>
        Request New Code
      </button>
    </form>
  {:else}
    <h1>Forgot Password</h1>
    <p class="subtitle">Enter your handle or email and we'll send you a code to reset your password.</p>
    <form onsubmit={handleRequestReset}>
      <div class="field">
        <label for="email">Handle or Email</label>
        <input
          id="email"
          type="text"
          bind:value={email}
          placeholder="handle or you@example.com"
          disabled={submitting}
          required
        />
      </div>
      <button type="submit" disabled={submitting || !email}>
        {submitting ? 'Sending...' : 'Send Reset Code'}
      </button>
    </form>
  {/if}
  <p class="back-link">
    <a href="#/login">Back to Sign In</a>
  </p>
</div>
<style>
  .reset-container {
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
    color: var(--text-secondary);
    border: 1px solid var(--border-color-light);
  }
  button.secondary:hover:not(:disabled) {
    background: var(--bg-secondary);
  }
  .message {
    padding: 0.75rem;
    border-radius: 4px;
    margin-bottom: 1rem;
  }
  .message.success {
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    color: var(--success-text);
  }
  .message.error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-text);
  }
  .back-link {
    text-align: center;
    margin-top: 1.5rem;
    color: var(--text-secondary);
  }
  .back-link a {
    color: var(--accent);
  }
</style>
