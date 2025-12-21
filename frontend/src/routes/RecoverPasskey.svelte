<script lang="ts">
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'

  let newPassword = $state('')
  let confirmPassword = $state('')
  let submitting = $state(false)
  let error = $state<string | null>(null)
  let success = $state(false)

  function getUrlParams(): { did: string | null; token: string | null } {
    const params = new URLSearchParams(window.location.hash.split('?')[1] || '')
    return {
      did: params.get('did'),
      token: params.get('token'),
    }
  }

  let { did, token } = getUrlParams()

  function validateForm(): string | null {
    if (!newPassword) return 'New password is required'
    if (newPassword.length < 8) return 'Password must be at least 8 characters'
    if (newPassword !== confirmPassword) return 'Passwords do not match'
    return null
  }

  async function handleSubmit(e: Event) {
    e.preventDefault()

    if (!did || !token) {
      error = 'Invalid recovery link. Please request a new one.'
      return
    }

    const validationError = validateForm()
    if (validationError) {
      error = validationError
      return
    }

    submitting = true
    error = null

    try {
      await api.recoverPasskeyAccount(did, token, newPassword)
      success = true
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.error === 'RecoveryLinkExpired') {
          error = 'This recovery link has expired. Please request a new one.'
        } else if (err.error === 'InvalidRecoveryLink') {
          error = 'Invalid recovery link. Please request a new one.'
        } else {
          error = err.message || 'Recovery failed'
        }
      } else if (err instanceof Error) {
        error = err.message || 'Recovery failed'
      } else {
        error = 'Recovery failed'
      }
    } finally {
      submitting = false
    }
  }

  function goToLogin() {
    navigate('/login')
  }

  function requestNewLink() {
    navigate('/login')
  }
</script>

<div class="recover-container">
  {#if !did || !token}
    <h1>Invalid Recovery Link</h1>
    <p class="error-message">
      This recovery link is invalid or has been corrupted. Please request a new recovery email.
    </p>
    <button onclick={requestNewLink}>Go to Login</button>
  {:else if success}
    <div class="success-content">
      <div class="success-icon">&#x2714;</div>
      <h1>Password Set!</h1>
      <p class="success-message">
        Your temporary password has been set. You can now sign in with this password.
      </p>
      <p class="next-steps">
        After signing in, we recommend adding a new passkey in your security settings
        to restore passkey-only authentication.
      </p>
      <button onclick={goToLogin}>Sign In</button>
    </div>
  {:else}
    <h1>Recover Your Account</h1>
    <p class="subtitle">
      Set a temporary password to regain access to your passkey-only account.
    </p>

    {#if error}
      <div class="error">{error}</div>
    {/if}

    <form onsubmit={handleSubmit}>
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
          placeholder="Confirm your password"
          disabled={submitting}
          required
        />
      </div>

      <div class="info-box">
        <strong>What happens next?</strong>
        <p>
          After setting this password, you can sign in and add a new passkey in your security settings.
          Once you have a new passkey, you can optionally remove the temporary password.
        </p>
      </div>

      <button type="submit" disabled={submitting}>
        {submitting ? 'Setting password...' : 'Set Password'}
      </button>
    </form>
  {/if}
</div>

<style>
  .recover-container {
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

  .info-box {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 1rem;
    font-size: 0.875rem;
  }

  .info-box strong {
    display: block;
    margin-bottom: 0.5rem;
  }

  .info-box p {
    margin: 0;
    color: var(--text-secondary);
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

  .error {
    padding: 0.75rem;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: 4px;
    color: var(--error-text);
    margin-bottom: 1rem;
  }

  .error-message {
    color: var(--text-secondary);
    margin-bottom: 1.5rem;
  }

  .success-content {
    text-align: center;
  }

  .success-icon {
    font-size: 4rem;
    color: var(--success-text);
    margin-bottom: 1rem;
  }

  .success-message {
    color: var(--text-secondary);
    margin-bottom: 0.5rem;
  }

  .next-steps {
    color: var(--text-muted);
    font-size: 0.875rem;
    margin-bottom: 1.5rem;
  }
</style>
