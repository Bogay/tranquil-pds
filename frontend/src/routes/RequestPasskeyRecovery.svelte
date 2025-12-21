<script lang="ts">
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'

  let identifier = $state('')
  let submitting = $state(false)
  let error = $state<string | null>(null)
  let success = $state(false)

  async function handleSubmit(e: Event) {
    e.preventDefault()
    submitting = true
    error = null

    try {
      await api.requestPasskeyRecovery(identifier)
      success = true
    } catch (err) {
      if (err instanceof ApiError) {
        error = err.message || 'Failed to send recovery link'
      } else if (err instanceof Error) {
        error = err.message || 'Failed to send recovery link'
      } else {
        error = 'Failed to send recovery link'
      }
    } finally {
      submitting = false
    }
  }
</script>

<div class="recovery-container">
  {#if success}
    <div class="success-content">
      <h1>Recovery Link Sent</h1>
      <p class="subtitle">
        If your account exists and is a passkey-only account, you'll receive a recovery link
        at your preferred notification channel.
      </p>
      <p class="info">
        The link will expire in 1 hour. Check your email, Discord, Telegram, or Signal
        depending on your account settings.
      </p>
      <button onclick={() => navigate('/login')}>Back to Sign In</button>
    </div>
  {:else}
    <h1>Recover Passkey Account</h1>
    <p class="subtitle">
      Lost access to your passkey? Enter your handle or email and we'll send you a recovery link.
    </p>

    {#if error}
      <div class="error">{error}</div>
    {/if}

    <form onsubmit={handleSubmit}>
      <div class="field">
        <label for="identifier">Handle or Email</label>
        <input
          id="identifier"
          type="text"
          bind:value={identifier}
          placeholder="handle or you@example.com"
          disabled={submitting}
          required
        />
      </div>

      <div class="info-box">
        <strong>How it works</strong>
        <p>
          We'll send a secure link to your registered notification channel.
          Click the link to set a temporary password. Then you can sign in
          and add a new passkey.
        </p>
      </div>

      <button type="submit" disabled={submitting || !identifier.trim()}>
        {submitting ? 'Sending...' : 'Send Recovery Link'}
      </button>
    </form>
  {/if}

  <p class="back-link">
    <a href="#/login">Back to Sign In</a>
  </p>
</div>

<style>
  .recovery-container {
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

  .success-content {
    text-align: center;
  }

  .info {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin-bottom: 1.5rem;
  }

  .back-link {
    text-align: center;
    margin-top: 2rem;
  }

  .back-link a {
    color: var(--accent);
    text-decoration: none;
  }

  .back-link a:hover {
    text-decoration: underline;
  }
</style>
