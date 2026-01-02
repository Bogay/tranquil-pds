<script lang="ts">
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'

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

<div class="recovery-page">
  {#if success}
    <div class="success-content">
      <h1>{$_('requestPasskeyRecovery.successTitle')}</h1>
      <p class="subtitle">{$_('requestPasskeyRecovery.successMessage')}</p>
      <p class="info-text">{$_('requestPasskeyRecovery.successInfo')}</p>
      <button onclick={() => navigate('/login')}>{$_('common.backToLogin')}</button>
    </div>
  {:else}
    <h1>{$_('requestPasskeyRecovery.title')}</h1>
    <p class="subtitle">{$_('requestPasskeyRecovery.subtitle')}</p>

    {#if error}
      <div class="message error">{error}</div>
    {/if}

    <form onsubmit={handleSubmit}>
      <div class="field">
        <label for="identifier">{$_('requestPasskeyRecovery.handleOrEmail')}</label>
        <input
          id="identifier"
          type="text"
          bind:value={identifier}
          placeholder={$_('requestPasskeyRecovery.emailPlaceholder')}
          disabled={submitting}
          required
        />
      </div>

      <div class="info-box">
        <strong>{$_('requestPasskeyRecovery.howItWorks')}</strong>
        <p>{$_('requestPasskeyRecovery.howItWorksDetail')}</p>
      </div>

      <button type="submit" disabled={submitting || !identifier.trim()}>
        {submitting ? $_('requestPasskeyRecovery.sending') : $_('requestPasskeyRecovery.sendRecoveryLink')}
      </button>
    </form>
  {/if}

  <p class="link-text">
    <a href="/app/login">{$_('common.backToLogin')}</a>
  </p>
</div>

<style>
  .recovery-page {
    max-width: var(--width-sm);
    margin: var(--space-9) auto;
    padding: var(--space-7);
  }

  h1 {
    margin: 0 0 var(--space-3) 0;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0 0 var(--space-7) 0;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .info-box {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
    font-size: var(--text-sm);
  }

  .info-box strong {
    display: block;
    margin-bottom: var(--space-3);
  }

  .info-box p {
    margin: 0;
    color: var(--text-secondary);
  }

  .success-content {
    text-align: center;
  }

  .info-text {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin-bottom: var(--space-6);
  }

  .link-text {
    text-align: center;
    margin-top: var(--space-7);
  }

  .link-text a {
    color: var(--accent);
  }
</style>
