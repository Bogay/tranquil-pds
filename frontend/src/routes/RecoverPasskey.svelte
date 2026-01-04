<script lang="ts">
  import { navigate, routes } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import { unsafeAsDid } from '../lib/types/branded'

  let newPassword = $state('')
  let confirmPassword = $state('')
  let submitting = $state(false)
  let error = $state<string | null>(null)
  let success = $state(false)

  function getUrlParams(): { did: string | null; token: string | null } {
    const params = new URLSearchParams(window.location.search)
    return {
      did: params.get('did'),
      token: params.get('token'),
    }
  }

  let { did, token } = getUrlParams()

  function validateForm(): string | null {
    if (!newPassword) return $_('recoverPasskey.validation.passwordRequired')
    if (newPassword.length < 8) return $_('recoverPasskey.validation.passwordLength')
    if (newPassword !== confirmPassword) return $_('recoverPasskey.validation.passwordsMismatch')
    return null
  }

  async function handleSubmit(e: Event) {
    e.preventDefault()

    if (!did || !token) {
      error = $_('recoverPasskey.errors.invalidLink')
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
      await api.recoverPasskeyAccount(unsafeAsDid(did), token, newPassword)
      success = true
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.error === 'RecoveryLinkExpired') {
          error = $_('recoverPasskey.errors.expired')
        } else if (err.error === 'InvalidRecoveryLink') {
          error = $_('recoverPasskey.errors.invalidLink')
        } else {
          error = err.message || $_('common.error')
        }
      } else if (err instanceof Error) {
        error = err.message || $_('common.error')
      } else {
        error = $_('common.error')
      }
    } finally {
      submitting = false
    }
  }

  function goToLogin() {
    navigate(routes.login)
  }

  function requestNewLink() {
    navigate(routes.login)
  }
</script>

<div class="recover-page">
  {#if !did || !token}
    <h1>{$_('recoverPasskey.invalidLinkTitle')}</h1>
    <p class="error-message">{$_('recoverPasskey.invalidLinkMessage')}</p>
    <button onclick={requestNewLink}>{$_('recoverPasskey.goToLogin')}</button>
  {:else if success}
    <div class="success-content">
      <div class="success-icon">&#x2714;</div>
      <h1>{$_('recoverPasskey.successTitle')}</h1>
      <p class="success-message">{$_('recoverPasskey.successMessage')}</p>
      <p class="next-steps">{$_('recoverPasskey.successNextSteps')}</p>
      <button onclick={goToLogin}>{$_('recoverPasskey.signIn')}</button>
    </div>
  {:else}
    <h1>{$_('recoverPasskey.title')}</h1>
    <p class="subtitle">{$_('recoverPasskey.subtitle')}</p>

    {#if error}
      <div class="message error">{error}</div>
    {/if}

    <form onsubmit={handleSubmit}>
      <div class="field">
        <label for="new-password">{$_('recoverPasskey.newPassword')}</label>
        <input
          id="new-password"
          type="password"
          bind:value={newPassword}
          placeholder={$_('recoverPasskey.newPasswordPlaceholder')}
          disabled={submitting}
          required
          minlength="8"
        />
      </div>

      <div class="field">
        <label for="confirm-password">{$_('recoverPasskey.confirmPassword')}</label>
        <input
          id="confirm-password"
          type="password"
          bind:value={confirmPassword}
          placeholder={$_('recoverPasskey.confirmPasswordPlaceholder')}
          disabled={submitting}
          required
        />
      </div>

      <div class="info-box">
        <strong>{$_('recoverPasskey.whatHappensNext')}</strong>
        <p>{$_('recoverPasskey.whatHappensNextDetail')}</p>
      </div>

      <button type="submit" disabled={submitting}>
        {submitting ? $_('recoverPasskey.settingPassword') : $_('recoverPasskey.setPassword')}
      </button>
    </form>
  {/if}
</div>

<style>
  .recover-page {
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

  .error-message {
    color: var(--text-secondary);
    margin-bottom: var(--space-6);
  }

  .success-content {
    text-align: center;
  }

  .success-icon {
    font-size: var(--text-4xl);
    color: var(--success-text);
    margin-bottom: var(--space-4);
  }

  .success-message {
    color: var(--text-secondary);
    margin-bottom: var(--space-3);
  }

  .next-steps {
    color: var(--text-muted);
    font-size: var(--text-sm);
    margin-bottom: var(--space-6);
  }
</style>
