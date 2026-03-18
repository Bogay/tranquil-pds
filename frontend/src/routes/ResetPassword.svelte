<script lang="ts">
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import { unsafeAsEmail } from '../lib/types/branded'

  let email = $state('')
  let token = $state('')
  let newPassword = $state('')
  let confirmPassword = $state('')
  let submitting = $state(false)
  let error = $state<string | null>(null)
  let success = $state<string | null>(null)
  let tokenSent = $state(false)

  async function handleRequestReset(e: Event) {
    e.preventDefault()
    if (!email) return
    submitting = true
    error = null
    success = null
    try {
      await api.requestPasswordReset(unsafeAsEmail(email))
      tokenSent = true
      success = $_('resetPassword.codeSent')
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
      error = $_('resetPassword.passwordsMismatch')
      return
    }
    if (newPassword.length < 8) {
      error = $_('resetPassword.passwordLength')
      return
    }
    submitting = true
    error = null
    success = null
    try {
      await api.resetPassword(token, newPassword)
      success = $_('resetPassword.success')
      setTimeout(() => navigate(routes.login), 2000)
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to reset password'
    } finally {
      submitting = false
    }
  }
</script>

<div class="reset-page">
  {#if error}
    <div class="message error">{error}</div>
  {/if}
  {#if success}
    <div class="message success">{success}</div>
  {/if}

  {#if tokenSent}
    <h1>{$_('resetPassword.title')}</h1>
    <p class="subtitle">{$_('resetPassword.subtitle')}</p>

    <form onsubmit={handleReset}>
      <div>
        <label for="token">{$_('resetPassword.code')}</label>
        <input
          id="token"
          type="text"
          bind:value={token}
          placeholder={$_('resetPassword.codePlaceholder')}
          disabled={submitting}
          required
        />
      </div>
      <div>
        <label for="new-password">{$_('resetPassword.newPassword')}</label>
        <input
          id="new-password"
          type="password"
          bind:value={newPassword}
          placeholder={$_('resetPassword.newPasswordPlaceholder')}
          disabled={submitting}
          required
          minlength="8"
        />
      </div>
      <div>
        <label for="confirm-password">{$_('resetPassword.confirmPassword')}</label>
        <input
          id="confirm-password"
          type="password"
          bind:value={confirmPassword}
          placeholder={$_('resetPassword.confirmPasswordPlaceholder')}
          disabled={submitting}
          required
        />
      </div>
      <button type="submit" disabled={submitting || !token || !newPassword || !confirmPassword}>
        {submitting ? $_('resetPassword.resetting') : $_('resetPassword.resetButton')}
      </button>
      <button type="button" class="secondary" onclick={() => { tokenSent = false; token = ''; newPassword = ''; confirmPassword = '' }}>
        {$_('resetPassword.requestNewCode')}
      </button>
    </form>
  {:else}
    <h1>{$_('resetPassword.forgotTitle')}</h1>
    <p class="subtitle">{$_('resetPassword.forgotSubtitle')}</p>

    <form onsubmit={handleRequestReset}>
      <div>
        <label for="email">{$_('resetPassword.handleOrEmail')}</label>
        <input
          id="email"
          type="text"
          bind:value={email}
          placeholder={$_('resetPassword.emailPlaceholder')}
          disabled={submitting}
          required
        />
      </div>
      <button type="submit" disabled={submitting || !email}>
        {submitting ? $_('resetPassword.sending') : $_('resetPassword.sendCode')}
      </button>
    </form>
  {/if}

  <p class="link-text">
    <a href="/app/login">{$_('common.backToLogin')}</a>
  </p>
</div>

