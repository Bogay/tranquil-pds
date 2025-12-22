<script lang="ts">
  import { confirmSignup, resendVerification, getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'

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
      case 'email': return $_('register.email')
      case 'discord': return $_('register.discord')
      case 'telegram': return $_('register.telegram')
      case 'signal': return $_('register.signal')
      default: return ch
    }
  }
</script>

<div class="verify-page">
  {#if error}
    <div class="message error">{error}</div>
  {/if}

  {#if pendingVerification}
    <h1>{$_('verify.title')}</h1>
    <p class="subtitle">
      {$_('verify.subtitle', { values: { channel: channelLabel(pendingVerification.channel) } })}
    </p>
    <p class="handle-info">{$_('verify.verifyingAccount', { values: { handle: pendingVerification.handle } })}</p>

    {#if resendMessage}
      <div class="message success">{resendMessage}</div>
    {/if}

    <form onsubmit={(e) => { e.preventDefault(); handleVerification(e); }}>
      <div class="field">
        <label for="verification-code">{$_('verify.codeLabel')}</label>
        <input
          id="verification-code"
          type="text"
          bind:value={verificationCode}
          placeholder={$_('verify.codePlaceholder')}
          disabled={submitting}
          required
          maxlength="6"
          inputmode="numeric"
          autocomplete="one-time-code"
        />
      </div>

      <button type="submit" disabled={submitting || !verificationCode.trim()}>
        {submitting ? $_('verify.verifying') : $_('verify.verifyButton')}
      </button>

      <button type="button" class="secondary" onclick={handleResendCode} disabled={resendingCode}>
        {resendingCode ? $_('verify.resending') : $_('verify.resendCode')}
      </button>
    </form>

    <p class="link-text">
      <a href="#/register" onclick={() => clearPendingVerification()}>{$_('verify.startOver')}</a>
    </p>
  {:else}
    <h1>{$_('verify.title')}</h1>
    <p class="subtitle">{$_('verify.noPending')}</p>
    <p class="info-text">{$_('verify.noPendingInfo')}</p>

    <div class="actions">
      <a href="#/register" class="btn">{$_('verify.createAccount')}</a>
      <a href="#/login" class="btn secondary">{$_('verify.signIn')}</a>
    </div>
  {/if}
</div>

<style>
  .verify-page {
    max-width: var(--width-sm);
    margin: var(--space-9) auto;
    padding: var(--space-7);
  }

  h1 {
    margin: 0 0 var(--space-3) 0;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0 0 var(--space-4) 0;
  }

  .handle-info {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin: 0 0 var(--space-6) 0;
  }

  .info-text {
    color: var(--text-secondary);
    margin: var(--space-4) 0 var(--space-6) 0;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .link-text {
    text-align: center;
    margin-top: var(--space-6);
    font-size: var(--text-sm);
  }

  .link-text a {
    color: var(--text-secondary);
  }

  .actions {
    display: flex;
    gap: var(--space-4);
  }

  .btn {
    flex: 1;
    display: inline-block;
    padding: var(--space-4);
    background: var(--accent);
    color: var(--text-inverse);
    border: none;
    border-radius: var(--radius-md);
    font-size: var(--text-base);
    font-weight: var(--font-medium);
    cursor: pointer;
    text-decoration: none;
    text-align: center;
  }

  .btn:hover {
    background: var(--accent-hover);
    text-decoration: none;
  }

  .btn.secondary {
    background: transparent;
    color: var(--accent);
    border: 1px solid var(--accent);
  }

  .btn.secondary:hover {
    background: var(--accent);
    color: var(--text-inverse);
  }
</style>
