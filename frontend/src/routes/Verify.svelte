<script lang="ts">
  import { onMount } from 'svelte'
  import { confirmSignup, resendVerification, getAuthState } from '../lib/auth.svelte'
  import { api, ApiError } from '../lib/api'
  import { navigate } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'

  const STORAGE_KEY = 'tranquil_pds_pending_verification'

  interface PendingVerification {
    did: string
    handle: string
    channel: string
  }

  type VerificationMode = 'signup' | 'token'

  let mode = $state<VerificationMode>('signup')
  let pendingVerification = $state<PendingVerification | null>(null)
  let verificationCode = $state('')
  let identifier = $state('')
  let submitting = $state(false)
  let resendingCode = $state(false)
  let error = $state<string | null>(null)
  let resendMessage = $state<string | null>(null)
  let success = $state(false)
  let autoSubmitting = $state(false)
  let successPurpose = $state<string | null>(null)
  let successChannel = $state<string | null>(null)

  const auth = getAuthState()


  function parseQueryParams() {
    const hash = window.location.hash
    const queryIndex = hash.indexOf('?')
    if (queryIndex === -1) return {}

    const queryString = hash.slice(queryIndex + 1)
    const params: Record<string, string> = {}
    for (const pair of queryString.split('&')) {
      const [key, value] = pair.split('=')
      if (key && value) {
        params[decodeURIComponent(key)] = decodeURIComponent(value)
      }
    }
    return params
  }

  onMount(async () => {
    const params = parseQueryParams()

    if (params.token) {
      mode = 'token'
      verificationCode = params.token
      if (params.identifier) {
        identifier = params.identifier
      }
      if (verificationCode && identifier) {
        autoSubmitting = true
        await handleTokenVerification()
        autoSubmitting = false
      }
    } else {
      mode = 'signup'
      const stored = localStorage.getItem(STORAGE_KEY)
      if (stored) {
        try {
          pendingVerification = JSON.parse(stored)
        } catch {
          pendingVerification = null
        }
      }
    }
  })

  $effect(() => {
    if (mode === 'signup' && auth.session) {
      clearPendingVerification()
      navigate('/dashboard')
    }
  })

  function clearPendingVerification() {
    localStorage.removeItem(STORAGE_KEY)
    pendingVerification = null
  }

  async function handleSignupVerification(e: Event) {
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

  async function handleTokenVerification() {
    if (!verificationCode.trim() || !identifier.trim()) return

    submitting = true
    error = null

    try {
      const result = await api.verifyToken(
        verificationCode.trim(),
        identifier.trim(),
        auth.session?.accessJwt
      )
      success = true
      successPurpose = result.purpose
      successChannel = result.channel
    } catch (e: any) {
      if (e instanceof ApiError) {
        if (e.error === 'AuthenticationRequired') {
          error = 'You must be signed in to complete this verification. Please sign in and try again.'
        } else {
          error = e.message
        }
      } else {
        error = 'Verification failed'
      }
    } finally {
      submitting = false
    }
  }

  async function handleResendCode() {
    if (mode === 'signup') {
      if (!pendingVerification || resendingCode) return

      resendingCode = true
      resendMessage = null
      error = null

      try {
        await resendVerification(pendingVerification.did)
        resendMessage = $_('verify.codeResent')
      } catch (e: any) {
        error = e.message || 'Failed to resend code'
      } finally {
        resendingCode = false
      }
    } else {
      if (!identifier.trim() || resendingCode) return

      resendingCode = true
      resendMessage = null
      error = null

      try {
        await api.resendMigrationVerification(identifier.trim())
        resendMessage = $_('verify.codeResentDetail')
      } catch (e: any) {
        error = e.message || 'Failed to resend verification'
      } finally {
        resendingCode = false
      }
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

  function goToNextStep() {
    if (successPurpose === 'migration') {
      navigate('/login')
    } else if (successChannel === 'email') {
      navigate('/settings')
    } else {
      navigate('/comms')
    }
  }
</script>

<div class="verify-page">
  {#if autoSubmitting}
    <div class="loading-container">
      <h1>{$_('verify.verifying')}</h1>
      <p class="subtitle">{$_('verify.pleaseWait')}</p>
    </div>
  {:else if success}
    <div class="success-container">
      <h1>{$_('verify.verified')}</h1>
      {#if successPurpose === 'migration' || successPurpose === 'signup'}
        <p class="subtitle">{$_('verify.channelVerified', { values: { channel: channelLabel(successChannel || '') } })}</p>
        <p class="info-text">{$_('verify.canNowSignIn')}</p>
        <div class="actions">
          <a href="#/login" class="btn">{$_('verify.signIn')}</a>
        </div>
      {:else}
        <p class="subtitle">
          {$_('verify.channelVerified', { values: { channel: channelLabel(successChannel || '') } })}
        </p>
        <div class="actions">
          <button class="btn" onclick={goToNextStep}>{$_('verify.continue')}</button>
        </div>
      {/if}
    </div>
  {:else if mode === 'token'}
    <h1>{$_('verify.tokenTitle')}</h1>
    <p class="subtitle">{$_('verify.tokenSubtitle')}</p>

    {#if error}
      <div class="message error">{error}</div>
    {/if}

    {#if resendMessage}
      <div class="message success">{resendMessage}</div>
    {/if}

    <form onsubmit={(e) => { e.preventDefault(); handleTokenVerification(); }}>
      <div class="field">
        <label for="identifier">{$_('verify.identifierLabel')}</label>
        <input
          id="identifier"
          type="text"
          bind:value={identifier}
          placeholder={$_('verify.identifierPlaceholder')}
          disabled={submitting}
          required
          autocomplete="email"
        />
        <p class="field-help">{$_('verify.identifierHelp')}</p>
      </div>

      <div class="field">
        <label for="verification-code">{$_('verify.codeLabel')}</label>
        <input
          id="verification-code"
          type="text"
          bind:value={verificationCode}
          placeholder={$_('verify.codePlaceholder')}
          disabled={submitting}
          required
          autocomplete="off"
          class="token-input"
        />
        <p class="field-help">{$_('verify.codeHelp')}</p>
      </div>

      <button type="submit" disabled={submitting || !verificationCode.trim() || !identifier.trim()}>
        {submitting ? $_('verify.verifying') : $_('verify.verify')}
      </button>

      <button type="button" class="secondary" onclick={handleResendCode} disabled={resendingCode || !identifier.trim()}>
        {resendingCode ? $_('verify.sending') : $_('verify.resendCode')}
      </button>
    </form>

    <p class="link-text">
      <a href="#/login">{$_('verify.backToLogin')}</a>
    </p>
  {:else if pendingVerification}
    <h1>{$_('verify.title')}</h1>
    <p class="subtitle">
      {$_('verify.subtitle', { values: { channel: channelLabel(pendingVerification.channel) } })}
    </p>
    <p class="handle-info">{$_('verify.verifyingAccount', { values: { handle: pendingVerification.handle } })}</p>

    {#if error}
      <div class="message error">{error}</div>
    {/if}

    {#if resendMessage}
      <div class="message success">{resendMessage}</div>
    {/if}

    <form onsubmit={(e) => { e.preventDefault(); handleSignupVerification(e); }}>
      <div class="field">
        <label for="verification-code">{$_('verify.codeLabel')}</label>
        <input
          id="verification-code"
          type="text"
          bind:value={verificationCode}
          placeholder={$_('verify.codePlaceholder')}
          disabled={submitting}
          required
          autocomplete="off"
          class="token-input"
        />
        <p class="field-help">{$_('verify.codeHelp')}</p>
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

  .field-help {
    font-size: var(--text-xs);
    color: var(--text-secondary);
    margin: var(--space-1) 0 0 0;
  }

  .token-input {
    font-family: var(--font-mono);
    letter-spacing: 0.05em;
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

  .success-container,
  .loading-container {
    text-align: center;
  }

  .success-container .actions {
    justify-content: center;
    margin-top: var(--space-6);
  }

  .success-container .btn {
    flex: none;
    padding: var(--space-4) var(--space-8);
  }
</style>
