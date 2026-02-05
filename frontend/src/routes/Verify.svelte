<script lang="ts">
  import { onMount } from 'svelte'
  import { confirmSignup, resendVerification, getAuthState } from '../lib/auth.svelte'
  import { api, ApiError } from '../lib/api'
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'
  import type { Session } from '../lib/types/api'
  import { unsafeAsDid, unsafeAsEmail, type Did } from '../lib/types/branded'

  const STORAGE_KEY = 'tranquil_pds_pending_verification'

  interface PendingVerification {
    did: Did
    handle: string
    channel: string
  }

  type VerificationMode = 'signup' | 'token' | 'email-update' | 'email-authorize-success'

  let mode = $state<VerificationMode>('signup')
  let newEmail = $state('')
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
  let tokenFromUrl = $state(false)
  let oauthRequestUri = $state<string | null>(null)
  let telegramBotUsername = $state<string | undefined>(undefined)
  let discordBotUsername = $state<string | undefined>(undefined)
  let discordAppId = $state<string | undefined>(undefined)

  const auth = $derived(getAuthState())

  function getSession(): Session | null {
    return auth.kind === 'authenticated' ? auth.session : null
  }

  const session = $derived(getSession())
  const isTelegram = $derived(pendingVerification?.channel === 'telegram')
  const isDiscord = $derived(pendingVerification?.channel === 'discord')
  const isBotVerified = $derived(isTelegram || isDiscord)

  function parseQueryParams(): Record<string, string> {
    return Object.fromEntries(new URLSearchParams(window.location.search))
  }

  onMount(async () => {
    const params = parseQueryParams()

    if (params.type === 'email-authorize-success') {
      mode = 'email-authorize-success'
      success = true
      successPurpose = 'email-authorize'
    } else if (params.type === 'email-update') {
      mode = 'email-update'
      if (params.token) {
        verificationCode = params.token
        tokenFromUrl = true
      }
    } else if (params.token) {
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
      if (params.request_uri) {
        oauthRequestUri = params.request_uri
      }
      const stored = localStorage.getItem(STORAGE_KEY)
      if (stored) {
        try {
          const parsed = JSON.parse(stored)
          pendingVerification = {
            did: unsafeAsDid(parsed.did),
            handle: parsed.handle,
            channel: parsed.channel,
          }
        } catch {
          pendingVerification = null
        }
      }
      if (!pendingVerification && params.did && params.handle && params.channel) {
        pendingVerification = {
          did: unsafeAsDid(params.did),
          handle: params.handle,
          channel: params.channel,
        }
        localStorage.setItem(STORAGE_KEY, JSON.stringify({
          did: params.did,
          handle: params.handle,
          channel: params.channel,
        }))
      }

      if (pendingVerification?.channel === 'telegram' || pendingVerification?.channel === 'discord') {
        try {
          const serverInfo = await api.describeServer()
          telegramBotUsername = serverInfo.telegramBotUsername
          discordBotUsername = serverInfo.discordBotUsername
          discordAppId = serverInfo.discordAppId
        } catch {
        }
      }
    }
  })

  $effect(() => {
    if (mode === 'signup' && session) {
      clearPendingVerification()
      navigate(routes.dashboard)
    }
  })

  let pollingVerification = false
  $effect(() => {
    if (mode === 'signup' && pendingVerification && (isBotVerified || !verificationCode.trim())) {
      const currentPending = pendingVerification
      const interval = setInterval(async () => {
        if (pollingVerification || (!isBotVerified && verificationCode.trim())) return
        pollingVerification = true
        try {
          const result = await api.checkChannelVerified(currentPending.did, currentPending.channel)
          if (result.verified) {
            clearInterval(interval)
            clearPendingVerification()
            if (oauthRequestUri) {
              navigate(routes.oauthConsent, { params: { request_uri: oauthRequestUri } })
            } else {
              navigate(routes.login)
            }
          }
        } catch {
        } finally {
          pollingVerification = false
        }
      }, 3000)
      return () => clearInterval(interval)
    }
    return undefined
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
      if (oauthRequestUri) {
        navigate(routes.oauthConsent, { params: { request_uri: oauthRequestUri } })
      } else {
        navigate(routes.dashboard)
      }
    } catch (e) {
      error = e instanceof Error ? e.message : 'Verification failed'
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
        session?.accessJwt
      )
      success = true
      successPurpose = result.purpose
      successChannel = result.channel
    } catch (e) {
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

  async function handleEmailUpdate() {
    if (!verificationCode.trim() || !newEmail.trim()) return

    if (!session) {
      error = $_('verify.emailUpdateRequiresAuth')
      return
    }

    submitting = true
    error = null

    try {
      await api.updateEmail(session.accessJwt, newEmail.trim(), verificationCode.trim())
      success = true
      successPurpose = 'email-update'
      successChannel = 'email'
    } catch (e) {
      if (e instanceof ApiError) {
        error = e.message
      } else {
        error = $_('verify.emailUpdateFailed')
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
      } catch (e) {
        error = e instanceof Error ? e.message : 'Failed to resend code'
      } finally {
        resendingCode = false
      }
    } else {
      if (!identifier.trim() || resendingCode) return

      resendingCode = true
      resendMessage = null
      error = null

      try {
        await api.resendMigrationVerification(unsafeAsEmail(identifier.trim()))
        resendMessage = $_('verify.codeResentDetail')
      } catch (e) {
        error = e instanceof Error ? e.message : 'Failed to resend verification'
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
      <h1>{$_('common.verifying')}</h1>
      <p class="subtitle">{$_('verify.pleaseWait')}</p>
    </div>
  {:else if success}
    <div class="success-container">
      <h1>{$_('verify.verified')}</h1>
      {#if successPurpose === 'email-authorize'}
        <p class="subtitle">{$_('verify.emailAuthorizeSuccess')}</p>
        <p class="info-text">{$_('verify.emailAuthorizeInfo')}</p>
      {:else if successPurpose === 'email-update'}
        <p class="subtitle">{$_('verify.emailUpdated')}</p>
        <p class="info-text">{$_('verify.emailUpdatedInfo')}</p>
        <div class="actions">
          <a href="/app/settings" class="btn">{$_('common.backToSettings')}</a>
        </div>
      {:else if successPurpose === 'migration'}
        <p class="subtitle">{$_('verify.channelVerified', { values: { channel: channelLabel(successChannel || '') } })}</p>
        <p class="info-text">{$_('verify.migrationContinue')}</p>
      {:else if successPurpose === 'signup'}
        <p class="subtitle">{$_('verify.channelVerified', { values: { channel: channelLabel(successChannel || '') } })}</p>
        <p class="info-text">{$_('verify.canNowSignIn')}</p>
        <div class="actions">
          <a href="/app/login" class="btn">{$_('verify.signIn')}</a>
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
  {:else if mode === 'email-update'}
    <h1>{$_('verify.emailUpdateTitle')}</h1>
    <p class="subtitle">{$_('verify.emailUpdateSubtitle')}</p>

    {#if !session}
      <div class="message warning">{$_('verify.emailUpdateRequiresAuth')}</div>
      <div class="actions">
        <a href="/app/login" class="btn">{$_('verify.signIn')}</a>
      </div>
    {:else}
      {#if error}
        <div class="message error">{error}</div>
      {/if}

      <form onsubmit={(e) => { e.preventDefault(); handleEmailUpdate(); }}>
        <div class="field">
          <label for="new-email">{$_('verify.newEmailLabel')}</label>
          <input
            id="new-email"
            type="email"
            bind:value={newEmail}
            placeholder={$_('verify.newEmailPlaceholder')}
            disabled={submitting}
            required
            autocomplete="email"
          />
        </div>

        {#if !tokenFromUrl}
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
            <p class="field-help">{$_('verify.emailUpdateCodeHelp')}</p>
          </div>
        {/if}

        <button type="submit" disabled={submitting || !verificationCode.trim() || !newEmail.trim()}>
          {submitting ? $_('verify.updating') : $_('verify.updateEmail')}
        </button>
      </form>

      <p class="link-text">
        <a href="/app/settings">{$_('common.backToSettings')}</a>
      </p>
    {/if}
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
        {submitting ? $_('common.verifying') : $_('common.verify')}
      </button>

      <button type="button" class="secondary" onclick={handleResendCode} disabled={resendingCode || !identifier.trim()}>
        {resendingCode ? $_('common.sending') : $_('common.resendCode')}
      </button>
    </form>

    <p class="link-text">
      <a href="/app/login">{$_('common.backToLogin')}</a>
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

    {#if isTelegram && telegramBotUsername}
      {@const encodedHandle = pendingVerification.handle.replaceAll('.', '_')}
      <div class="bot-hint">
        <p>
          <a href="https://t.me/{telegramBotUsername}?start={encodedHandle}" target="_blank" rel="noopener">{$_('comms.telegramOpenLink')}</a>
        </p>
        <p class="manual-text">
          {$_('comms.telegramStartBot', { values: { botUsername: telegramBotUsername, handle: pendingVerification.handle } })}
        </p>
        <p class="waiting-text">{$_('verify.pleaseWait')}</p>
      </div>
    {:else if isDiscord && discordAppId}
      <div class="bot-hint">
        <p>
          <a href="https://discord.com/users/{discordAppId}" target="_blank" rel="noopener">{$_('comms.discordOpenLink')}</a>
        </p>
        <p class="manual-text">
          {$_('comms.discordStartBot', { values: { botUsername: discordBotUsername ?? 'the bot', handle: pendingVerification.handle } })}
        </p>
        <p class="waiting-text">{$_('verify.pleaseWait')}</p>
      </div>
    {:else}
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

        <div class="form-actions">
          <button type="button" class="secondary" onclick={handleResendCode} disabled={resendingCode}>
            {resendingCode ? $_('common.sending') : $_('common.resendCode')}
          </button>
          <button type="submit" disabled={submitting || !verificationCode.trim()}>
            {submitting ? $_('common.verifying') : $_('common.verify')}
          </button>
        </div>
      </form>
    {/if}

    <p class="link-text">
      <a href="/app/register" onclick={() => clearPendingVerification()}>{$_('verify.startOver')}</a>
    </p>
  {:else}
    <h1>{$_('verify.title')}</h1>
    <p class="subtitle">{$_('verify.noPending')}</p>
    <p class="info-text">{$_('verify.noPendingInfo')}</p>

    <div class="actions">
      <a href="/app/register" class="btn">{$_('verify.createAccount')}</a>
      <a href="/app/login" class="btn secondary">{$_('verify.signIn')}</a>
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

  .form-actions {
    display: flex;
    gap: var(--space-4);
    margin-top: var(--space-4);
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

  .bot-hint {
    padding: var(--space-4);
    background: var(--bg-secondary);
    border-radius: var(--radius-md);
  }

  .bot-hint p {
    margin: 0;
  }

  .bot-hint .manual-text {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin-top: var(--space-1);
  }

  .bot-hint .waiting-text {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin-top: var(--space-2);
  }
</style>
