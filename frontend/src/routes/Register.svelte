<script lang="ts">
  import { register, getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError, type VerificationChannel, type DidType } from '../lib/api'
  import { _ } from '../lib/i18n'

  const STORAGE_KEY = 'tranquil_pds_pending_verification'

  let handle = $state('')
  let email = $state('')
  let password = $state('')
  let confirmPassword = $state('')
  let inviteCode = $state('')
  let verificationChannel = $state<VerificationChannel>('email')
  let discordId = $state('')
  let telegramUsername = $state('')
  let signalNumber = $state('')
  let didType = $state<DidType>('plc')
  let externalDid = $state('')
  let submitting = $state(false)
  let error = $state<string | null>(null)
  let serverInfo = $state<{
    availableUserDomains: string[]
    inviteCodeRequired: boolean
  } | null>(null)
  let loadingServerInfo = $state(true)
  let serverInfoLoaded = false

  const auth = getAuthState()

  $effect(() => {
    if (!serverInfoLoaded) {
      serverInfoLoaded = true
      loadServerInfo()
    }
  })

  async function loadServerInfo() {
    try {
      serverInfo = await api.describeServer()
    } catch (e) {
      console.error('Failed to load server info:', e)
    } finally {
      loadingServerInfo = false
    }
  }

  let handleHasDot = $derived(handle.includes('.'))

  function validateForm(): string | null {
    if (!handle.trim()) return $_('register.validation.handleRequired')
    if (handle.includes('.')) return $_('register.validation.handleNoDots')
    if (!password) return $_('register.validation.passwordRequired')
    if (password.length < 8) return $_('register.validation.passwordLength')
    if (password !== confirmPassword) return $_('register.validation.passwordsMismatch')
    if (serverInfo?.inviteCodeRequired && !inviteCode.trim()) {
      return $_('register.validation.inviteCodeRequired')
    }
    if (didType === 'web-external') {
      if (!externalDid.trim()) return $_('register.validation.externalDidRequired')
      if (!externalDid.trim().startsWith('did:web:')) return $_('register.validation.externalDidFormat')
    }
    switch (verificationChannel) {
      case 'email':
        if (!email.trim()) return $_('register.validation.emailRequired')
        break
      case 'discord':
        if (!discordId.trim()) return $_('register.validation.discordIdRequired')
        break
      case 'telegram':
        if (!telegramUsername.trim()) return $_('register.validation.telegramRequired')
        break
      case 'signal':
        if (!signalNumber.trim()) return $_('register.validation.signalRequired')
        break
    }
    return null
  }

  async function handleSubmit(e: Event) {
    e.preventDefault()
    const validationError = validateForm()
    if (validationError) {
      error = validationError
      return
    }
    submitting = true
    error = null
    try {
      const result = await register({
        handle: handle.trim(),
        email: email.trim(),
        password,
        inviteCode: inviteCode.trim() || undefined,
        didType,
        did: didType === 'web-external' ? externalDid.trim() : undefined,
        verificationChannel,
        discordId: discordId.trim() || undefined,
        telegramUsername: telegramUsername.trim() || undefined,
        signalNumber: signalNumber.trim() || undefined,
      })
      if (result.verificationRequired) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify({
          did: result.did,
          handle: result.handle,
          channel: result.verificationChannel,
        }))
        navigate('/verify')
      } else {
        navigate('/dashboard')
      }
    } catch (err: any) {
      if (err instanceof ApiError) {
        error = err.message || 'Registration failed'
      } else if (err instanceof Error) {
        error = err.message || 'Registration failed'
      } else {
        error = 'Registration failed'
      }
    } finally {
      submitting = false
    }
  }

  let fullHandle = $derived(() => {
    if (!handle.trim()) return ''
    if (handle.includes('.')) return handle.trim()
    const domain = serverInfo?.availableUserDomains?.[0]
    if (domain) return `${handle.trim()}.${domain}`
    return handle.trim()
  })
</script>

<div class="register-page">
  {#if error}
    <div class="message error">{error}</div>
  {/if}

  <h1>{$_('register.title')}</h1>
  <p class="subtitle">{$_('register.subtitle')}</p>

  {#if loadingServerInfo}
    <p class="loading">{$_('common.loading')}</p>
  {:else}
    <form onsubmit={(e) => { e.preventDefault(); handleSubmit(e); }}>
      <div class="field">
        <label for="handle">{$_('register.handle')}</label>
        <input
          id="handle"
          type="text"
          bind:value={handle}
          placeholder={$_('register.handlePlaceholder')}
          disabled={submitting}
          required
        />
        {#if handleHasDot}
          <p class="hint warning">{$_('register.handleDotWarning')}</p>
        {:else if fullHandle()}
          <p class="hint">{$_('register.handleHint', { values: { handle: fullHandle() } })}</p>
        {/if}
      </div>

      <div class="field">
        <label for="password">{$_('register.password')}</label>
        <input
          id="password"
          type="password"
          bind:value={password}
          placeholder={$_('register.passwordPlaceholder')}
          disabled={submitting}
          required
          minlength="8"
        />
      </div>

      <div class="field">
        <label for="confirm-password">{$_('register.confirmPassword')}</label>
        <input
          id="confirm-password"
          type="password"
          bind:value={confirmPassword}
          placeholder={$_('register.confirmPasswordPlaceholder')}
          disabled={submitting}
          required
        />
      </div>

      <fieldset class="section-fieldset">
        <legend>{$_('register.identityType')}</legend>
        <p class="section-hint">{$_('register.identityHint')}</p>

        <div class="radio-group">
          <label class="radio-label">
            <input type="radio" name="didType" value="plc" bind:group={didType} disabled={submitting} />
            <span class="radio-content">
              <strong>{$_('register.didPlc')}</strong> {$_('register.didPlcRecommended')}
              <span class="radio-hint">{$_('register.didPlcHint')}</span>
            </span>
          </label>

          <label class="radio-label">
            <input type="radio" name="didType" value="web" bind:group={didType} disabled={submitting} />
            <span class="radio-content">
              <strong>{$_('register.didWeb')}</strong>
              <span class="radio-hint">{$_('register.didWebHint')}</span>
            </span>
          </label>

          <label class="radio-label">
            <input type="radio" name="didType" value="web-external" bind:group={didType} disabled={submitting} />
            <span class="radio-content">
              <strong>{$_('register.didWebBYOD')}</strong>
              <span class="radio-hint">{$_('register.didWebBYODHint')}</span>
            </span>
          </label>
        </div>

        {#if didType === 'web'}
          <div class="warning-box">
            <strong>{$_('register.didWebWarningTitle')}</strong>
            <ul>
              <li><strong>{$_('register.didWebWarning1')}</strong> {$_('register.didWebWarning1Detail', { values: { did: `did:web:yourhandle.${serverInfo?.availableUserDomains?.[0] || 'this-pds.com'}` } })}</li>
              <li><strong>{$_('register.didWebWarning2')}</strong> {$_('register.didWebWarning2Detail')}</li>
              <li><strong>{$_('register.didWebWarning3')}</strong> {$_('register.didWebWarning3Detail')}</li>
              <li><strong>{$_('register.didWebWarning4')}</strong> {$_('register.didWebWarning4Detail')}</li>
            </ul>
          </div>
        {/if}

        {#if didType === 'web-external'}
          <div class="field">
            <label for="external-did">{$_('register.externalDid')}</label>
            <input
              id="external-did"
              type="text"
              bind:value={externalDid}
              placeholder={$_('register.externalDidPlaceholder')}
              disabled={submitting}
              required
            />
            <p class="hint">{$_('register.externalDidHint')}</p>
          </div>
        {/if}
      </fieldset>

      <fieldset class="section-fieldset">
        <legend>{$_('register.contactMethod')}</legend>
        <p class="section-hint">{$_('register.contactMethodHint')}</p>

        <div class="field">
          <label for="verification-channel">{$_('register.verificationMethod')}</label>
          <select id="verification-channel" bind:value={verificationChannel} disabled={submitting}>
            <option value="email">{$_('register.email')}</option>
            <option value="discord">{$_('register.discord')}</option>
            <option value="telegram">{$_('register.telegram')}</option>
            <option value="signal">{$_('register.signal')}</option>
          </select>
        </div>

        {#if verificationChannel === 'email'}
          <div class="field">
            <label for="email">{$_('register.emailAddress')}</label>
            <input
              id="email"
              type="email"
              bind:value={email}
              placeholder={$_('register.emailPlaceholder')}
              disabled={submitting}
              required
            />
          </div>
        {:else if verificationChannel === 'discord'}
          <div class="field">
            <label for="discord-id">{$_('register.discordId')}</label>
            <input
              id="discord-id"
              type="text"
              bind:value={discordId}
              placeholder={$_('register.discordIdPlaceholder')}
              disabled={submitting}
              required
            />
            <p class="hint">{$_('register.discordIdHint')}</p>
          </div>
        {:else if verificationChannel === 'telegram'}
          <div class="field">
            <label for="telegram-username">{$_('register.telegramUsername')}</label>
            <input
              id="telegram-username"
              type="text"
              bind:value={telegramUsername}
              placeholder={$_('register.telegramUsernamePlaceholder')}
              disabled={submitting}
              required
            />
          </div>
        {:else if verificationChannel === 'signal'}
          <div class="field">
            <label for="signal-number">{$_('register.signalNumber')}</label>
            <input
              id="signal-number"
              type="tel"
              bind:value={signalNumber}
              placeholder={$_('register.signalNumberPlaceholder')}
              disabled={submitting}
              required
            />
            <p class="hint">{$_('register.signalNumberHint')}</p>
          </div>
        {/if}
      </fieldset>

      {#if serverInfo?.inviteCodeRequired}
        <div class="field">
          <label for="invite-code">{$_('register.inviteCode')} <span class="required">{$_('register.inviteCodeRequired')}</span></label>
          <input
            id="invite-code"
            type="text"
            bind:value={inviteCode}
            placeholder={$_('register.inviteCodePlaceholder')}
            disabled={submitting}
            required
          />
        </div>
      {/if}

      <button type="submit" disabled={submitting}>
        {submitting ? $_('register.creating') : $_('register.createButton')}
      </button>
    </form>

    <p class="link-text">
      {$_('register.alreadyHaveAccount')} <a href="#/login">{$_('register.signIn')}</a>
    </p>
    <p class="link-text">
      {$_('register.wantPasswordless')} <a href="#/register-passkey">{$_('register.createPasskeyAccount')}</a>
    </p>
  {/if}
</div>

<style>
  .register-page {
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

  .loading {
    text-align: center;
    color: var(--text-secondary);
  }

  form {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }

  .required {
    color: var(--error-text);
  }

  .section-fieldset {
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
  }

  .section-fieldset legend {
    font-weight: var(--font-semibold);
    padding: 0 var(--space-3);
  }

  .section-hint {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin: 0 0 var(--space-5) 0;
  }

  .radio-group {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .radio-label {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    cursor: pointer;
    font-size: var(--text-base);
    font-weight: var(--font-normal);
    margin-bottom: 0;
  }

  .radio-label input[type="radio"] {
    margin-top: var(--space-1);
    width: auto;
  }

  .radio-content {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .radio-hint {
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .warning-box {
    margin-top: var(--space-5);
    padding: var(--space-5);
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius-lg);
    font-size: var(--text-sm);
  }

  .warning-box strong {
    color: var(--warning-text);
  }

  .warning-box ul {
    margin: var(--space-4) 0 0 0;
    padding-left: var(--space-5);
  }

  .warning-box li {
    margin-bottom: var(--space-3);
    line-height: var(--leading-normal);
  }

  .warning-box li:last-child {
    margin-bottom: 0;
  }

  button[type="submit"] {
    margin-top: var(--space-3);
  }

  .link-text {
    text-align: center;
    margin-top: var(--space-6);
    color: var(--text-secondary);
  }

  .link-text a {
    color: var(--accent);
  }
</style>
