<script lang="ts">
  import { register, confirmSignup, resendVerification, getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError, type VerificationChannel } from '../lib/api'
  let handle = $state('')
  let email = $state('')
  let password = $state('')
  let confirmPassword = $state('')
  let inviteCode = $state('')
  let verificationChannel = $state<VerificationChannel>('email')
  let discordId = $state('')
  let telegramUsername = $state('')
  let signalNumber = $state('')
  let submitting = $state(false)
  let error = $state<string | null>(null)
  let pendingVerification = $state<{ did: string; handle: string; channel: string } | null>(null)
  let verificationCode = $state('')
  let resendingCode = $state(false)
  let resendMessage = $state<string | null>(null)
  let serverInfo = $state<{
    availableUserDomains: string[]
    inviteCodeRequired: boolean
  } | null>(null)
  let loadingServerInfo = $state(true)
  let serverInfoLoaded = false
  const auth = getAuthState()
  $effect(() => {
    if (auth.session) {
      navigate('/dashboard')
    }
  })
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
  function validateForm(): string | null {
    if (!handle.trim()) return 'Handle is required'
    if (!password) return 'Password is required'
    if (password.length < 8) return 'Password must be at least 8 characters'
    if (password !== confirmPassword) return 'Passwords do not match'
    if (serverInfo?.inviteCodeRequired && !inviteCode.trim()) {
      return 'Invite code is required'
    }
    switch (verificationChannel) {
      case 'email':
        if (!email.trim()) return 'Email is required for email verification'
        break
      case 'discord':
        if (!discordId.trim()) return 'Discord ID is required for Discord verification'
        break
      case 'telegram':
        if (!telegramUsername.trim()) return 'Telegram username is required for Telegram verification'
        break
      case 'signal':
        if (!signalNumber.trim()) return 'Phone number is required for Signal verification'
        break
    }
    return null
  }
  async function handleSubmit(e: Event) {
    e.preventDefault()
    console.log('[Register] handleSubmit called')
    const validationError = validateForm()
    if (validationError) {
      console.log('[Register] validation error:', validationError)
      error = validationError
      return
    }
    submitting = true
    error = null
    console.log('[Register] starting registration...')
    try {
      const result = await register({
        handle: handle.trim(),
        email: email.trim(),
        password,
        inviteCode: inviteCode.trim() || undefined,
        verificationChannel,
        discordId: discordId.trim() || undefined,
        telegramUsername: telegramUsername.trim() || undefined,
        signalNumber: signalNumber.trim() || undefined,
      })
      console.log('[Register] registration result:', result)
      if (result.verificationRequired) {
        console.log('[Register] setting pendingVerification')
        pendingVerification = {
          did: result.did,
          handle: result.handle,
          channel: result.verificationChannel,
        }
        console.log('[Register] pendingVerification set to:', pendingVerification)
      } else {
        console.log('[Register] no verification required, navigating to dashboard')
        navigate('/dashboard')
      }
    } catch (err: any) {
      console.error('[Register] error:', err)
      if (err instanceof ApiError) {
        error = err.message || 'Registration failed'
      } else if (err instanceof Error) {
        error = err.message || 'Registration failed'
      } else {
        error = 'Registration failed'
      }
    } finally {
      submitting = false
      console.log('[Register] finished, submitting=false')
    }
  }
  async function handleVerification(e: Event) {
    e.preventDefault()
    if (!pendingVerification || !verificationCode.trim()) return
    submitting = true
    error = null
    try {
      await confirmSignup(pendingVerification.did, verificationCode.trim())
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
  let fullHandle = $derived(() => {
    if (!handle.trim()) return ''
    if (handle.includes('.')) return handle.trim()
    const domain = serverInfo?.availableUserDomains?.[0]
    if (domain) return `${handle.trim()}.${domain}`
    return handle.trim()
  })
  function channelLabel(ch: string): string {
    switch (ch) {
      case 'email': return 'Email'
      case 'discord': return 'Discord'
      case 'telegram': return 'Telegram'
      case 'signal': return 'Signal'
      default: return ch
    }
  }
</script>
<div class="register-container">
  {#if error}
    <div class="error">{error}</div>
  {/if}
  {#if pendingVerification}
    <h1>Verify Your Account</h1>
    <p class="subtitle">
      We've sent a verification code to your {channelLabel(pendingVerification.channel)}.
      Enter it below to complete registration.
    </p>
    {#if resendMessage}
      <div class="success">{resendMessage}</div>
    {/if}
    <form onsubmit={(e) => { e.preventDefault(); handleVerification(e); }}>
      <div class="field">
        <label for="verification-code">Verification Code</label>
        <input
          id="verification-code"
          type="text"
          bind:value={verificationCode}
          placeholder="Enter 6-digit code"
          disabled={submitting}
          required
          maxlength="6"
          inputmode="numeric"
          autocomplete="one-time-code"
        />
      </div>
      <button type="submit" disabled={submitting || !verificationCode.trim()}>
        {submitting ? 'Verifying...' : 'Verify Account'}
      </button>
      <button type="button" class="secondary" onclick={handleResendCode} disabled={resendingCode}>
        {resendingCode ? 'Resending...' : 'Resend Code'}
      </button>
    </form>
  {:else}
    <h1>Create Account</h1>
    <p class="subtitle">Create a new account on this PDS</p>
    {#if loadingServerInfo}
      <p class="loading">Loading...</p>
    {:else}
      <form onsubmit={(e) => { e.preventDefault(); handleSubmit(e); }}>
        <div class="field">
          <label for="handle">Handle</label>
          <input
            id="handle"
            type="text"
            bind:value={handle}
            placeholder="yourname"
            disabled={submitting}
            required
          />
          {#if fullHandle()}
            <p class="hint">Your full handle will be: @{fullHandle()}</p>
          {/if}
        </div>
        <div class="field">
          <label for="password">Password</label>
          <input
            id="password"
            type="password"
            bind:value={password}
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
        <fieldset class="verification-section">
          <legend>Contact Method</legend>
          <p class="section-hint">Choose how you'd like to verify your account and receive notifications. You only need one.</p>
          <div class="field">
            <label for="verification-channel">Verification Method</label>
            <select
              id="verification-channel"
              bind:value={verificationChannel}
              disabled={submitting}
            >
              <option value="email">Email</option>
              <option value="discord">Discord</option>
              <option value="telegram">Telegram</option>
              <option value="signal">Signal</option>
            </select>
          </div>
          {#if verificationChannel === 'email'}
            <div class="field">
              <label for="email">Email Address</label>
              <input
                id="email"
                type="email"
                bind:value={email}
                placeholder="you@example.com"
                disabled={submitting}
                required
              />
            </div>
          {:else if verificationChannel === 'discord'}
            <div class="field">
              <label for="discord-id">Discord User ID</label>
              <input
                id="discord-id"
                type="text"
                bind:value={discordId}
                placeholder="Your Discord user ID"
                disabled={submitting}
                required
              />
              <p class="hint">Your numeric Discord user ID (enable Developer Mode to find it)</p>
            </div>
          {:else if verificationChannel === 'telegram'}
            <div class="field">
              <label for="telegram-username">Telegram Username</label>
              <input
                id="telegram-username"
                type="text"
                bind:value={telegramUsername}
                placeholder="@yourusername"
                disabled={submitting}
                required
              />
            </div>
          {:else if verificationChannel === 'signal'}
            <div class="field">
              <label for="signal-number">Signal Phone Number</label>
              <input
                id="signal-number"
                type="tel"
                bind:value={signalNumber}
                placeholder="+1234567890"
                disabled={submitting}
                required
              />
              <p class="hint">Include country code (e.g., +1 for US)</p>
            </div>
          {/if}
        </fieldset>
        {#if serverInfo?.inviteCodeRequired}
          <div class="field">
            <label for="invite-code">Invite Code <span class="required">*</span></label>
            <input
              id="invite-code"
              type="text"
              bind:value={inviteCode}
              placeholder="Enter your invite code"
              disabled={submitting}
              required
            />
          </div>
        {:else}
          <div class="field optional">
            <label for="invite-code">Invite Code <span class="optional-label">(optional)</span></label>
            <input
              id="invite-code"
              type="text"
              bind:value={inviteCode}
              placeholder="Enter invite code if you have one"
              disabled={submitting}
            />
          </div>
        {/if}
        <button type="submit" disabled={submitting}>
          {submitting ? 'Creating account...' : 'Create Account'}
        </button>
      </form>
      <p class="login-link">
        Already have an account? <a href="#/login">Sign in</a>
      </p>
    {/if}
  {/if}
</div>
<style>
  .register-container {
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
  .loading {
    text-align: center;
    color: var(--text-secondary);
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
  .field.optional {
    opacity: 0.8;
  }
  label {
    font-size: 0.875rem;
    font-weight: 500;
  }
  .required {
    color: var(--error-text);
  }
  .optional-label {
    color: var(--text-secondary);
    font-weight: normal;
  }
  input, select {
    padding: 0.75rem;
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    font-size: 1rem;
    background: var(--bg-input);
    color: var(--text-primary);
  }
  input:focus, select:focus {
    outline: none;
    border-color: var(--accent);
  }
  .hint {
    font-size: 0.75rem;
    color: var(--text-secondary);
    margin: 0.25rem 0 0 0;
  }
  .verification-section {
    border: 1px solid var(--border-color-light);
    border-radius: 6px;
    padding: 1rem;
    margin: 0.5rem 0;
  }
  .verification-section legend {
    font-weight: 600;
    padding: 0 0.5rem;
    color: var(--text-primary);
  }
  .section-hint {
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin: 0 0 1rem 0;
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
    color: var(--accent);
    border: 1px solid var(--accent);
  }
  button.secondary:hover:not(:disabled) {
    background: var(--accent);
    color: white;
  }
  .error {
    padding: 0.75rem;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: 4px;
    color: var(--error-text);
  }
  .success {
    padding: 0.75rem;
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    border-radius: 4px;
    color: var(--success-text);
  }
  .login-link {
    text-align: center;
    margin-top: 1.5rem;
    color: var(--text-secondary);
  }
  .login-link a {
    color: var(--accent);
  }
</style>
