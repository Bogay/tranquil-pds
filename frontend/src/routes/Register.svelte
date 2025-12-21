<script lang="ts">
  import { register, getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError, type VerificationChannel, type DidType } from '../lib/api'

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

  let handleHasDot = $derived(handle.includes('.'))

  function validateForm(): string | null {
    if (!handle.trim()) return 'Handle is required'
    if (handle.includes('.')) return 'Handle cannot contain dots. You can set up a custom domain handle after creating your account.'
    if (!password) return 'Password is required'
    if (password.length < 8) return 'Password must be at least 8 characters'
    if (password !== confirmPassword) return 'Passwords do not match'
    if (serverInfo?.inviteCodeRequired && !inviteCode.trim()) {
      return 'Invite code is required'
    }
    if (didType === 'web-external') {
      if (!externalDid.trim()) return 'External did:web is required'
      if (!externalDid.trim().startsWith('did:web:')) return 'External DID must start with did:web:'
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
<div class="register-container">
  {#if error}
    <div class="error">{error}</div>
  {/if}
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
          {#if handleHasDot}
            <p class="hint warning">Custom domain handles can be set up after account creation in Settings.</p>
          {:else if fullHandle()}
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
        <fieldset class="identity-section">
          <legend>Identity Type</legend>
          <p class="section-hint">Choose how your decentralized identity will be managed.</p>
          <div class="radio-group">
            <label class="radio-label">
              <input
                type="radio"
                name="didType"
                value="plc"
                bind:group={didType}
                disabled={submitting}
              />
              <span class="radio-content">
                <strong>did:plc</strong> (Recommended)
                <span class="radio-hint">Portable identity managed by PLC Directory</span>
              </span>
            </label>
            <label class="radio-label">
              <input
                type="radio"
                name="didType"
                value="web"
                bind:group={didType}
                disabled={submitting}
              />
              <span class="radio-content">
                <strong>did:web</strong>
                <span class="radio-hint">Identity hosted on this PDS (read warning below)</span>
              </span>
            </label>
            <label class="radio-label">
              <input
                type="radio"
                name="didType"
                value="web-external"
                bind:group={didType}
                disabled={submitting}
              />
              <span class="radio-content">
                <strong>did:web (BYOD)</strong>
                <span class="radio-hint">Bring your own domain</span>
              </span>
            </label>
          </div>
          {#if didType === 'web'}
            <div class="did-web-warning">
              <strong>Important: Understand the trade-offs</strong>
              <ul>
                <li><strong>Permanent tie to this PDS:</strong> Your identity will be <code>did:web:yourhandle.{serverInfo?.availableUserDomains?.[0] || 'this-pds.com'}</code>. Even if you migrate to another PDS later, this server must continue hosting your DID document.</li>
                <li><strong>No recovery mechanism:</strong> Unlike did:plc, did:web has no rotation keys. If this PDS goes offline permanently, your identity cannot be recovered.</li>
                <li><strong>We commit to you:</strong> If you migrate away, we will continue serving a minimal DID document pointing to your new PDS. Your identity will remain functional.</li>
                <li><strong>Recommendation:</strong> Choose did:plc unless you have a specific reason to prefer did:web.</li>
              </ul>
            </div>
          {/if}
          {#if didType === 'web-external'}
            <div class="field">
              <label for="external-did">Your did:web</label>
              <input
                id="external-did"
                type="text"
                bind:value={externalDid}
                placeholder="did:web:yourdomain.com"
                disabled={submitting}
                required
              />
              <p class="hint">Your domain must serve a valid DID document at /.well-known/did.json pointing to this PDS</p>
            </div>
          {/if}
        </fieldset>
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
        {/if}
        <button type="submit" disabled={submitting}>
          {submitting ? 'Creating account...' : 'Create Account'}
        </button>
      </form>
      <p class="login-link">
        Already have an account? <a href="#/login">Sign in</a>
      </p>
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
  label {
    font-size: 0.875rem;
    font-weight: 500;
  }
  .required {
    color: var(--error-text);
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
  .hint.warning {
    color: var(--warning-text, #856404);
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
  .identity-section {
    border: 1px solid var(--border-color-light);
    border-radius: 6px;
    padding: 1rem;
    margin: 0.5rem 0;
  }
  .identity-section legend {
    font-weight: 600;
    padding: 0 0.5rem;
    color: var(--text-primary);
  }
  .radio-group {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .radio-label {
    display: flex;
    align-items: flex-start;
    gap: 0.5rem;
    cursor: pointer;
  }
  .radio-label input[type="radio"] {
    margin-top: 0.25rem;
  }
  .radio-content {
    display: flex;
    flex-direction: column;
    gap: 0.125rem;
  }
  .radio-hint {
    font-size: 0.75rem;
    color: var(--text-secondary);
  }
  .section-hint {
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin: 0 0 1rem 0;
  }
  .did-web-warning {
    margin-top: 1rem;
    padding: 1rem;
    background: var(--warning-bg, #fff3cd);
    border: 1px solid var(--warning-border, #ffc107);
    border-radius: 6px;
    font-size: 0.875rem;
  }
  .did-web-warning strong {
    color: var(--warning-text, #856404);
  }
  .did-web-warning ul {
    margin: 0.75rem 0 0 0;
    padding-left: 1.25rem;
  }
  .did-web-warning li {
    margin-bottom: 0.5rem;
    line-height: 1.4;
  }
  .did-web-warning li:last-child {
    margin-bottom: 0;
  }
  .did-web-warning code {
    background: rgba(0, 0, 0, 0.1);
    padding: 0.125rem 0.25rem;
    border-radius: 3px;
    font-size: 0.8rem;
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
