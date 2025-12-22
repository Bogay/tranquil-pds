<script lang="ts">
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError, type VerificationChannel, type DidType } from '../lib/api'
  import { getAuthState, confirmSignup, resendVerification } from '../lib/auth.svelte'

  const auth = getAuthState()

  let step = $state<'info' | 'passkey' | 'app-password' | 'verify' | 'success'>('info')
  let handle = $state('')
  let email = $state('')
  let inviteCode = $state('')
  let didType = $state<DidType>('plc')
  let externalDid = $state('')
  let verificationChannel = $state<VerificationChannel>('email')
  let discordId = $state('')
  let telegramUsername = $state('')
  let signalNumber = $state('')
  let passkeyName = $state('')
  let submitting = $state(false)
  let error = $state<string | null>(null)
  let serverInfo = $state<{ availableUserDomains: string[]; inviteCodeRequired: boolean } | null>(null)
  let loadingServerInfo = $state(true)
  let serverInfoLoaded = false

  let setupData = $state<{ did: string; handle: string; setupToken: string } | null>(null)
  let appPasswordResult = $state<{ appPassword: string; appPasswordName: string } | null>(null)
  let appPasswordAcknowledged = $state(false)
  let appPasswordCopied = $state(false)
  let verificationCode = $state('')
  let resendingCode = $state(false)
  let resendMessage = $state<string | null>(null)

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

  function validateInfoStep(): string | null {
    if (!handle.trim()) return 'Handle is required'
    if (handle.includes('.')) return 'Handle cannot contain dots. You can set up a custom domain handle after creating your account.'
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

  function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer)
    let binary = ''
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  }

  function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
    const padded = base64 + '='.repeat((4 - base64.length % 4) % 4)
    const binary = atob(padded)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i)
    }
    return bytes.buffer
  }

  function preparePublicKeyOptions(options: any): PublicKeyCredentialCreationOptions {
    return {
      ...options.publicKey,
      challenge: base64UrlToArrayBuffer(options.publicKey.challenge),
      user: {
        ...options.publicKey.user,
        id: base64UrlToArrayBuffer(options.publicKey.user.id)
      },
      excludeCredentials: options.publicKey.excludeCredentials?.map((cred: any) => ({
        ...cred,
        id: base64UrlToArrayBuffer(cred.id)
      })) || []
    }
  }

  async function handleInfoSubmit(e: Event) {
    e.preventDefault()
    const validationError = validateInfoStep()
    if (validationError) {
      error = validationError
      return
    }

    if (!window.PublicKeyCredential) {
      error = 'Passkeys are not supported in this browser. Please use a different browser or register with a password instead.'
      return
    }

    submitting = true
    error = null

    try {
      const result = await api.createPasskeyAccount({
        handle: handle.trim(),
        email: email.trim() || undefined,
        inviteCode: inviteCode.trim() || undefined,
        didType,
        did: didType === 'web-external' ? externalDid.trim() : undefined,
        verificationChannel,
        discordId: discordId.trim() || undefined,
        telegramUsername: telegramUsername.trim() || undefined,
        signalNumber: signalNumber.trim() || undefined,
      })

      setupData = {
        did: result.did,
        handle: result.handle,
        setupToken: result.setupToken,
      }

      step = 'passkey'
    } catch (err) {
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

  async function handlePasskeyRegistration() {
    if (!setupData) return

    submitting = true
    error = null

    try {
      const { options } = await api.startPasskeyRegistrationForSetup(
        setupData.did,
        setupData.setupToken,
        passkeyName || undefined
      )

      const publicKeyOptions = preparePublicKeyOptions(options)
      const credential = await navigator.credentials.create({
        publicKey: publicKeyOptions
      })

      if (!credential) {
        error = 'Passkey creation was cancelled'
        submitting = false
        return
      }

      const pkCredential = credential as PublicKeyCredential
      const response = pkCredential.response as AuthenticatorAttestationResponse
      const credentialResponse = {
        id: pkCredential.id,
        type: pkCredential.type,
        rawId: arrayBufferToBase64Url(pkCredential.rawId),
        response: {
          clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
          attestationObject: arrayBufferToBase64Url(response.attestationObject),
        },
      }

      const result = await api.completePasskeySetup(
        setupData.did,
        setupData.setupToken,
        credentialResponse,
        passkeyName || undefined
      )

      appPasswordResult = {
        appPassword: result.appPassword,
        appPasswordName: result.appPasswordName,
      }

      step = 'app-password'
    } catch (err) {
      if (err instanceof DOMException && err.name === 'NotAllowedError') {
        error = 'Passkey creation was cancelled'
      } else if (err instanceof ApiError) {
        error = err.message || 'Passkey registration failed'
      } else if (err instanceof Error) {
        error = err.message || 'Passkey registration failed'
      } else {
        error = 'Passkey registration failed'
      }
    } finally {
      submitting = false
    }
  }

  function copyAppPassword() {
    if (appPasswordResult) {
      navigator.clipboard.writeText(appPasswordResult.appPassword)
      appPasswordCopied = true
    }
  }

  function handleFinish() {
    step = 'verify'
  }

  async function handleVerification() {
    if (!setupData || !verificationCode.trim()) return

    submitting = true
    error = null

    try {
      await confirmSignup(setupData.did, verificationCode.trim())
      navigate('/dashboard')
    } catch (err) {
      if (err instanceof ApiError) {
        error = err.message || 'Verification failed'
      } else if (err instanceof Error) {
        error = err.message || 'Verification failed'
      } else {
        error = 'Verification failed'
      }
    } finally {
      submitting = false
    }
  }

  async function handleResendCode() {
    if (!setupData || resendingCode) return

    resendingCode = true
    resendMessage = null
    error = null

    try {
      await resendVerification(setupData.did)
      resendMessage = 'Verification code resent!'
    } catch (err) {
      if (err instanceof ApiError) {
        error = err.message || 'Failed to resend code'
      } else if (err instanceof Error) {
        error = err.message || 'Failed to resend code'
      } else {
        error = 'Failed to resend code'
      }
    } finally {
      resendingCode = false
    }
  }

  function channelLabel(ch: string): string {
    switch (ch) {
      case 'email': return 'Email'
      case 'discord': return 'Discord'
      case 'telegram': return 'Telegram'
      case 'signal': return 'Signal'
      default: return ch
    }
  }

  function goToLogin() {
    navigate('/login')
  }

  let fullHandle = $derived(() => {
    if (!handle.trim()) return ''
    if (handle.includes('.')) return handle.trim()
    const domain = serverInfo?.availableUserDomains?.[0]
    if (domain) return `${handle.trim()}.${domain}`
    return handle.trim()
  })
</script>

<div class="register-passkey-container">
  <h1>Create Passkey Account</h1>
  <p class="subtitle">
    {#if step === 'info'}
      Create an ultra-secure account using a passkey instead of a password.
    {:else if step === 'passkey'}
      Register your passkey to secure your account.
    {:else if step === 'app-password'}
      Save your app password for third-party apps.
    {:else if step === 'verify'}
      Verify your {channelLabel(verificationChannel)} to complete registration.
    {:else}
      Your account has been created successfully!
    {/if}
  </p>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  {#if loadingServerInfo}
    <p class="loading">Loading...</p>
  {:else if step === 'info'}
    <form onsubmit={handleInfoSubmit}>
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
        {#if handle.includes('.')}
          <p class="hint warning">Custom domain handles can be set up after account creation.</p>
        {:else if fullHandle()}
          <p class="hint">Your full handle will be: @{fullHandle()}</p>
        {/if}
      </div>

      <fieldset class="section">
        <legend>Contact Method</legend>
        <p class="section-hint">Choose how you'd like to verify your account and receive notifications.</p>
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

      <fieldset class="section">
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

      <div class="info-box">
        <strong>Why passkey-only?</strong>
        <p>
          Passkey accounts are more secure than password-based accounts because they:
        </p>
        <ul>
          <li>Cannot be phished or stolen in data breaches</li>
          <li>Use hardware-backed cryptographic keys</li>
          <li>Require your biometric or device PIN to use</li>
        </ul>
      </div>

      <button type="submit" disabled={submitting}>
        {submitting ? 'Creating account...' : 'Continue'}
      </button>
    </form>

    <p class="alt-link">
      Want a traditional password? <a href="#/register">Register with password</a>
    </p>
  {:else if step === 'passkey'}
    <div class="passkey-step">
      <div class="field">
        <label for="passkey-name">Passkey Name (optional)</label>
        <input
          id="passkey-name"
          type="text"
          bind:value={passkeyName}
          placeholder="e.g., MacBook Touch ID"
          disabled={submitting}
        />
        <p class="hint">A friendly name to identify this passkey</p>
      </div>

      <div class="passkey-instructions">
        <p>Click the button below to create your passkey. You'll be prompted to use:</p>
        <ul>
          <li>Touch ID or Face ID</li>
          <li>Your device PIN or password</li>
          <li>A security key (if you have one)</li>
        </ul>
      </div>

      <button onclick={handlePasskeyRegistration} disabled={submitting} class="passkey-btn">
        {submitting ? 'Creating Passkey...' : 'Create Passkey'}
      </button>

      <button type="button" class="secondary" onclick={() => step = 'info'} disabled={submitting}>
        Back
      </button>
    </div>
  {:else if step === 'app-password'}
    <div class="app-password-step">
      <div class="warning-box">
        <strong>Important: Save this app password!</strong>
        <p>
          This app password is required to sign into apps that don't support passkeys yet (like bsky.app).
          You will only see this password once.
        </p>
      </div>

      <div class="app-password-display">
        <div class="app-password-label">
          App Password for: <strong>{appPasswordResult?.appPasswordName}</strong>
        </div>
        <code class="app-password-code">{appPasswordResult?.appPassword}</code>
        <button type="button" class="copy-btn" onclick={copyAppPassword}>
          {appPasswordCopied ? 'Copied!' : 'Copy to Clipboard'}
        </button>
      </div>

      <div class="field acknowledge-field">
        <label class="checkbox-label">
          <input
            type="checkbox"
            bind:checked={appPasswordAcknowledged}
          />
          <span>I have saved my app password in a secure location</span>
        </label>
      </div>

      <button onclick={handleFinish} disabled={!appPasswordAcknowledged}>
        Continue
      </button>
    </div>
  {:else if step === 'verify'}
    <div class="verify-step">
      <p class="verify-info">
        We've sent a verification code to your {channelLabel(verificationChannel)}.
        Enter it below to complete your account setup.
      </p>

      {#if resendMessage}
        <div class="success">{resendMessage}</div>
      {/if}

      <form onsubmit={(e) => { e.preventDefault(); handleVerification(); }}>
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
    </div>
  {:else if step === 'success'}
    <div class="success-step">
      <div class="success-icon">&#x2714;</div>
      <h2>Account Created!</h2>
      <p>Your passkey-only account has been created successfully.</p>
      <p class="handle-display">@{setupData?.handle}</p>

      <button onclick={goToLogin}>
        Sign In
      </button>
    </div>
  {/if}
</div>

<style>
  .register-passkey-container {
    max-width: 450px;
    margin: 4rem auto;
    padding: 2rem;
  }

  h1 {
    margin: 0 0 0.5rem 0;
  }

  h2 {
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
    color: var(--warning-text);
  }

  .section {
    border: 1px solid var(--border-color-light);
    border-radius: 6px;
    padding: 1rem;
    margin: 0.5rem 0;
  }

  .section legend {
    font-weight: 600;
    padding: 0 0.5rem;
    color: var(--text-primary);
  }

  .section-hint {
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin: 0 0 1rem 0;
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
    margin: 0 0 0.5rem 0;
    color: var(--text-secondary);
  }

  .info-box ul {
    margin: 0;
    padding-left: 1.25rem;
    color: var(--text-secondary);
  }

  .info-box li {
    margin-bottom: 0.25rem;
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
    color: var(--text-secondary);
    border: 1px solid var(--border-color-light);
  }

  button.secondary:hover:not(:disabled) {
    background: var(--bg-secondary);
  }

  .error {
    padding: 0.75rem;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: 4px;
    color: var(--error-text);
    margin-bottom: 1rem;
  }

  .alt-link {
    text-align: center;
    margin-top: 1.5rem;
    color: var(--text-secondary);
  }

  .alt-link a {
    color: var(--accent);
  }

  .passkey-step {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .passkey-instructions {
    background: var(--bg-secondary);
    border-radius: 6px;
    padding: 1rem;
  }

  .passkey-instructions p {
    margin: 0 0 0.5rem 0;
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .passkey-instructions ul {
    margin: 0;
    padding-left: 1.25rem;
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .passkey-btn {
    padding: 1rem;
    font-size: 1.125rem;
  }

  .app-password-step {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .warning-box {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border, #ffc107);
    border-radius: 6px;
    padding: 1rem;
  }

  .warning-box strong {
    display: block;
    margin-bottom: 0.5rem;
    color: var(--warning-text);
  }

  .warning-box p {
    margin: 0;
    font-size: 0.875rem;
    color: var(--warning-text);
  }

  .app-password-display {
    background: var(--bg-card);
    border: 2px solid var(--accent);
    border-radius: 8px;
    padding: 1.5rem;
    text-align: center;
  }

  .app-password-label {
    font-size: 0.875rem;
    color: var(--text-secondary);
    margin-bottom: 0.75rem;
  }

  .app-password-code {
    display: block;
    font-size: 1.5rem;
    font-family: monospace;
    letter-spacing: 0.1em;
    padding: 1rem;
    background: var(--bg-input);
    border-radius: 4px;
    margin-bottom: 1rem;
    user-select: all;
  }

  .copy-btn {
    margin-top: 0;
    padding: 0.5rem 1rem;
    font-size: 0.875rem;
  }

  .acknowledge-field {
    margin-top: 0;
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
    font-weight: normal;
  }

  .checkbox-label input[type="checkbox"] {
    width: auto;
    padding: 0;
  }

  .success-step {
    text-align: center;
  }

  .success-icon {
    font-size: 4rem;
    color: var(--success-text);
    margin-bottom: 1rem;
  }

  .success-step p {
    color: var(--text-secondary);
  }

  .handle-display {
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--text-primary) !important;
    margin: 1rem 0;
  }

  .verify-step {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .verify-info {
    color: var(--text-secondary);
    margin: 0;
  }

  .success {
    padding: 0.75rem;
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    border-radius: 4px;
    color: var(--success-text);
  }
</style>
