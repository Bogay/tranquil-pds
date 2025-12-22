<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import ReauthModal from '../components/ReauthModal.svelte'

  const auth = getAuthState()
  let message = $state<{ type: 'success' | 'error'; text: string } | null>(null)
  let loading = $state(true)
  let totpEnabled = $state(false)
  let hasBackupCodes = $state(false)
  let setupStep = $state<'idle' | 'qr' | 'verify' | 'backup'>('idle')
  let qrBase64 = $state('')
  let totpUri = $state('')
  let verifyCodeRaw = $state('')
  let verifyCode = $derived(verifyCodeRaw.replace(/\s/g, ''))
  let verifyLoading = $state(false)
  let backupCodes = $state<string[]>([])
  let disablePassword = $state('')
  let disableCode = $state('')
  let disableLoading = $state(false)
  let showDisableForm = $state(false)
  let regenPassword = $state('')
  let regenCode = $state('')
  let regenLoading = $state(false)
  let showRegenForm = $state(false)

  interface Passkey {
    id: string
    credentialId: string
    friendlyName: string | null
    createdAt: string
    lastUsed: string | null
  }
  let passkeys = $state<Passkey[]>([])
  let passkeysLoading = $state(true)
  let addingPasskey = $state(false)
  let newPasskeyName = $state('')
  let editingPasskeyId = $state<string | null>(null)
  let editPasskeyName = $state('')

  let hasPassword = $state(true)
  let passwordLoading = $state(true)
  let showRemovePasswordForm = $state(false)
  let removePasswordLoading = $state(false)

  let allowLegacyLogin = $state(true)
  let hasMfa = $state(false)
  let legacyLoginLoading = $state(true)
  let legacyLoginUpdating = $state(false)

  let showReauthModal = $state(false)
  let reauthMethods = $state<string[]>(['password'])
  let pendingAction = $state<(() => Promise<void>) | null>(null)

  $effect(() => {
    if (!auth.loading && !auth.session) {
      navigate('/login')
    }
  })

  $effect(() => {
    if (auth.session) {
      loadTotpStatus()
      loadPasskeys()
      loadPasswordStatus()
      loadLegacyLoginPreference()
    }
  })

  async function loadPasswordStatus() {
    if (!auth.session) return
    passwordLoading = true
    try {
      const status = await api.getPasswordStatus(auth.session.accessJwt)
      hasPassword = status.hasPassword
    } catch {
      hasPassword = true
    } finally {
      passwordLoading = false
    }
  }

  async function loadLegacyLoginPreference() {
    if (!auth.session) return
    legacyLoginLoading = true
    try {
      const pref = await api.getLegacyLoginPreference(auth.session.accessJwt)
      allowLegacyLogin = pref.allowLegacyLogin
      hasMfa = pref.hasMfa
    } catch {
      allowLegacyLogin = true
      hasMfa = false
    } finally {
      legacyLoginLoading = false
    }
  }

  async function handleToggleLegacyLogin() {
    if (!auth.session) return
    legacyLoginUpdating = true
    try {
      const result = await api.updateLegacyLoginPreference(auth.session.accessJwt, !allowLegacyLogin)
      allowLegacyLogin = result.allowLegacyLogin
      showMessage('success', allowLegacyLogin
        ? 'Legacy app login enabled'
        : 'Legacy app login disabled - only OAuth apps can sign in')
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.error === 'ReauthRequired' || e.error === 'MfaVerificationRequired') {
          reauthMethods = e.reauthMethods || ['password']
          pendingAction = handleToggleLegacyLogin
          showReauthModal = true
        } else {
          showMessage('error', e.message)
        }
      } else {
        showMessage('error', 'Failed to update preference')
      }
    } finally {
      legacyLoginUpdating = false
    }
  }

  async function handleRemovePassword() {
    if (!auth.session) return
    removePasswordLoading = true
    try {
      await api.removePassword(auth.session.accessJwt)
      hasPassword = false
      showRemovePasswordForm = false
      showMessage('success', 'Password removed. Your account is now passkey-only.')
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.error === 'ReauthRequired') {
          reauthMethods = e.reauthMethods || ['password']
          pendingAction = handleRemovePassword
          showReauthModal = true
        } else {
          showMessage('error', e.message)
        }
      } else {
        showMessage('error', 'Failed to remove password')
      }
    } finally {
      removePasswordLoading = false
    }
  }

  function handleReauthSuccess() {
    if (pendingAction) {
      pendingAction()
      pendingAction = null
    }
  }

  function handleReauthCancel() {
    pendingAction = null
  }

  async function loadTotpStatus() {
    if (!auth.session) return
    loading = true
    try {
      const status = await api.getTotpStatus(auth.session.accessJwt)
      totpEnabled = status.enabled
      hasBackupCodes = status.hasBackupCodes
    } catch {
      showMessage('error', 'Failed to load TOTP status')
    } finally {
      loading = false
    }
  }

  function showMessage(type: 'success' | 'error', text: string) {
    message = { type, text }
    setTimeout(() => {
      if (message?.text === text) message = null
    }, 5000)
  }

  async function handleStartSetup() {
    if (!auth.session) return
    verifyLoading = true
    try {
      const result = await api.createTotpSecret(auth.session.accessJwt)
      qrBase64 = result.qrBase64
      totpUri = result.uri
      setupStep = 'qr'
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : 'Failed to generate TOTP secret')
    } finally {
      verifyLoading = false
    }
  }

  async function handleVerifySetup(e: Event) {
    e.preventDefault()
    if (!auth.session || !verifyCode) return
    verifyLoading = true
    try {
      const result = await api.enableTotp(auth.session.accessJwt, verifyCode)
      backupCodes = result.backupCodes
      setupStep = 'backup'
      totpEnabled = true
      hasBackupCodes = true
      verifyCodeRaw = ''
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : 'Invalid code. Please try again.')
    } finally {
      verifyLoading = false
    }
  }

  function handleFinishSetup() {
    setupStep = 'idle'
    backupCodes = []
    qrBase64 = ''
    totpUri = ''
    showMessage('success', 'Two-factor authentication enabled successfully')
  }

  async function handleDisable(e: Event) {
    e.preventDefault()
    if (!auth.session || !disablePassword || !disableCode) return
    disableLoading = true
    try {
      await api.disableTotp(auth.session.accessJwt, disablePassword, disableCode)
      totpEnabled = false
      hasBackupCodes = false
      showDisableForm = false
      disablePassword = ''
      disableCode = ''
      showMessage('success', 'Two-factor authentication disabled')
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : 'Failed to disable TOTP')
    } finally {
      disableLoading = false
    }
  }

  async function handleRegenerate(e: Event) {
    e.preventDefault()
    if (!auth.session || !regenPassword || !regenCode) return
    regenLoading = true
    try {
      const result = await api.regenerateBackupCodes(auth.session.accessJwt, regenPassword, regenCode)
      backupCodes = result.backupCodes
      setupStep = 'backup'
      showRegenForm = false
      regenPassword = ''
      regenCode = ''
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : 'Failed to regenerate backup codes')
    } finally {
      regenLoading = false
    }
  }

  function copyBackupCodes() {
    const text = backupCodes.join('\n')
    navigator.clipboard.writeText(text)
    showMessage('success', 'Backup codes copied to clipboard')
  }

  async function loadPasskeys() {
    if (!auth.session) return
    passkeysLoading = true
    try {
      const result = await api.listPasskeys(auth.session.accessJwt)
      passkeys = result.passkeys
    } catch {
      showMessage('error', 'Failed to load passkeys')
    } finally {
      passkeysLoading = false
    }
  }

  async function handleAddPasskey() {
    if (!auth.session) return
    if (!window.PublicKeyCredential) {
      showMessage('error', 'Passkeys are not supported in this browser')
      return
    }
    addingPasskey = true
    try {
      const { options } = await api.startPasskeyRegistration(auth.session.accessJwt, newPasskeyName || undefined)
      const publicKeyOptions = preparePublicKeyOptions(options)
      const credential = await navigator.credentials.create({
        publicKey: publicKeyOptions
      })
      if (!credential) {
        showMessage('error', 'Passkey creation was cancelled')
        return
      }
      const credentialResponse = {
        id: credential.id,
        type: credential.type,
        rawId: arrayBufferToBase64Url((credential as PublicKeyCredential).rawId),
        response: {
          clientDataJSON: arrayBufferToBase64Url((credential as PublicKeyCredential).response.clientDataJSON),
          attestationObject: arrayBufferToBase64Url(((credential as PublicKeyCredential).response as AuthenticatorAttestationResponse).attestationObject),
        },
      }
      await api.finishPasskeyRegistration(auth.session.accessJwt, credentialResponse, newPasskeyName || undefined)
      await loadPasskeys()
      newPasskeyName = ''
      showMessage('success', 'Passkey added successfully')
    } catch (e) {
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        showMessage('error', 'Passkey creation was cancelled')
      } else {
        showMessage('error', e instanceof ApiError ? e.message : 'Failed to add passkey')
      }
    } finally {
      addingPasskey = false
    }
  }

  async function handleDeletePasskey(id: string) {
    if (!auth.session) return
    if (!confirm('Are you sure you want to delete this passkey?')) return
    try {
      await api.deletePasskey(auth.session.accessJwt, id)
      await loadPasskeys()
      showMessage('success', 'Passkey deleted')
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : 'Failed to delete passkey')
    }
  }

  async function handleSavePasskeyName() {
    if (!auth.session || !editingPasskeyId || !editPasskeyName.trim()) return
    try {
      await api.updatePasskey(auth.session.accessJwt, editingPasskeyId, editPasskeyName.trim())
      await loadPasskeys()
      editingPasskeyId = null
      editPasskeyName = ''
      showMessage('success', 'Passkey renamed')
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : 'Failed to rename passkey')
    }
  }

  function startEditPasskey(passkey: Passkey) {
    editingPasskeyId = passkey.id
    editPasskeyName = passkey.friendlyName || ''
  }

  function cancelEditPasskey() {
    editingPasskeyId = null
    editPasskeyName = ''
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

  function formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleDateString()
  }
</script>

<div class="page">
  <header>
    <a href="#/dashboard" class="back">&larr; Dashboard</a>
    <h1>Security Settings</h1>
  </header>

  {#if message}
    <div class="message {message.type}">{message.text}</div>
  {/if}

  {#if loading}
    <div class="loading">Loading...</div>
  {:else}
    <section>
      <h2>Two-Factor Authentication</h2>
      <p class="description">
        Add an extra layer of security to your account using an authenticator app like Google Authenticator, Authy, or 1Password.
      </p>

      {#if setupStep === 'idle'}
        {#if totpEnabled}
          <div class="status enabled">
            <span>Two-factor authentication is <strong>enabled</strong></span>
          </div>

          {#if !showDisableForm && !showRegenForm}
            <div class="totp-actions">
              <button type="button" class="secondary" onclick={() => showRegenForm = true}>
                Regenerate Backup Codes
              </button>
              <button type="button" class="danger-outline" onclick={() => showDisableForm = true}>
                Disable 2FA
              </button>
            </div>
          {/if}

          {#if showRegenForm}
            <form onsubmit={handleRegenerate} class="inline-form">
              <h3>Regenerate Backup Codes</h3>
              <p class="warning-text">This will invalidate all existing backup codes.</p>
              <div class="field">
                <label for="regen-password">Password</label>
                <input
                  id="regen-password"
                  type="password"
                  bind:value={regenPassword}
                  placeholder="Enter your password"
                  disabled={regenLoading}
                  required
                />
              </div>
              <div class="field">
                <label for="regen-code">Authenticator Code</label>
                <input
                  id="regen-code"
                  type="text"
                  bind:value={regenCode}
                  placeholder="6-digit code"
                  disabled={regenLoading}
                  required
                  maxlength="6"
                  pattern="[0-9]{6}"
                  inputmode="numeric"
                />
              </div>
              <div class="actions">
                <button type="button" class="secondary" onclick={() => { showRegenForm = false; regenPassword = ''; regenCode = '' }}>
                  Cancel
                </button>
                <button type="submit" disabled={regenLoading || !regenPassword || regenCode.length !== 6}>
                  {regenLoading ? 'Regenerating...' : 'Regenerate'}
                </button>
              </div>
            </form>
          {/if}

          {#if showDisableForm}
            <form onsubmit={handleDisable} class="inline-form danger-form">
              <h3>Disable Two-Factor Authentication</h3>
              <p class="warning-text">This will make your account less secure.</p>
              <div class="field">
                <label for="disable-password">Password</label>
                <input
                  id="disable-password"
                  type="password"
                  bind:value={disablePassword}
                  placeholder="Enter your password"
                  disabled={disableLoading}
                  required
                />
              </div>
              <div class="field">
                <label for="disable-code">Authenticator Code</label>
                <input
                  id="disable-code"
                  type="text"
                  bind:value={disableCode}
                  placeholder="6-digit code"
                  disabled={disableLoading}
                  required
                  maxlength="6"
                  pattern="[0-9]{6}"
                  inputmode="numeric"
                />
              </div>
              <div class="actions">
                <button type="button" class="secondary" onclick={() => { showDisableForm = false; disablePassword = ''; disableCode = '' }}>
                  Cancel
                </button>
                <button type="submit" class="danger" disabled={disableLoading || !disablePassword || disableCode.length !== 6}>
                  {disableLoading ? 'Disabling...' : 'Disable 2FA'}
                </button>
              </div>
            </form>
          {/if}
        {:else}
          <div class="status disabled">
            <span>Two-factor authentication is <strong>not enabled</strong></span>
          </div>
          <button onclick={handleStartSetup} disabled={verifyLoading}>
            {verifyLoading ? 'Setting up...' : 'Set Up Two-Factor Authentication'}
          </button>
        {/if}
      {:else if setupStep === 'qr'}
        <div class="setup-step">
          <h3>Step 1: Scan QR Code</h3>
          <p>Scan this QR code with your authenticator app:</p>
          <div class="qr-container">
            <img src="data:image/png;base64,{qrBase64}" alt="TOTP QR Code" class="qr-code" />
          </div>
          <details class="manual-entry">
            <summary>Can't scan? Enter manually</summary>
            <code class="secret-code">{totpUri.split('secret=')[1]?.split('&')[0] || ''}</code>
          </details>
          <button onclick={() => setupStep = 'verify'}>
            Next: Verify Code
          </button>
        </div>
      {:else if setupStep === 'verify'}
        <div class="setup-step">
          <h3>Step 2: Verify Setup</h3>
          <p>Enter the 6-digit code from your authenticator app:</p>
          <form onsubmit={handleVerifySetup}>
            <div class="field">
              <input
                type="text"
                bind:value={verifyCodeRaw}
                placeholder="000000"
                disabled={verifyLoading}
                inputmode="numeric"
                class="code-input"
              />
            </div>
            <div class="actions">
              <button type="button" class="secondary" onclick={() => { setupStep = 'qr' }}>
                Back
              </button>
              <button type="submit" disabled={verifyLoading || verifyCode.length !== 6}>
                {verifyLoading ? 'Verifying...' : 'Verify & Enable'}
              </button>
            </div>
          </form>
        </div>
      {:else if setupStep === 'backup'}
        <div class="setup-step">
          <h3>Step 3: Save Backup Codes</h3>
          <p class="warning-text">
            Save these backup codes in a secure location. Each code can only be used once.
            If you lose access to your authenticator app, you'll need these to sign in.
          </p>
          <div class="backup-codes">
            {#each backupCodes as code}
              <code class="backup-code">{code}</code>
            {/each}
          </div>
          <div class="actions">
            <button type="button" class="secondary" onclick={copyBackupCodes}>
              Copy to Clipboard
            </button>
            <button onclick={handleFinishSetup}>
              I've Saved My Codes
            </button>
          </div>
        </div>
      {/if}
    </section>

    <section>
      <h2>Passkeys</h2>
      <p class="description">
        Passkeys are a secure, passwordless way to sign in using biometrics (fingerprint or face), a security key, or your device's screen lock.
      </p>

      {#if passkeysLoading}
        <div class="loading">Loading passkeys...</div>
      {:else}
        {#if passkeys.length > 0}
          <div class="passkey-list">
            {#each passkeys as passkey}
              <div class="passkey-item">
                {#if editingPasskeyId === passkey.id}
                  <div class="passkey-edit">
                    <input
                      type="text"
                      bind:value={editPasskeyName}
                      placeholder="Passkey name"
                      class="passkey-name-input"
                    />
                    <div class="passkey-edit-actions">
                      <button type="button" class="small" onclick={handleSavePasskeyName}>Save</button>
                      <button type="button" class="small secondary" onclick={cancelEditPasskey}>Cancel</button>
                    </div>
                  </div>
                {:else}
                  <div class="passkey-info">
                    <span class="passkey-name">{passkey.friendlyName || 'Unnamed passkey'}</span>
                    <span class="passkey-meta">
                      Added {formatDate(passkey.createdAt)}
                      {#if passkey.lastUsed}
                        &middot; Last used {formatDate(passkey.lastUsed)}
                      {/if}
                    </span>
                  </div>
                  <div class="passkey-actions">
                    <button type="button" class="small secondary" onclick={() => startEditPasskey(passkey)}>
                      Rename
                    </button>
                    {#if hasPassword || passkeys.length > 1}
                      <button type="button" class="small danger-outline" onclick={() => handleDeletePasskey(passkey.id)}>
                        Delete
                      </button>
                    {/if}
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        {:else}
          <div class="status disabled">
            <span>No passkeys registered</span>
          </div>
        {/if}

        <div class="add-passkey">
          <div class="field">
            <label for="passkey-name">Passkey Name (optional)</label>
            <input
              id="passkey-name"
              type="text"
              bind:value={newPasskeyName}
              placeholder="e.g., MacBook Touch ID"
              disabled={addingPasskey}
            />
          </div>
          <button onclick={handleAddPasskey} disabled={addingPasskey}>
            {addingPasskey ? 'Adding Passkey...' : 'Add a Passkey'}
          </button>
        </div>
      {/if}
    </section>

    <section>
      <h2>Password</h2>
      <p class="description">
        Manage your account password. If you have passkeys set up, you can optionally remove your password for a fully passwordless experience.
      </p>

      {#if passwordLoading}
        <div class="loading">Loading...</div>
      {:else if hasPassword}
        <div class="status enabled">
          <span>Password authentication is <strong>enabled</strong></span>
        </div>

        {#if passkeys.length > 0}
          {#if !showRemovePasswordForm}
            <button type="button" class="danger-outline" onclick={() => showRemovePasswordForm = true}>
              Remove Password
            </button>
          {:else}
            <div class="inline-form danger-form">
              <h3>Remove Password</h3>
              <p class="warning-text">
                This will make your account passkey-only. You'll only be able to sign in using your registered passkeys.
                If you lose access to all your passkeys, you can recover your account using your notification channel.
              </p>
              <div class="info-box-inline">
                <strong>Before proceeding:</strong>
                <ul>
                  <li>Make sure you have at least one reliable passkey registered</li>
                  <li>Consider registering passkeys on multiple devices</li>
                  <li>Ensure your recovery notification channel is up to date</li>
                </ul>
              </div>
              <div class="actions">
                <button type="button" class="secondary" onclick={() => showRemovePasswordForm = false}>
                  Cancel
                </button>
                <button type="button" class="danger" onclick={handleRemovePassword} disabled={removePasswordLoading}>
                  {removePasswordLoading ? 'Removing...' : 'Remove Password'}
                </button>
              </div>
            </div>
          {/if}
        {:else}
          <p class="hint">Add at least one passkey before you can remove your password.</p>
        {/if}
      {:else}
        <div class="status passkey-only">
          <span>Your account is <strong>passkey-only</strong></span>
        </div>
        <p class="hint">
          You sign in using passkeys only. If you ever lose access to your passkeys,
          you can recover your account using the "Lost passkey?" link on the login page.
        </p>
      {/if}
    </section>

    <section>
      <h2>Trusted Devices</h2>
      <p class="description">
        Manage devices that can skip two-factor authentication when signing in. Trust is granted for 30 days and automatically extends when you use the device.
      </p>
      <a href="#/trusted-devices" class="section-link">
        Manage Trusted Devices &rarr;
      </a>
    </section>

    {#if hasMfa}
      <section>
        <h2>App Compatibility</h2>
        <p class="description">
          Control whether apps that don't support modern authentication (like the official Bluesky app) can sign in to your account.
        </p>

        {#if legacyLoginLoading}
          <div class="loading">Loading...</div>
        {:else}
          <div class="toggle-row">
            <div class="toggle-info">
              <span class="toggle-label">Allow legacy app login</span>
              <span class="toggle-description">
                {#if allowLegacyLogin}
                  Legacy apps can sign in with just your password, but sensitive actions (like changing your password) will require MFA verification.
                {:else}
                  Only OAuth-compatible apps can sign in. Legacy apps will be blocked.
                {/if}
              </span>
            </div>
            <button
              type="button"
              class="toggle-button {allowLegacyLogin ? 'on' : 'off'}"
              onclick={handleToggleLegacyLogin}
              disabled={legacyLoginUpdating}
            >
              <span class="toggle-slider"></span>
            </button>
          </div>

          {#if totpEnabled}
            <div class="warning-box">
              <strong>Important: Password changes in Bluesky app will fail</strong>
              <p>
                With TOTP enabled, changing your password from the Bluesky app (or other legacy apps) will be blocked.
                To change your password, you have two options:
              </p>
              <ol>
                <li><strong>Change it here:</strong> Use this website's <a href="#/settings">Settings page</a> where you can verify with your authenticator app.</li>
                <li><strong>Verify your session first:</strong> Use the <a href="#/settings">re-authenticate option</a> to verify your Bluesky session with TOTP, then password changes will work temporarily.</li>
              </ol>
            </div>
          {/if}

          <div class="info-box-inline">
            <strong>What are legacy apps?</strong>
            <p>
              Some apps (like the official Bluesky app) use older authentication that only requires your password.
              When you have MFA enabled, these apps bypass your second factor.
              Disabling legacy login forces all apps to use OAuth, which properly enforces MFA.
            </p>
          </div>
        {/if}
      </section>
    {/if}
  {/if}
</div>

<ReauthModal
  bind:show={showReauthModal}
  availableMethods={reauthMethods}
  onSuccess={handleReauthSuccess}
  onCancel={handleReauthCancel}
/>

<style>
  .page {
    max-width: 600px;
    margin: 0 auto;
    padding: 2rem;
  }

  header {
    margin-bottom: 2rem;
  }

  .back {
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 0.875rem;
  }

  .back:hover {
    color: var(--accent);
  }

  h1 {
    margin: 0.5rem 0 0 0;
  }

  .message {
    padding: 0.75rem;
    border-radius: 4px;
    margin-bottom: 1rem;
  }

  .message.success {
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    color: var(--success-text);
  }

  .message.error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-text);
  }

  .loading {
    text-align: center;
    color: var(--text-secondary);
    padding: 2rem;
  }

  section {
    padding: 1.5rem;
    background: var(--bg-secondary);
    border-radius: 8px;
    margin-bottom: 1.5rem;
  }

  section h2 {
    margin: 0 0 0.5rem 0;
    font-size: 1.125rem;
  }

  .description {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin-bottom: 1.5rem;
  }

  .status {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.75rem;
    border-radius: 4px;
    margin-bottom: 1rem;
  }

  .status.enabled {
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    color: var(--success-text);
  }

  .status.disabled {
    background: var(--warning-bg);
    border: 1px solid var(--border-color);
    color: var(--warning-text);
  }

  .totp-actions {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  .field {
    margin-bottom: 1rem;
  }

  label {
    display: block;
    font-size: 0.875rem;
    font-weight: 500;
    margin-bottom: 0.25rem;
  }

  input {
    width: 100%;
    padding: 0.75rem;
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    font-size: 1rem;
    box-sizing: border-box;
    background: var(--bg-input);
    color: var(--text-primary);
  }

  input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .code-input {
    font-size: 1.5rem;
    letter-spacing: 0.5em;
    text-align: center;
    max-width: 200px;
    margin: 0 auto;
    display: block;
  }

  button {
    padding: 0.75rem 1.5rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 1rem;
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
    background: var(--bg-card);
  }

  button.danger {
    background: var(--error-text);
  }

  button.danger:hover:not(:disabled) {
    background: #900;
  }

  button.danger-outline {
    background: transparent;
    color: var(--error-text);
    border: 1px solid var(--error-border);
  }

  button.danger-outline:hover:not(:disabled) {
    background: var(--error-bg);
  }

  .actions {
    display: flex;
    gap: 0.5rem;
    margin-top: 1rem;
  }

  .inline-form {
    margin-top: 1rem;
    padding: 1rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color-light);
    border-radius: 6px;
  }

  .inline-form h3 {
    margin: 0 0 0.5rem 0;
    font-size: 1rem;
  }

  .danger-form {
    border-color: var(--error-border);
    background: var(--error-bg);
  }

  .warning-text {
    color: var(--error-text);
    font-size: 0.875rem;
    margin-bottom: 1rem;
  }

  .setup-step {
    padding: 1rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color-light);
    border-radius: 6px;
  }

  .setup-step h3 {
    margin: 0 0 0.5rem 0;
  }

  .setup-step p {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin-bottom: 1rem;
  }

  .qr-container {
    display: flex;
    justify-content: center;
    margin: 1.5rem 0;
  }

  .qr-code {
    width: 200px;
    height: 200px;
    image-rendering: pixelated;
  }

  .manual-entry {
    margin-bottom: 1rem;
    font-size: 0.875rem;
  }

  .manual-entry summary {
    cursor: pointer;
    color: var(--accent);
  }

  .secret-code {
    display: block;
    margin-top: 0.5rem;
    padding: 0.5rem;
    background: var(--bg-input);
    border-radius: 4px;
    word-break: break-all;
    font-size: 0.75rem;
  }

  .backup-codes {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 0.5rem;
    margin: 1rem 0;
  }

  .backup-code {
    padding: 0.5rem;
    background: var(--bg-input);
    border-radius: 4px;
    text-align: center;
    font-size: 0.875rem;
    font-family: monospace;
  }

  .passkey-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }

  .passkey-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color-light);
    border-radius: 6px;
    gap: 1rem;
  }

  .passkey-info {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    flex: 1;
    min-width: 0;
  }

  .passkey-name {
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .passkey-meta {
    font-size: 0.75rem;
    color: var(--text-secondary);
  }

  .passkey-actions {
    display: flex;
    gap: 0.5rem;
    flex-shrink: 0;
  }

  .passkey-edit {
    display: flex;
    flex: 1;
    gap: 0.5rem;
    align-items: center;
  }

  .passkey-name-input {
    flex: 1;
    padding: 0.5rem;
    font-size: 0.875rem;
  }

  .passkey-edit-actions {
    display: flex;
    gap: 0.25rem;
  }

  button.small {
    padding: 0.375rem 0.75rem;
    font-size: 0.75rem;
  }

  .add-passkey {
    margin-top: 1rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border-color-light);
  }

  .add-passkey .field {
    margin-bottom: 0.75rem;
  }

  .section-link {
    display: inline-block;
    color: var(--accent);
    text-decoration: none;
    font-weight: 500;
  }

  .section-link:hover {
    text-decoration: underline;
  }

  .status.passkey-only {
    background: var(--accent);
    background: linear-gradient(135deg, rgba(77, 166, 255, 0.15), rgba(128, 90, 213, 0.15));
    border: 1px solid var(--accent);
    color: var(--accent);
  }

  .hint {
    font-size: 0.875rem;
    color: var(--text-secondary);
    margin: 0;
  }

  .info-box-inline {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 1rem;
    margin-bottom: 1rem;
    font-size: 0.875rem;
  }

  .info-box-inline strong {
    display: block;
    margin-bottom: 0.5rem;
  }

  .info-box-inline ul {
    margin: 0;
    padding-left: 1.25rem;
    color: var(--text-secondary);
  }

  .info-box-inline li {
    margin-bottom: 0.25rem;
  }

  .info-box-inline p {
    margin: 0;
    color: var(--text-secondary);
  }

  .toggle-row {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1rem;
    padding: 1rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color-light);
    border-radius: 6px;
    margin-bottom: 1rem;
  }

  .toggle-info {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .toggle-label {
    font-weight: 500;
  }

  .toggle-description {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  .toggle-button {
    position: relative;
    width: 50px;
    height: 26px;
    padding: 0;
    border: none;
    border-radius: 13px;
    cursor: pointer;
    transition: background 0.2s;
    flex-shrink: 0;
  }

  .toggle-button.on {
    background: var(--success-text);
  }

  .toggle-button.off {
    background: var(--text-secondary);
  }

  .toggle-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .toggle-slider {
    position: absolute;
    top: 3px;
    width: 20px;
    height: 20px;
    background: white;
    border-radius: 50%;
    transition: left 0.2s;
  }

  .toggle-button.on .toggle-slider {
    left: 27px;
  }

  .toggle-button.off .toggle-slider {
    left: 3px;
  }

  .warning-box {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border, var(--border-color));
    border-left: 4px solid var(--warning-text);
    border-radius: 6px;
    padding: 1rem;
    margin-bottom: 1rem;
  }

  .warning-box strong {
    display: block;
    margin-bottom: 0.5rem;
    color: var(--warning-text);
  }

  .warning-box p {
    margin: 0 0 0.75rem 0;
    font-size: 0.875rem;
    color: var(--text-primary);
  }

  .warning-box ol {
    margin: 0;
    padding-left: 1.25rem;
    font-size: 0.875rem;
  }

  .warning-box li {
    margin-bottom: 0.5rem;
  }

  .warning-box a {
    color: var(--accent);
  }
</style>
