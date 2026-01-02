<script lang="ts">
  import { getAuthState, getValidToken } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import ReauthModal from '../components/ReauthModal.svelte'
  import { _ } from '../lib/i18n'
  import { formatDate as formatDateUtil } from '../lib/date'

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
        ? $_('security.legacyLoginEnabled')
        : $_('security.legacyLoginDisabled'))
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
        showMessage('error', $_('security.failedToUpdatePreference'))
      }
    } finally {
      legacyLoginUpdating = false
    }
  }

  async function handleRemovePassword() {
    if (!auth.session) return
    removePasswordLoading = true
    try {
      const token = await getValidToken()
      if (!token) {
        showMessage('error', $_('security.sessionExpired'))
        return
      }
      await api.removePassword(token)
      hasPassword = false
      showRemovePasswordForm = false
      showMessage('success', $_('security.passwordRemoved'))
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
        showMessage('error', $_('security.failedToRemovePassword'))
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
      showMessage('error', $_('security.failedToLoadTotpStatus'))
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
    showMessage('success', $_('security.totpEnabledSuccess'))
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
      showMessage('success', $_('security.totpDisabledSuccess'))
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
    showMessage('success', $_('security.backupCodesCopied'))
  }

  async function loadPasskeys() {
    if (!auth.session) return
    passkeysLoading = true
    try {
      const result = await api.listPasskeys(auth.session.accessJwt)
      passkeys = result.passkeys
    } catch {
      showMessage('error', $_('security.failedToLoadPasskeys'))
    } finally {
      passkeysLoading = false
    }
  }

  async function handleAddPasskey() {
    if (!auth.session) return
    if (!window.PublicKeyCredential) {
      showMessage('error', $_('security.passkeysNotSupported'))
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
        showMessage('error', $_('security.passkeyCreationCancelled'))
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
      showMessage('success', $_('security.passkeyAddedSuccess'))
    } catch (e) {
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        showMessage('error', $_('security.passkeyCreationCancelled'))
      } else {
        showMessage('error', e instanceof ApiError ? e.message : 'Failed to add passkey')
      }
    } finally {
      addingPasskey = false
    }
  }

  async function handleDeletePasskey(id: string) {
    if (!auth.session) return
    const passkey = passkeys.find(p => p.id === id)
    const name = passkey?.friendlyName || 'this passkey'
    if (!confirm($_('security.deletePasskeyConfirm', { values: { name } }))) return
    try {
      await api.deletePasskey(auth.session.accessJwt, id)
      await loadPasskeys()
      showMessage('success', $_('security.passkeyDeleted'))
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
      showMessage('success', $_('security.passkeyRenamed'))
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
    return formatDateUtil(dateStr)
  }
</script>

<div class="page">
  <header>
    <a href="/app/dashboard" class="back">{$_('common.backToDashboard')}</a>
    <h1>{$_('security.title')}</h1>
  </header>

  {#if message}
    <div class="message {message.type}">{message.text}</div>
  {/if}

  {#if loading}
    <div class="loading">{$_('common.loading')}</div>
  {:else}
    <div class="sections-grid">
    <section>
      <h2>{$_('security.totp')}</h2>
      <p class="description">
        {$_('security.totpDescription')}
      </p>

      {#if setupStep === 'idle'}
        {#if totpEnabled}
          <div class="status enabled">
            <span>{$_('security.totpEnabled')}</span>
          </div>

          {#if !showDisableForm && !showRegenForm}
            <div class="totp-actions">
              <button type="button" class="secondary" onclick={() => showRegenForm = true}>
                {$_('security.regenerateBackupCodes')}
              </button>
              <button type="button" class="danger-outline" onclick={() => showDisableForm = true}>
                {$_('security.disableTotp')}
              </button>
            </div>
          {/if}

          {#if showRegenForm}
            <form onsubmit={handleRegenerate} class="inline-form">
              <h3>{$_('security.regenerateBackupCodes')}</h3>
              <p class="warning-text">{$_('security.regenerateConfirm')}</p>
              <div class="field">
                <label for="regen-password">{$_('security.password')}</label>
                <input
                  id="regen-password"
                  type="password"
                  bind:value={regenPassword}
                  placeholder={$_('security.enterPassword')}
                  disabled={regenLoading}
                  required
                />
              </div>
              <div class="field">
                <label for="regen-code">{$_('security.totpCode')}</label>
                <input
                  id="regen-code"
                  type="text"
                  bind:value={regenCode}
                  placeholder="{$_('security.totpCodePlaceholder')}"
                  disabled={regenLoading}
                  required
                  maxlength="6"
                  pattern="[0-9]{6}"
                  inputmode="numeric"
                />
              </div>
              <div class="actions">
                <button type="button" class="secondary" onclick={() => { showRegenForm = false; regenPassword = ''; regenCode = '' }}>
                  {$_('common.cancel')}
                </button>
                <button type="submit" disabled={regenLoading || !regenPassword || regenCode.length !== 6}>
                  {regenLoading ? $_('security.regenerating') : $_('security.regenerateBackupCodes')}
                </button>
              </div>
            </form>
          {/if}

          {#if showDisableForm}
            <form onsubmit={handleDisable} class="inline-form danger-form">
              <h3>{$_('security.disableTotp')}</h3>
              <p class="warning-text">{$_('security.disableTotpWarning')}</p>
              <div class="field">
                <label for="disable-password">{$_('security.password')}</label>
                <input
                  id="disable-password"
                  type="password"
                  bind:value={disablePassword}
                  placeholder={$_('security.enterPassword')}
                  disabled={disableLoading}
                  required
                />
              </div>
              <div class="field">
                <label for="disable-code">{$_('security.totpCode')}</label>
                <input
                  id="disable-code"
                  type="text"
                  bind:value={disableCode}
                  placeholder="{$_('security.totpCodePlaceholder')}"
                  disabled={disableLoading}
                  required
                  maxlength="6"
                  pattern="[0-9]{6}"
                  inputmode="numeric"
                />
              </div>
              <div class="actions">
                <button type="button" class="secondary" onclick={() => { showDisableForm = false; disablePassword = ''; disableCode = '' }}>
                  {$_('common.cancel')}
                </button>
                <button type="submit" class="danger" disabled={disableLoading || !disablePassword || disableCode.length !== 6}>
                  {disableLoading ? $_('security.disabling') : $_('security.disableTotp')}
                </button>
              </div>
            </form>
          {/if}
        {:else}
          <div class="status disabled">
            <span>{$_('security.totpDisabled')}</span>
          </div>
          <button onclick={handleStartSetup} disabled={verifyLoading}>
            {$_('security.enableTotp')}
          </button>
        {/if}
      {:else if setupStep === 'qr'}
        <div class="setup-step">
          <h3>{$_('security.totpSetup')}</h3>
          <p>{$_('security.totpSetupInstructions')}</p>
          <div class="qr-container">
            <img src="data:image/png;base64,{qrBase64}" alt="TOTP QR Code" class="qr-code" />
          </div>
          <details class="manual-entry">
            <summary>{$_('security.cantScan')}</summary>
            <code class="secret-code">{totpUri.split('secret=')[1]?.split('&')[0] || ''}</code>
          </details>
          <button onclick={() => setupStep = 'verify'}>
            {$_('security.next')}
          </button>
        </div>
      {:else if setupStep === 'verify'}
        <div class="setup-step">
          <h3>{$_('security.totpSetup')}</h3>
          <p>{$_('security.totpCodePlaceholder')}</p>
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
                {$_('common.back')}
              </button>
              <button type="submit" disabled={verifyLoading || verifyCode.length !== 6}>
                {$_('security.verifyAndEnable')}
              </button>
            </div>
          </form>
        </div>
      {:else if setupStep === 'backup'}
        <div class="setup-step">
          <h3>{$_('security.backupCodes')}</h3>
          <p class="warning-text">
            {$_('security.backupCodesDescription')}
          </p>
          <div class="backup-codes">
            {#each backupCodes as code}
              <code class="backup-code">{code}</code>
            {/each}
          </div>
          <div class="actions">
            <button type="button" class="secondary" onclick={copyBackupCodes}>
              {$_('security.copyToClipboard')}
            </button>
            <button onclick={handleFinishSetup}>
              {$_('security.savedMyCodes')}
            </button>
          </div>
        </div>
      {/if}
    </section>

    <section>
      <h2>{$_('security.passkeys')}</h2>
      <p class="description">
        {$_('security.passkeysDescription')}
      </p>

      {#if passkeysLoading}
        <div class="loading">{$_('security.loadingPasskeys')}</div>
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
                      placeholder="{$_('security.passkeyName')}"
                      class="passkey-name-input"
                    />
                    <div class="passkey-edit-actions">
                      <button type="button" class="small" onclick={handleSavePasskeyName}>{$_('common.save')}</button>
                      <button type="button" class="small secondary" onclick={cancelEditPasskey}>{$_('common.cancel')}</button>
                    </div>
                  </div>
                {:else}
                  <div class="passkey-info">
                    <span class="passkey-name">{passkey.friendlyName || $_('security.unnamedPasskey')}</span>
                    <span class="passkey-meta">
                      {$_('security.added')} {formatDate(passkey.createdAt)}
                      {#if passkey.lastUsed}
                        &middot; {$_('security.lastUsed')} {formatDate(passkey.lastUsed)}
                      {/if}
                    </span>
                  </div>
                  <div class="passkey-actions">
                    <button type="button" class="small secondary" onclick={() => startEditPasskey(passkey)}>
                      {$_('security.rename')}
                    </button>
                    {#if hasPassword || passkeys.length > 1}
                      <button type="button" class="small danger-outline" onclick={() => handleDeletePasskey(passkey.id)}>
                        {$_('security.deletePasskey')}
                      </button>
                    {/if}
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        {:else}
          <div class="status disabled">
            <span>{$_('security.noPasskeys')}</span>
          </div>
        {/if}

        <div class="add-passkey">
          <div class="field">
            <label for="passkey-name">{$_('security.passkeyName')}</label>
            <input
              id="passkey-name"
              type="text"
              bind:value={newPasskeyName}
              placeholder="{$_('security.passkeyNamePlaceholder')}"
              disabled={addingPasskey}
            />
          </div>
          <button onclick={handleAddPasskey} disabled={addingPasskey}>
            {addingPasskey ? $_('security.adding') : $_('security.addPasskey')}
          </button>
        </div>
      {/if}
    </section>

    <section>
      <h2>{$_('security.password')}</h2>
      <p class="description">
        {$_('security.passwordDescription')}
      </p>

      {#if passwordLoading}
        <div class="loading">{$_('common.loading')}</div>
      {:else if hasPassword}
        <div class="status enabled">
          <span>{$_('security.passwordStatus')}</span>
        </div>

        {#if passkeys.length > 0}
          {#if !showRemovePasswordForm}
            <button type="button" class="danger-outline" onclick={() => showRemovePasswordForm = true}>
              {$_('security.removePassword')}
            </button>
          {:else}
            <div class="inline-form danger-form">
              <h3>{$_('security.removePassword')}</h3>
              <p class="warning-text">
                {$_('security.removePasswordWarning')}
              </p>
              <div class="info-box-inline">
                <strong>{$_('security.beforeProceeding')}</strong>
                <ul>
                  <li>{$_('security.beforeProceedingItem1')}</li>
                  <li>{$_('security.beforeProceedingItem2')}</li>
                  <li>{$_('security.beforeProceedingItem3')}</li>
                </ul>
              </div>
              <div class="actions">
                <button type="button" class="secondary" onclick={() => showRemovePasswordForm = false}>
                  {$_('common.cancel')}
                </button>
                <button type="button" class="danger" onclick={handleRemovePassword} disabled={removePasswordLoading}>
                  {removePasswordLoading ? $_('security.removing') : $_('security.removePassword')}
                </button>
              </div>
            </div>
          {/if}
        {:else}
          <p class="hint">{$_('security.addPasskeyFirst')}</p>
        {/if}
      {:else}
        <div class="status passkey-only">
          <span>{$_('security.noPassword')}</span>
        </div>
        <p class="hint">
          {$_('security.passkeyOnlyHint')}
        </p>
      {/if}
    </section>

    <section>
      <h2>{$_('security.trustedDevices')}</h2>
      <p class="description">
        {$_('security.trustedDevicesDescription')}
      </p>
      <a href="/app/trusted-devices" class="section-link">
        {$_('security.manageTrustedDevices')} &rarr;
      </a>
    </section>
    </div>

    {#if hasMfa}
      <section>
        <h2>{$_('security.appCompatibility')}</h2>
        <p class="description">
          {$_('security.legacyLoginDescription')}
        </p>

        {#if legacyLoginLoading}
          <div class="loading">{$_('common.loading')}</div>
        {:else}
          <div class="toggle-row">
            <div class="toggle-info">
              <span class="toggle-label">{$_('security.legacyLogin')}</span>
              <span class="toggle-description">
                {#if allowLegacyLogin}
                  {$_('security.legacyLoginOn')}
                {:else}
                  {$_('security.legacyLoginOff')}
                {/if}
              </span>
            </div>
            <button
              type="button"
              class="toggle-button {allowLegacyLogin ? 'on' : 'off'}"
              onclick={handleToggleLegacyLogin}
              disabled={legacyLoginUpdating}
              aria-label={allowLegacyLogin ? $_('security.disableLegacyLogin') : $_('security.enableLegacyLogin')}
            >
              <span class="toggle-slider"></span>
            </button>
          </div>

          {#if totpEnabled}
            <div class="warning-box">
              <strong>{$_('security.legacyLoginWarning')}</strong>
              <p>{$_('security.totpPasswordWarning')}</p>
              <ol>
                <li><strong>{$_('security.totpPasswordOption1Label')}</strong> {$_('security.totpPasswordOption1Text')} <a href="/app/settings">{$_('security.totpPasswordOption1Link')}</a> {$_('security.totpPasswordOption1Suffix')}</li>
                <li><strong>{$_('security.totpPasswordOption2Label')}</strong> {$_('security.totpPasswordOption2Text')} <a href="/app/settings">{$_('security.totpPasswordOption2Link')}</a> {$_('security.totpPasswordOption2Suffix')}</li>
              </ol>
            </div>
          {/if}

          <div class="info-box-inline">
            <strong>{$_('security.legacyAppsTitle')}</strong>
            <p>{$_('security.legacyAppsDescription')}</p>
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
    max-width: var(--width-lg);
    margin: 0 auto;
    padding: var(--space-7);
  }

  header {
    margin-bottom: var(--space-7);
  }

  .sections-grid {
    display: flex;
    flex-direction: column;
    gap: var(--space-6);
    margin-bottom: var(--space-6);
  }

  @media (min-width: 800px) {
    .sections-grid {
      columns: 2;
      column-gap: var(--space-6);
      display: block;
    }

    .sections-grid section {
      break-inside: avoid;
      margin-bottom: var(--space-6);
    }
  }

  .back {
    color: var(--text-secondary);
    text-decoration: none;
    font-size: var(--text-sm);
  }

  .back:hover {
    color: var(--accent);
  }

  h1 {
    margin: var(--space-2) 0 0 0;
  }

  .loading {
    text-align: center;
    color: var(--text-secondary);
    padding: var(--space-7);
  }

  section {
    padding: var(--space-6);
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-6);
    height: fit-content;
  }

  section h2 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-lg);
  }

  .description {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin-bottom: var(--space-6);
  }

  .status {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-3);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-4);
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

  .status.passkey-only {
    background: linear-gradient(135deg, rgba(77, 166, 255, 0.15), rgba(128, 90, 213, 0.15));
    border: 1px solid var(--accent);
    color: var(--accent);
  }

  .totp-actions {
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  .code-input {
    font-size: var(--text-2xl);
    letter-spacing: 0.5em;
    text-align: center;
    max-width: 200px;
    margin: 0 auto;
    display: block;
  }

  .actions {
    display: flex;
    gap: var(--space-2);
    margin-top: var(--space-4);
  }

  .inline-form {
    margin-top: var(--space-4);
    padding: var(--space-4);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
  }

  .inline-form h3 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-base);
  }

  .danger-form {
    border-color: var(--error-border);
    background: var(--error-bg);
  }

  .warning-text {
    color: var(--error-text);
    font-size: var(--text-sm);
    margin-bottom: var(--space-4);
  }

  .setup-step {
    padding: var(--space-4);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
  }

  .setup-step h3 {
    margin: 0 0 var(--space-2) 0;
  }

  .setup-step p {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin-bottom: var(--space-4);
  }

  .qr-container {
    display: flex;
    justify-content: center;
    margin: var(--space-6) 0;
  }

  .qr-code {
    width: 200px;
    height: 200px;
    image-rendering: pixelated;
  }

  .manual-entry {
    margin-bottom: var(--space-4);
    font-size: var(--text-sm);
  }

  .manual-entry summary {
    cursor: pointer;
    color: var(--accent);
  }

  .secret-code {
    display: block;
    margin-top: var(--space-2);
    padding: var(--space-2);
    background: var(--bg-input);
    border-radius: var(--radius-md);
    word-break: break-all;
    font-size: var(--text-xs);
  }

  .backup-codes {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: var(--space-2);
    margin: var(--space-4) 0;
  }

  .backup-code {
    padding: var(--space-2);
    background: var(--bg-input);
    border-radius: var(--radius-md);
    text-align: center;
    font-size: var(--text-sm);
    font-family: ui-monospace, monospace;
  }

  .passkey-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin-bottom: var(--space-4);
  }

  .passkey-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-3);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    gap: var(--space-4);
  }

  .passkey-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    flex: 1;
    min-width: 0;
  }

  .passkey-name {
    font-weight: var(--font-medium);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .passkey-meta {
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .passkey-actions {
    display: flex;
    gap: var(--space-2);
    flex-shrink: 0;
  }

  .passkey-edit {
    display: flex;
    flex: 1;
    gap: var(--space-2);
    align-items: center;
  }

  .passkey-name-input {
    flex: 1;
    padding: var(--space-2);
    font-size: var(--text-sm);
  }

  .passkey-edit-actions {
    display: flex;
    gap: var(--space-1);
  }

  button.small {
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-xs);
  }

  .add-passkey {
    margin-top: var(--space-4);
    padding-top: var(--space-4);
    border-top: 1px solid var(--border-color);
  }

  .add-passkey .field {
    margin-bottom: var(--space-3);
  }

  .section-link {
    display: inline-block;
    color: var(--accent);
    text-decoration: none;
    font-weight: var(--font-medium);
  }

  .section-link:hover {
    text-decoration: underline;
  }

  .hint {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin: 0;
  }

  .info-box-inline {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    margin-bottom: var(--space-4);
    font-size: var(--text-sm);
  }

  .info-box-inline strong {
    display: block;
    margin-bottom: var(--space-2);
  }

  .info-box-inline ul {
    margin: 0;
    padding-left: var(--space-5);
    color: var(--text-secondary);
  }

  .info-box-inline li {
    margin-bottom: var(--space-1);
  }

  .info-box-inline p {
    margin: 0;
    color: var(--text-secondary);
  }

  .toggle-row {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--space-4);
    padding: var(--space-4);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-4);
  }

  .toggle-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .toggle-label {
    font-weight: var(--font-medium);
  }

  .toggle-description {
    font-size: var(--text-sm);
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
    transition: background var(--transition-fast);
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
    transition: left var(--transition-fast);
  }

  .toggle-button.on .toggle-slider {
    left: 27px;
  }

  .toggle-button.off .toggle-slider {
    left: 3px;
  }

  .warning-box {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-left: 4px solid var(--warning-text);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    margin-bottom: var(--space-4);
  }

  .warning-box strong {
    display: block;
    margin-bottom: var(--space-2);
    color: var(--warning-text);
  }

  .warning-box p {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-sm);
    color: var(--text-primary);
  }

  .warning-box ol {
    margin: 0;
    padding-left: var(--space-5);
    font-size: var(--text-sm);
  }

  .warning-box li {
    margin-bottom: var(--space-2);
  }

  .warning-box a {
    color: var(--accent);
  }
</style>
