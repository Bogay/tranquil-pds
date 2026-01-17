<script lang="ts">
  import { getAuthState, getValidToken } from '../lib/auth.svelte'
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import ReauthModal from '../components/ReauthModal.svelte'
  import SsoIcon from '../components/SsoIcon.svelte'
  import { _ } from '../lib/i18n'
  import { formatDate as formatDateUtil } from '../lib/date'
  import type { Session } from '../lib/types/api'
  import {
    prepareCreationOptions,
    serializeAttestationResponse,
    type WebAuthnCreationOptionsResponse,
  } from '../lib/webauthn'
  import { toast } from '../lib/toast.svelte'

  interface SsoProvider {
    provider: string
    name: string
    icon: string
  }

  interface LinkedAccount {
    id: string
    provider: string
    provider_name: string
    provider_username: string | null
    provider_email: string | null
    created_at: string
    last_login_at: string | null
  }

  const auth = $derived(getAuthState())

  function getSession(): Session | null {
    return auth.kind === 'authenticated' ? auth.session : null
  }

  function isLoading(): boolean {
    return auth.kind === 'loading'
  }

  const session = $derived(getSession())
  const authLoading = $derived(isLoading())

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

  let ssoProviders = $state<SsoProvider[]>([])
  let linkedAccounts = $state<LinkedAccount[]>([])
  let linkedAccountsLoading = $state(true)
  let linkingProvider = $state<string | null>(null)
  let unlinkingId = $state<string | null>(null)

  let showReauthModal = $state(false)
  let reauthMethods = $state<string[]>(['password'])
  let pendingAction = $state<(() => Promise<void>) | null>(null)

  $effect(() => {
    if (!authLoading && !session) {
      navigate(routes.login)
    }
  })

  $effect(() => {
    if (session) {
      loadTotpStatus()
      loadPasskeys()
      loadPasswordStatus()
      loadLegacyLoginPreference()
      loadSsoProviders()
      loadLinkedAccounts()
    }
  })

  async function loadSsoProviders() {
    try {
      const response = await fetch('/oauth/sso/providers')
      if (response.ok) {
        const data = await response.json()
        ssoProviders = data.providers || []
      }
    } catch {
      ssoProviders = []
    }
  }

  async function loadLinkedAccounts() {
    if (!session) return
    linkedAccountsLoading = true
    try {
      const response = await fetch('/oauth/sso/linked', {
        headers: { 'Authorization': `Bearer ${session.accessJwt}` }
      })
      if (response.ok) {
        const data = await response.json()
        linkedAccounts = data.accounts || []
      }
    } catch {
      linkedAccounts = []
    } finally {
      linkedAccountsLoading = false
    }
  }

  async function handleLinkAccount(provider: string) {
    linkingProvider = provider

    const linkRequestUri = `urn:tranquil:sso:link:${Date.now()}`

    try {
      const response = await fetch('/oauth/sso/initiate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Authorization': `Bearer ${session?.accessJwt}`
        },
        body: JSON.stringify({
          provider,
          request_uri: linkRequestUri,
          action: 'link'
        })
      })

      const data = await response.json()

      if (!response.ok) {
        if (data.error === 'ReauthRequired') {
          reauthMethods = data.reauthMethods || ['password']
          pendingAction = () => handleLinkAccount(provider)
          showReauthModal = true
        } else {
          toast.error(data.error_description || data.error || 'Failed to start SSO linking')
        }
        linkingProvider = null
        return
      }

      if (data.redirect_url) {
        window.location.href = data.redirect_url
        return
      }

      toast.error($_('common.error'))
      linkingProvider = null
    } catch {
      toast.error($_('common.error'))
      linkingProvider = null
    }
  }

  async function handleUnlinkAccount(id: string) {
    const account = linkedAccounts.find(a => a.id === id)
    if (!confirm($_('oauth.sso.unlinkConfirm'))) return

    unlinkingId = id
    try {
      const response = await fetch('/oauth/sso/unlink', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${session?.accessJwt}`
        },
        body: JSON.stringify({ id })
      })

      if (!response.ok) {
        const data = await response.json()
        if (data.error === 'ReauthRequired') {
          reauthMethods = data.reauthMethods || ['password']
          pendingAction = () => handleUnlinkAccount(id)
          showReauthModal = true
        } else {
          toast.error(data.error_description || data.error || 'Failed to unlink account')
        }
        unlinkingId = null
        return
      }

      await loadLinkedAccounts()
      toast.success($_('oauth.sso.unlinked', { values: { provider: account?.provider_name || 'account' } }))
    } catch {
      toast.error($_('common.error'))
    } finally {
      unlinkingId = null
    }
  }

  async function loadPasswordStatus() {
    if (!session) return
    passwordLoading = true
    try {
      const status = await api.getPasswordStatus(session.accessJwt)
      hasPassword = status.hasPassword
    } catch {
      hasPassword = true
    } finally {
      passwordLoading = false
    }
  }

  async function loadLegacyLoginPreference() {
    if (!session) return
    legacyLoginLoading = true
    try {
      const pref = await api.getLegacyLoginPreference(session.accessJwt)
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
    if (!session) return
    legacyLoginUpdating = true
    try {
      const result = await api.updateLegacyLoginPreference(session.accessJwt, !allowLegacyLogin)
      allowLegacyLogin = result.allowLegacyLogin
      toast.success(allowLegacyLogin
        ? $_('security.legacyLoginEnabled')
        : $_('security.legacyLoginDisabled'))
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.error === 'ReauthRequired' || e.error === 'MfaVerificationRequired') {
          reauthMethods = e.reauthMethods || ['password']
          pendingAction = handleToggleLegacyLogin
          showReauthModal = true
        } else {
          toast.error(e.message)
        }
      } else {
        toast.error($_('security.failedToUpdatePreference'))
      }
    } finally {
      legacyLoginUpdating = false
    }
  }

  async function handleRemovePassword() {
    if (!session) return
    removePasswordLoading = true
    try {
      const token = await getValidToken()
      if (!token) {
        toast.error($_('security.sessionExpired'))
        return
      }
      await api.removePassword(token)
      hasPassword = false
      showRemovePasswordForm = false
      toast.success($_('security.passwordRemoved'))
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.error === 'ReauthRequired') {
          reauthMethods = e.reauthMethods || ['password']
          pendingAction = handleRemovePassword
          showReauthModal = true
        } else {
          toast.error(e.message)
        }
      } else {
        toast.error($_('security.failedToRemovePassword'))
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
    if (!session) return
    loading = true
    try {
      const status = await api.getTotpStatus(session.accessJwt)
      totpEnabled = status.enabled
      hasBackupCodes = status.hasBackupCodes
    } catch {
      toast.error($_('security.failedToLoadTotpStatus'))
    } finally {
      loading = false
    }
  }

  async function handleStartSetup() {
    if (!session) return
    verifyLoading = true
    try {
      const result = await api.createTotpSecret(session.accessJwt)
      qrBase64 = result.qrBase64
      totpUri = result.uri
      setupStep = 'qr'
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to generate TOTP secret')
    } finally {
      verifyLoading = false
    }
  }

  async function handleVerifySetup(e: Event) {
    e.preventDefault()
    if (!session || !verifyCode) return
    verifyLoading = true
    try {
      const result = await api.enableTotp(session.accessJwt, verifyCode)
      backupCodes = result.backupCodes
      setupStep = 'backup'
      totpEnabled = true
      hasBackupCodes = true
      verifyCodeRaw = ''
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Invalid code. Please try again.')
    } finally {
      verifyLoading = false
    }
  }

  function handleFinishSetup() {
    setupStep = 'idle'
    backupCodes = []
    qrBase64 = ''
    totpUri = ''
    toast.success($_('security.totpEnabledSuccess'))
  }

  async function handleDisable(e: Event) {
    e.preventDefault()
    if (!session || !disablePassword || !disableCode) return
    disableLoading = true
    try {
      await api.disableTotp(session.accessJwt, disablePassword, disableCode)
      totpEnabled = false
      hasBackupCodes = false
      showDisableForm = false
      disablePassword = ''
      disableCode = ''
      toast.success($_('security.totpDisabledSuccess'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to disable TOTP')
    } finally {
      disableLoading = false
    }
  }

  async function handleRegenerate(e: Event) {
    e.preventDefault()
    if (!session || !regenPassword || !regenCode) return
    regenLoading = true
    try {
      const result = await api.regenerateBackupCodes(session.accessJwt, regenPassword, regenCode)
      backupCodes = result.backupCodes
      setupStep = 'backup'
      showRegenForm = false
      regenPassword = ''
      regenCode = ''
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to regenerate backup codes')
    } finally {
      regenLoading = false
    }
  }

  function copyBackupCodes() {
    const text = backupCodes.join('\n')
    navigator.clipboard.writeText(text)
    toast.success($_('security.backupCodesCopied'))
  }

  async function loadPasskeys() {
    if (!session) return
    passkeysLoading = true
    try {
      const result = await api.listPasskeys(session.accessJwt)
      passkeys = result.passkeys
    } catch {
      toast.error($_('security.failedToLoadPasskeys'))
    } finally {
      passkeysLoading = false
    }
  }

  async function handleAddPasskey() {
    if (!session) return
    if (!window.PublicKeyCredential) {
      toast.error($_('security.passkeysNotSupported'))
      return
    }
    addingPasskey = true
    try {
      const { options } = await api.startPasskeyRegistration(session.accessJwt, newPasskeyName || undefined)
      const publicKeyOptions = prepareCreationOptions(options as unknown as WebAuthnCreationOptionsResponse)
      const credential = await navigator.credentials.create({
        publicKey: publicKeyOptions
      })
      if (!credential) {
        toast.error($_('security.passkeyCreationCancelled'))
        return
      }
      const credentialResponse = serializeAttestationResponse(credential as PublicKeyCredential)
      await api.finishPasskeyRegistration(session.accessJwt, credentialResponse, newPasskeyName || undefined)
      await loadPasskeys()
      newPasskeyName = ''
      toast.success($_('security.passkeyAddedSuccess'))
    } catch (e) {
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        toast.error($_('security.passkeyCreationCancelled'))
      } else {
        toast.error(e instanceof ApiError ? e.message : 'Failed to add passkey')
      }
    } finally {
      addingPasskey = false
    }
  }

  async function handleDeletePasskey(id: string) {
    if (!session) return
    const passkey = passkeys.find(p => p.id === id)
    const name = passkey?.friendlyName || 'this passkey'
    if (!confirm($_('security.deletePasskeyConfirm', { values: { name } }))) return
    try {
      await api.deletePasskey(session.accessJwt, id)
      await loadPasskeys()
      toast.success($_('security.passkeyDeleted'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to delete passkey')
    }
  }

  async function handleSavePasskeyName() {
    if (!session || !editingPasskeyId || !editPasskeyName.trim()) return
    try {
      await api.updatePasskey(session.accessJwt, editingPasskeyId, editPasskeyName.trim())
      await loadPasskeys()
      editingPasskeyId = null
      editPasskeyName = ''
      toast.success($_('security.passkeyRenamed'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to rename passkey')
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

  function formatDate(dateStr: string): string {
    return formatDateUtil(dateStr)
  }
</script>

<div class="page">
  <header>
    <a href={getFullUrl(routes.dashboard)} class="back">{$_('common.backToDashboard')}</a>
    <h1>{$_('security.title')}</h1>
  </header>

  {#if loading}
    <div class="skeleton-grid">
      {#each Array(4) as _}
        <div class="skeleton-section"></div>
      {/each}
    </div>
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

      {#if !passkeysLoading}
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

      {#if !passwordLoading && hasPassword}
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
        <p class="hint">
          {$_('security.addPasswordHint')}
        </p>
        <a href={getFullUrl(routes.settings)} class="section-link">
          {$_('security.goToSettings')}
        </a>
      {/if}
    </section>

    <section>
      <h2>{$_('security.trustedDevices')}</h2>
      <p class="description">
        {$_('security.trustedDevicesDescription')}
      </p>
      <a href={getFullUrl(routes.trustedDevices)} class="section-link">
        {$_('security.manageTrustedDevices')} &rarr;
      </a>
    </section>

    {#if ssoProviders.length > 0}
      <section>
        <h2>{$_('oauth.sso.linkedAccounts')}</h2>
        <p class="description">
          {$_('oauth.sso.linkedAccountsDesc')}
        </p>

        {#if !linkedAccountsLoading}
          {#if linkedAccounts.length > 0}
            <div class="linked-accounts-list">
              {#each linkedAccounts as account}
                <div class="linked-account-item">
                  <div class="linked-account-icon">
                    <SsoIcon provider={account.provider} size={24} />
                  </div>
                  <div class="linked-account-info">
                    <span class="linked-account-provider">{account.provider_name}</span>
                    <span class="linked-account-meta">
                      {#if account.provider_username}
                        {account.provider_username}
                      {:else if account.provider_email}
                        {account.provider_email}
                      {/if}
                      {#if account.last_login_at}
                        &middot; {$_('oauth.sso.lastLoginAt')} {formatDate(account.last_login_at)}
                      {/if}
                    </span>
                  </div>
                  <button
                    type="button"
                    class="small danger-outline"
                    onclick={() => handleUnlinkAccount(account.id)}
                    disabled={unlinkingId !== null}
                  >
                    {unlinkingId === account.id ? $_('common.loading') : $_('oauth.sso.unlinkAccount')}
                  </button>
                </div>
              {/each}
            </div>
          {:else}
            <div class="status disabled">
              <span>{$_('oauth.sso.noLinkedAccounts')}</span>
            </div>
            <p class="hint">{$_('oauth.sso.noLinkedAccountsDesc')}</p>
          {/if}

          {#if ssoProviders.some(p => !linkedAccounts.some(a => a.provider === p.provider))}
            <div class="link-account-section">
              <h3>{$_('oauth.sso.linkAccount')}</h3>
              <div class="sso-link-buttons">
                {#each ssoProviders.filter(p => !linkedAccounts.some(a => a.provider === p.provider)) as provider}
                  <button
                    type="button"
                    class="sso-link-btn"
                    onclick={() => handleLinkAccount(provider.provider)}
                    disabled={linkingProvider !== null}
                  >
                    {#if linkingProvider === provider.provider}
                      <span class="loading-spinner small"></span>
                    {:else}
                      <SsoIcon provider={provider.icon} size={18} />
                    {/if}
                    <span>{provider.name}</span>
                  </button>
                {/each}
              </div>
            </div>
          {/if}
        {:else}
          <div class="loading-text">{$_('common.loading')}</div>
        {/if}
      </section>
    {/if}
    </div>

    {#if hasMfa}
      <section>
        <h2>{$_('security.appCompatibility')}</h2>
        <p class="description">
          {$_('security.legacyLoginDescription')}
        </p>

        {#if !legacyLoginLoading}
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
                <li><strong>{$_('security.totpPasswordOption1Label')}</strong> {$_('security.totpPasswordOption1Text')} <a href={getFullUrl(routes.settings)}>{$_('security.totpPasswordOption1Link')}</a> {$_('security.totpPasswordOption1Suffix')}</li>
                <li><strong>{$_('security.totpPasswordOption2Label')}</strong> {$_('security.totpPasswordOption2Text')} <a href={getFullUrl(routes.settings)}>{$_('security.totpPasswordOption2Link')}</a> {$_('security.totpPasswordOption2Suffix')}</li>
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

  .skeleton-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: var(--space-6);
  }

  .skeleton-section {
    height: 200px;
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
    animation: skeleton-pulse 1.5s ease-in-out infinite;
  }

  @keyframes skeleton-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  @media (max-width: 900px) {
    .skeleton-grid {
      grid-template-columns: 1fr;
    }
  }

  .linked-accounts-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin-bottom: var(--space-4);
  }

  .linked-account-item {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
  }

  .linked-account-icon {
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-secondary);
  }

  .linked-account-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .linked-account-provider {
    font-weight: var(--font-medium);
  }

  .linked-account-meta {
    font-size: var(--text-xs);
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .link-account-section {
    margin-top: var(--space-4);
    padding-top: var(--space-4);
    border-top: 1px solid var(--border-color);
  }

  .link-account-section h3 {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
    color: var(--text-secondary);
  }

  .sso-link-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }

  .sso-link-btn {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    background: var(--bg-card);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background-color var(--transition-fast), border-color var(--transition-fast);
  }

  .sso-link-btn:hover:not(:disabled) {
    background: var(--bg-secondary);
    border-color: var(--accent);
  }

  .sso-link-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .loading-spinner.small {
    width: 18px;
    height: 18px;
    border-width: 2px;
  }

  .loading-spinner {
    border: 3px solid var(--border-color);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .loading-text {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    text-align: center;
    padding: var(--space-4);
  }
</style>
