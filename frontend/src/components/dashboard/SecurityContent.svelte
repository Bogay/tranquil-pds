<script lang="ts">
  import { onMount } from 'svelte'
  import { getValidToken } from '../../lib/auth.svelte'
  import { api, ApiError } from '../../lib/api'
  import { _ } from '../../lib/i18n'
  import { formatDate } from '../../lib/date'
  import type { Session } from '../../lib/types/api'
  import { toast } from '../../lib/toast.svelte'
  import ReauthModal from '../ReauthModal.svelte'
  import SsoIcon from '../SsoIcon.svelte'
  import {
    prepareCreationOptions,
    serializeAttestationResponse,
    type WebAuthnCreationOptionsResponse,
  } from '../../lib/webauthn'
  import {
    type TotpSetupState,
    idleState,
    qrState,
    verifyState,
    backupState,
    goBackToQr,
    finish,
    type TotpQr,
  } from '../../lib/types/totp-state'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  let loading = $state(true)
  let totpEnabled = $state(false)
  let hasBackupCodes = $state(false)
  let totpSetup = $state<TotpSetupState>(idleState)
  let verifyCodeRaw = $state('')
  let verifyCode = $derived(verifyCodeRaw.replace(/\s/g, ''))
  let verifyLoading = $state(false)

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

  let showChangePasswordForm = $state(false)
  let currentPassword = $state('')
  let newPassword = $state('')
  let confirmNewPassword = $state('')
  let changePasswordLoading = $state(false)

  let showSetPasswordForm = $state(false)
  let setNewPassword = $state('')
  let setConfirmPassword = $state('')
  let setPasswordLoading = $state(false)

  let disablePassword = $state('')
  let disableCode = $state('')
  let disableLoading = $state(false)
  let showDisableForm = $state(false)

  let regenPassword = $state('')
  let regenCode = $state('')
  let regenLoading = $state(false)
  let showRegenForm = $state(false)

  interface SsoProvider {
    provider: string
    name: string
    icon: string
  }

  interface SsoLinkedAccount {
    id: string
    provider: string
    provider_name: string
    provider_username: string
    provider_email?: string
    created_at: string
    last_login_at?: string
  }

  let ssoProviders = $state<SsoProvider[]>([])
  let linkedAccounts = $state<SsoLinkedAccount[]>([])
  let linkedAccountsLoading = $state(true)
  let linkingProvider = $state<string | null>(null)
  let unlinkingId = $state<string | null>(null)

  let allowLegacyLogin = $state(true)
  let hasMfa = $state(false)
  let legacyLoginLoading = $state(true)
  let legacyLoginUpdating = $state(false)

  interface TrustedDevice {
    id: string
    userAgent: string | null
    friendlyName: string | null
    trustedAt: string | null
    trustedUntil: string | null
    lastSeenAt: string
  }
  let trustedDevices = $state<TrustedDevice[]>([])
  let trustedDevicesLoading = $state(true)
  let editingDeviceId = $state<string | null>(null)
  let editDeviceName = $state('')

  let showReauthModal = $state(false)
  let reauthMethods = $state<string[]>(['password'])
  let pendingAction = $state<(() => Promise<void>) | null>(null)

  function handleReauthSuccess() {
    if (pendingAction) {
      pendingAction()
      pendingAction = null
    }
  }

  function handleReauthCancel() {
    pendingAction = null
  }

  onMount(async () => {
    const params = new URLSearchParams(globalThis.location.search)
    const error = params.get('error')
    const ssoLinked = params.get('sso_linked')
    if (error) {
      toast.error(error)
      globalThis.history.replaceState({}, '', globalThis.location.pathname)
    } else if (ssoLinked === 'true') {
      toast.success($_('oauth.sso.linkSuccess'))
      globalThis.history.replaceState({}, '', globalThis.location.pathname)
    }

    await Promise.all([
      loadTotpStatus(),
      loadPasskeys(),
      loadPasswordStatus(),
      loadSsoProviders(),
      loadLinkedAccounts(),
      loadLegacyLoginPreference(),
      loadTrustedDevices()
    ])
    loading = false
  })

  async function loadTotpStatus() {
    try {
      const status = await api.getTotpStatus(session.accessJwt)
      totpEnabled = status.enabled
      hasBackupCodes = status.hasBackupCodes
    } catch {
      toast.error($_('security.failedToLoadTotpStatus'))
    }
  }

  async function loadPasskeys() {
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

  async function loadPasswordStatus() {
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

  async function loadSsoProviders() {
    try {
      const response = await fetch('/oauth/sso/providers')
      if (response.ok) {
        const data = await response.json()
        ssoProviders = (data.providers || []).toSorted((a: SsoProvider, b: SsoProvider) => a.name.localeCompare(b.name))
      }
    } catch {
      ssoProviders = []
    }
  }

  async function loadLinkedAccounts() {
    linkedAccountsLoading = true
    try {
      const result = await api.getSsoLinkedAccounts(session.accessJwt)
      linkedAccounts = result.accounts || []
    } catch {
      linkedAccounts = []
    } finally {
      linkedAccountsLoading = false
    }
  }

  async function loadTrustedDevices() {
    trustedDevicesLoading = true
    try {
      const result = await api.listTrustedDevices(session.accessJwt)
      trustedDevices = result.devices
    } catch {
      trustedDevices = []
    } finally {
      trustedDevicesLoading = false
    }
  }

  async function handleRevokeDevice(deviceId: string) {
    if (!confirm($_('trustedDevices.revokeConfirm'))) return
    try {
      await api.revokeTrustedDevice(session.accessJwt, deviceId)
      await loadTrustedDevices()
      toast.success($_('trustedDevices.deviceRevoked'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('common.error'))
    }
  }

  function startEditDevice(device: TrustedDevice) {
    editingDeviceId = device.id
    editDeviceName = device.friendlyName || ''
  }

  function cancelEditDevice() {
    editingDeviceId = null
    editDeviceName = ''
  }

  async function handleSaveDeviceName() {
    if (!editingDeviceId || !editDeviceName.trim()) return
    try {
      await api.updateTrustedDevice(session.accessJwt, editingDeviceId, editDeviceName.trim())
      await loadTrustedDevices()
      editingDeviceId = null
      editDeviceName = ''
      toast.success($_('trustedDevices.deviceRenamed'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('common.error'))
    }
  }

  function parseUserAgent(ua: string | null): string {
    if (!ua) return $_('trustedDevices.unknownDevice')
    if (ua.includes('Firefox')) return 'Firefox'
    if (ua.includes('Chrome')) return 'Chrome'
    if (ua.includes('Safari')) return 'Safari'
    if (ua.includes('Edge')) return 'Edge'
    return 'Browser'
  }

  function getDaysRemaining(trustedUntil: string | null): number {
    if (!trustedUntil) return 0
    const now = new Date()
    const until = new Date(trustedUntil)
    const diff = until.getTime() - now.getTime()
    return Math.ceil(diff / (1000 * 60 * 60 * 24))
  }

  async function handleLinkAccount(provider: string) {
    linkingProvider = provider
    const linkRequestUri = `urn:tranquil:sso:link:${Date.now()}`

    try {
      const result = await api.initiateSsoLink(session.accessJwt, provider, linkRequestUri)
      if (result.redirect_url) {
        window.location.href = result.redirect_url
        return
      }
      toast.error($_('common.error'))
      linkingProvider = null
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.error === 'ReauthRequired') {
          reauthMethods = e.reauthMethods || ['password']
          pendingAction = () => handleLinkAccount(provider)
          showReauthModal = true
        } else {
          toast.error(e.message || $_('oauth.sso.linkFailed'))
        }
      } else {
        toast.error($_('common.error'))
      }
      linkingProvider = null
    }
  }

  async function handleUnlinkAccount(id: string) {
    const account = linkedAccounts.find(a => a.id === id)
    if (!confirm($_('oauth.sso.unlinkConfirm'))) return

    unlinkingId = id
    try {
      await api.unlinkSsoAccount(session.accessJwt, id)
      await loadLinkedAccounts()
      toast.success($_('oauth.sso.unlinked', { values: { provider: account?.provider_name || 'account' } }))
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.error === 'ReauthRequired') {
          reauthMethods = e.reauthMethods || ['password']
          pendingAction = () => handleUnlinkAccount(id)
          showReauthModal = true
        } else {
          toast.error(e.message || $_('oauth.sso.unlinkFailed'))
        }
      } else {
        toast.error($_('common.error'))
      }
    } finally {
      unlinkingId = null
    }
  }

  async function loadLegacyLoginPreference() {
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

  async function handleChangePassword(e: Event) {
    e.preventDefault()
    if (!currentPassword || !newPassword || !confirmNewPassword) return
    if (newPassword !== confirmNewPassword) {
      toast.error($_('security.passwordsDoNotMatch'))
      return
    }
    if (newPassword.length < 8) {
      toast.error($_('security.passwordTooShort'))
      return
    }
    changePasswordLoading = true
    try {
      await api.changePassword(session.accessJwt, currentPassword, newPassword)
      toast.success($_('security.passwordChanged'))
      currentPassword = ''
      newPassword = ''
      confirmNewPassword = ''
      showChangePasswordForm = false
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.error === 'ReauthRequired') {
          reauthMethods = e.reauthMethods || ['password']
          pendingAction = () => handleChangePassword(new Event('submit'))
          showReauthModal = true
        } else {
          toast.error(e.message)
        }
      } else {
        toast.error($_('security.failedToChangePassword'))
      }
    } finally {
      changePasswordLoading = false
    }
  }

  async function handleSetPassword(e: Event) {
    e.preventDefault()
    if (!setNewPassword || !setConfirmPassword) return
    if (setNewPassword !== setConfirmPassword) {
      toast.error($_('security.passwordsDoNotMatch'))
      return
    }
    if (setNewPassword.length < 8) {
      toast.error($_('security.passwordTooShort'))
      return
    }
    setPasswordLoading = true
    try {
      await api.setPassword(session.accessJwt, setNewPassword)
      hasPassword = true
      toast.success($_('security.passwordSet'))
      setNewPassword = ''
      setConfirmPassword = ''
      showSetPasswordForm = false
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.error === 'ReauthRequired') {
          reauthMethods = e.reauthMethods || ['passkey']
          pendingAction = () => handleSetPassword(new Event('submit'))
          showReauthModal = true
        } else {
          toast.error(e.message)
        }
      } else {
        toast.error($_('security.failedToSetPassword'))
      }
    } finally {
      setPasswordLoading = false
    }
  }

  async function handleStartTotpSetup() {
    verifyLoading = true
    try {
      const result = await api.createTotpSecret(session.accessJwt)
      totpSetup = qrState(result.qrBase64, result.uri)
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to generate TOTP secret')
    } finally {
      verifyLoading = false
    }
  }

  async function handleVerifyTotp(e: Event) {
    e.preventDefault()
    if (!verifyCode || totpSetup.step !== 'verify') return
    verifyLoading = true
    try {
      const result = await api.enableTotp(session.accessJwt, verifyCode)
      totpSetup = backupState(totpSetup, result.backupCodes)
      totpEnabled = true
      hasBackupCodes = true
      verifyCodeRaw = ''
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Invalid code')
    } finally {
      verifyLoading = false
    }
  }

  function handleFinishSetup() {
    if (totpSetup.step !== 'backup') return
    totpSetup = finish(totpSetup)
    toast.success($_('security.totpEnabledSuccess'))
  }

  function copyBackupCodes() {
    if (totpSetup.step !== 'backup') return
    navigator.clipboard.writeText(totpSetup.backupCodes.join('\n'))
    toast.success($_('security.backupCodesCopied'))
  }

  async function handleDisableTotp(e: Event) {
    e.preventDefault()
    if (!disablePassword || !disableCode) return
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
      toast.error(e instanceof ApiError ? e.message : $_('security.failedToDisableTotp'))
    } finally {
      disableLoading = false
    }
  }

  async function handleRegenerateBackupCodes(e: Event) {
    e.preventDefault()
    if (!regenPassword || !regenCode) return
    regenLoading = true
    try {
      const result = await api.regenerateBackupCodes(session.accessJwt, regenPassword, regenCode)
      const dummyVerify = verifyState(qrState('', ''))
      totpSetup = backupState(dummyVerify, result.backupCodes)
      showRegenForm = false
      regenPassword = ''
      regenCode = ''
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('security.failedToRegenerateBackupCodes'))
    } finally {
      regenLoading = false
    }
  }

  async function handleAddPasskey() {
    if (!window.PublicKeyCredential) {
      toast.error($_('security.passkeysNotSupported'))
      return
    }
    addingPasskey = true
    try {
      const { options } = await api.startPasskeyRegistration(session.accessJwt, newPasskeyName || undefined)
      const publicKeyOptions = prepareCreationOptions(options as unknown as WebAuthnCreationOptionsResponse)
      const credential = await navigator.credentials.create({ publicKey: publicKeyOptions })
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
    const passkey = passkeys.find(p => p.id === id)
    if (!confirm($_('security.deletePasskeyConfirm', { values: { name: passkey?.friendlyName || 'this passkey' } }))) return
    try {
      await api.deletePasskey(session.accessJwt, id)
      await loadPasskeys()
      toast.success($_('security.passkeyDeleted'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to delete passkey')
    }
  }

  async function handleSavePasskeyName() {
    if (!editingPasskeyId || !editPasskeyName.trim()) return
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
</script>

<div class="security">
  {#if loading}
    <div class="loading">{$_('common.loading')}</div>
  {:else}
    <section>
      <h3>{$_('security.passkeys')}</h3>

      {#if !passkeysLoading}
        {#if passkeys.length > 0}
          <ul class="passkey-list">
            {#each passkeys as passkey}
              <li class="passkey-item">
                {#if editingPasskeyId === passkey.id}
                  <div class="passkey-edit">
                    <input type="text" bind:value={editPasskeyName} placeholder={$_('security.passkeyName')} />
                    <button type="button" class="small" onclick={handleSavePasskeyName}>{$_('common.save')}</button>
                    <button type="button" class="small secondary" onclick={cancelEditPasskey}>{$_('common.cancel')}</button>
                  </div>
                {:else}
                  <div class="passkey-info">
                    <span class="passkey-name">{passkey.friendlyName || $_('security.unnamedPasskey')}</span>
                    <span class="passkey-meta">
                      {$_('security.added')} {formatDate(passkey.createdAt)}
                      {#if passkey.lastUsed}
                        - {$_('security.lastUsed')} {formatDate(passkey.lastUsed)}
                      {/if}
                    </span>
                  </div>
                  <div class="passkey-actions">
                    <button type="button" class="small secondary" onclick={() => startEditPasskey(passkey)}>{$_('security.rename')}</button>
                    {#if hasPassword || passkeys.length > 1}
                      <button type="button" class="small danger" onclick={() => handleDeletePasskey(passkey.id)}>{$_('security.deletePasskey')}</button>
                    {/if}
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        {:else}
          <div class="status warning">{$_('security.noPasskeys')}</div>
        {/if}

        <div class="add-passkey">
          <input type="text" bind:value={newPasskeyName} placeholder={$_('security.passkeyNamePlaceholder')} disabled={addingPasskey} />
          <button onclick={handleAddPasskey} disabled={addingPasskey}>
            {addingPasskey ? $_('security.adding') : $_('security.addPasskey')}
          </button>
        </div>

      {/if}
    </section>

    <section>
      <h3>{$_('security.totp')}</h3>

      {#if totpSetup.step === 'idle'}
        {#if totpEnabled}
          <div class="status success">{$_('security.totpEnabled')}</div>

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
            <form class="inline-form" onsubmit={handleRegenerateBackupCodes}>
              <h4>{$_('security.regenerateBackupCodes')}</h4>
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
                  placeholder={$_('security.totpCodePlaceholder')}
                  disabled={regenLoading}
                  required
                  maxlength="6"
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
            <form class="inline-form danger-form" onsubmit={handleDisableTotp}>
              <h4>{$_('security.disableTotp')}</h4>
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
                  placeholder={$_('security.totpCodePlaceholder')}
                  disabled={disableLoading}
                  required
                  maxlength="6"
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
          <div class="status warning">{$_('security.totpDisabled')}</div>
          <button onclick={handleStartTotpSetup} disabled={verifyLoading}>
            {$_('security.enableTotp')}
          </button>
        {/if}
      {:else if totpSetup.step === 'qr'}
        {@const qrData = totpSetup as TotpQr}
        <div class="setup-step">
          <p>{$_('security.totpSetupInstructions')}</p>
          <div class="qr-container">
            <img src="data:image/png;base64,{qrData.qrBase64}" alt="TOTP QR Code" class="qr-code" />
          </div>
          <details class="manual-entry">
            <summary>{$_('security.cantScan')}</summary>
            <code class="secret-code">{qrData.totpUri.split('secret=')[1]?.split('&')[0] || ''}</code>
          </details>
          <button onclick={() => totpSetup = verifyState(qrData)}>{$_('security.next')}</button>
        </div>
      {:else if totpSetup.step === 'verify'}
        {@const verifyData = totpSetup}
        <div class="setup-step">
          <p>{$_('security.totpCodePlaceholder')}</p>
          <form onsubmit={handleVerifyTotp}>
            <input type="text" bind:value={verifyCodeRaw} placeholder="000000" class="code-input" inputmode="numeric" disabled={verifyLoading} />
            <div class="actions">
              <button type="button" class="secondary" onclick={() => totpSetup = goBackToQr(verifyData)}>{$_('common.back')}</button>
              <button type="submit" disabled={verifyLoading || verifyCode.length !== 6}>{$_('security.verifyAndEnable')}</button>
            </div>
          </form>
        </div>
      {:else if totpSetup.step === 'backup'}
        <div class="setup-step">
          <h4>{$_('security.backupCodes')}</h4>
          <p class="warning-text">{$_('security.backupCodesDescription')}</p>
          <div class="backup-codes">
            {#each totpSetup.backupCodes as code}
              <code class="backup-code">{code}</code>
            {/each}
          </div>
          <div class="actions">
            <button type="button" class="secondary" onclick={copyBackupCodes}>{$_('security.copyToClipboard')}</button>
            <button onclick={handleFinishSetup}>{$_('security.savedMyCodes')}</button>
          </div>
        </div>
      {/if}
    </section>

    <section>
      <h3>{$_('security.password')}</h3>
      {#if !passwordLoading}
        {#if hasPassword}
          <div class="status success">{$_('security.passwordStatus')}</div>

          {#if !showChangePasswordForm && !showRemovePasswordForm}
            <div class="password-actions">
              <button type="button" onclick={() => showChangePasswordForm = true}>
                {$_('security.changePassword')}
              </button>
              {#if passkeys.length > 0}
                <button type="button" class="danger-outline" onclick={() => showRemovePasswordForm = true}>
                  {$_('security.removePassword')}
                </button>
              {/if}
            </div>
          {/if}

          {#if showChangePasswordForm}
            <form class="inline-form" onsubmit={handleChangePassword}>
              <h4>{$_('security.changePassword')}</h4>
              <div class="field">
                <label for="current-password">{$_('security.currentPassword')}</label>
                <input
                  id="current-password"
                  type="password"
                  bind:value={currentPassword}
                  placeholder={$_('security.currentPasswordPlaceholder')}
                  disabled={changePasswordLoading}
                  required
                />
              </div>
              <div class="field">
                <label for="new-password">{$_('security.newPassword')}</label>
                <input
                  id="new-password"
                  type="password"
                  bind:value={newPassword}
                  placeholder={$_('security.newPasswordPlaceholder')}
                  disabled={changePasswordLoading}
                  required
                  minlength="8"
                />
              </div>
              <div class="field">
                <label for="confirm-password">{$_('security.confirmPassword')}</label>
                <input
                  id="confirm-password"
                  type="password"
                  bind:value={confirmNewPassword}
                  placeholder={$_('security.confirmPasswordPlaceholder')}
                  disabled={changePasswordLoading}
                  required
                  minlength="8"
                />
              </div>
              <div class="actions">
                <button type="button" class="secondary" onclick={() => { showChangePasswordForm = false; currentPassword = ''; newPassword = ''; confirmNewPassword = '' }}>
                  {$_('common.cancel')}
                </button>
                <button type="submit" disabled={changePasswordLoading || !currentPassword || !newPassword || !confirmNewPassword}>
                  {changePasswordLoading ? $_('security.changing') : $_('security.changePassword')}
                </button>
              </div>
            </form>
          {/if}

          {#if showRemovePasswordForm}
            <div class="remove-password-form">
              <p class="warning-text">{$_('security.removePasswordWarning')}</p>
              <div class="actions">
                <button type="button" class="ghost sm" onclick={() => showRemovePasswordForm = false}>
                  {$_('common.cancel')}
                </button>
                <button type="button" class="danger sm" onclick={handleRemovePassword} disabled={removePasswordLoading}>
                  {removePasswordLoading ? $_('security.removing') : $_('security.removePassword')}
                </button>
              </div>
            </div>
          {/if}
        {:else}
          <div class="status info">{$_('security.noPassword')}</div>

          {#if !showSetPasswordForm}
            <button type="button" onclick={() => showSetPasswordForm = true}>
              {$_('security.setPassword')}
            </button>
          {:else}
            <form class="inline-form" onsubmit={handleSetPassword}>
              <h4>{$_('security.setPassword')}</h4>
              <div class="field">
                <label for="set-new-password">{$_('security.newPassword')}</label>
                <input
                  id="set-new-password"
                  type="password"
                  bind:value={setNewPassword}
                  placeholder={$_('security.newPasswordPlaceholder')}
                  disabled={setPasswordLoading}
                  required
                  minlength="8"
                />
              </div>
              <div class="field">
                <label for="set-confirm-password">{$_('security.confirmPassword')}</label>
                <input
                  id="set-confirm-password"
                  type="password"
                  bind:value={setConfirmPassword}
                  placeholder={$_('security.confirmPasswordPlaceholder')}
                  disabled={setPasswordLoading}
                  required
                  minlength="8"
                />
              </div>
              <div class="actions">
                <button type="button" class="secondary" onclick={() => { showSetPasswordForm = false; setNewPassword = ''; setConfirmPassword = '' }}>
                  {$_('common.cancel')}
                </button>
                <button type="submit" disabled={setPasswordLoading || !setNewPassword || !setConfirmPassword}>
                  {setPasswordLoading ? $_('security.setting') : $_('security.setPassword')}
                </button>
              </div>
            </form>
          {/if}
        {/if}
      {/if}
    </section>

    {#if ssoProviders.length > 0}
      <section>
        <h3>{$_('oauth.sso.linkedAccounts')}</h3>

        {#if linkedAccountsLoading}
          <div class="loading">{$_('common.loading')}</div>
        {:else}
          {#if linkedAccounts.length > 0}
            <ul class="sso-list">
              {#each linkedAccounts as account}
                <li class="sso-item">
                  <div class="sso-info">
                    <span class="sso-provider">{account.provider_name}</span>
                    <span class="sso-id">{account.provider_username}</span>
                    <span class="sso-meta">{$_('oauth.sso.linkedAt')} {formatDate(account.created_at)}</span>
                  </div>
                  <button
                    type="button"
                    class="small danger"
                    onclick={() => handleUnlinkAccount(account.id)}
                    disabled={unlinkingId === account.id}
                  >
                    {unlinkingId === account.id ? $_('common.loading') : $_('oauth.sso.unlink')}
                  </button>
                </li>
              {/each}
            </ul>
          {:else}
            <p class="empty">{$_('oauth.sso.noLinkedAccounts')}</p>
          {/if}

          <div class="sso-providers">
            <h4>{$_('oauth.sso.linkNewAccount')}</h4>
            <div class="provider-buttons">
              {#each ssoProviders as provider}
                {@const isLinked = linkedAccounts.some(a => a.provider === provider.provider)}
                <button
                  type="button"
                  class="provider-btn"
                  onclick={() => handleLinkAccount(provider.provider)}
                  disabled={linkingProvider === provider.provider || isLinked}
                >
                  <SsoIcon provider={provider.provider} />
                  <span class="provider-name">{linkingProvider === provider.provider ? $_('common.loading') : provider.name}</span>
                  {#if isLinked}
                    <span class="linked-badge">{$_('oauth.sso.linked')}</span>
                  {/if}
                </button>
              {/each}
            </div>
          </div>
        {/if}
      </section>
    {/if}

    {#if hasMfa}
      <section>
        <h3>{$_('security.appCompatibility')}</h3>
        <p class="section-description">{$_('security.legacyLoginDescription')}</p>

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

          {#if totpEnabled && allowLegacyLogin}
            <div class="warning-box">
              <strong>{$_('security.legacyLoginWarning')}</strong>
            </div>
          {/if}

          <div class="info-box">
            <strong>{$_('security.legacyAppsTitle')}</strong>
            <p>{$_('security.legacyAppsDescription')}</p>
          </div>
        {/if}
      </section>
    {/if}

    <section>
      <h3>{$_('security.trustedDevices')}</h3>
      <p class="section-description">{$_('security.trustedDevicesDescription')}</p>

      {#if trustedDevicesLoading}
        <div class="loading">{$_('common.loading')}</div>
      {:else if trustedDevices.length === 0}
        <p class="empty-hint">{$_('trustedDevices.noDevices')}</p>
        <p class="hint-text">{$_('trustedDevices.noDevicesHint')}</p>
      {:else}
        <div class="device-list">
          {#each trustedDevices as device}
            <div class="device-card">
              <div class="device-header">
                {#if editingDeviceId === device.id}
                  <input
                    type="text"
                    class="edit-name-input"
                    bind:value={editDeviceName}
                    placeholder={$_('trustedDevices.deviceNamePlaceholder')}
                  />
                  <div class="edit-actions">
                    <button type="button" class="sm" onclick={handleSaveDeviceName}>{$_('common.save')}</button>
                    <button type="button" class="sm ghost" onclick={cancelEditDevice}>{$_('common.cancel')}</button>
                  </div>
                {:else}
                  <span class="device-name">{device.friendlyName || parseUserAgent(device.userAgent)}</span>
                  <button type="button" class="icon-btn" onclick={() => startEditDevice(device)} title={$_('security.rename')}>
                    &#9998;
                  </button>
                {/if}
              </div>

              <div class="device-details">
                {#if device.userAgent}
                  <span class="detail">{parseUserAgent(device.userAgent)}</span>
                {/if}
                {#if device.trustedAt}
                  <span class="detail">{$_('trustedDevices.trustedSince')} {formatDate(device.trustedAt)}</span>
                {/if}
                <span class="detail">{$_('trustedDevices.lastSeen')} {formatDate(device.lastSeenAt)}</span>
                {#if device.trustedUntil}
                  {@const daysRemaining = getDaysRemaining(device.trustedUntil)}
                  <span class="detail" class:expiring-soon={daysRemaining <= 7}>
                    {#if daysRemaining <= 0}
                      {$_('trustedDevices.expired')}
                    {:else if daysRemaining === 1}
                      {$_('trustedDevices.tomorrow')}
                    {:else}
                      {$_('trustedDevices.inDays', { values: { days: daysRemaining } })}
                    {/if}
                  </span>
                {/if}
              </div>

              <button type="button" class="sm danger-outline" onclick={() => handleRevokeDevice(device.id)}>
                {$_('trustedDevices.revoke')}
              </button>
            </div>
          {/each}
        </div>
      {/if}
    </section>
  {/if}
</div>

<ReauthModal
  bind:show={showReauthModal}
  availableMethods={reauthMethods}
  onSuccess={handleReauthSuccess}
  onCancel={handleReauthCancel}
/>

<style>
  .security {
    max-width: var(--width-lg);
  }

  .loading {
    color: var(--text-secondary);
    padding: var(--space-4);
  }

  section {
    background: var(--bg-secondary);
    padding: var(--space-5);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-5);
  }

  section h3 {
    margin: 0 0 var(--space-4) 0;
    font-size: var(--text-base);
  }

  .status {
    display: block;
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    margin-bottom: var(--space-4);
    width: fit-content;
  }

  .status.success {
    background: var(--success-bg);
    color: var(--success-text);
  }

  .status.warning {
    background: var(--warning-bg);
    color: var(--warning-text);
  }

  .status.info {
    background: var(--accent-muted);
    color: var(--accent);
  }

  .passkey-list {
    list-style: none;
    padding: 0;
    margin: 0 0 var(--space-4) 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .passkey-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-3);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    gap: var(--space-3);
  }

  .passkey-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    min-width: 0;
  }

  .passkey-name {
    font-weight: var(--font-medium);
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
    gap: var(--space-2);
    align-items: center;
    width: 100%;
  }

  .passkey-edit input {
    flex: 1;
  }

  .add-passkey {
    display: flex;
    gap: var(--space-2);
    margin-top: var(--space-4);
    padding-top: var(--space-4);
    border-top: 1px solid var(--border-color);
  }

  .add-passkey input {
    flex: 1;
  }

  .password-actions {
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  .remove-password-form {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
  }

  .remove-password-form .warning-text {
    color: var(--error-text);
    font-size: var(--text-sm);
    margin: 0 0 var(--space-4) 0;
  }

  .remove-password-form .actions {
    display: flex;
    gap: var(--space-2);
  }

  button.small {
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-sm);
  }

  button.small.danger {
    background: transparent;
    border: 1px solid var(--error-border);
    color: var(--error-text);
  }

  button.small.danger:hover {
    background: var(--error-bg);
  }

  .setup-step {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: var(--space-4);
  }

  .setup-step p {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin: 0 0 var(--space-4) 0;
  }

  .setup-step h4 {
    margin: 0 0 var(--space-2) 0;
  }

  .qr-container {
    display: flex;
    justify-content: center;
    margin: var(--space-4) 0;
  }

  .qr-code {
    width: 180px;
    height: 180px;
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

  .code-input {
    font-size: var(--text-xl);
    letter-spacing: 0.3em;
    text-align: center;
    max-width: 180px;
    margin: 0 auto var(--space-4) auto;
    display: block;
  }

  .actions {
    display: flex;
    gap: var(--space-2);
    margin-top: var(--space-4);
  }

  .warning-text {
    color: var(--error-text);
    font-size: var(--text-sm);
    margin-bottom: var(--space-4);
  }

  .backup-codes {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: var(--space-2);
    margin-bottom: var(--space-4);
  }

  .backup-code {
    padding: var(--space-2);
    background: var(--bg-input);
    border-radius: var(--radius-md);
    text-align: center;
    font-size: var(--text-sm);
    font-family: var(--font-mono);
  }

  .totp-actions {
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  .inline-form {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: var(--space-4);
    margin-top: var(--space-4);
  }

  .inline-form.danger-form {
    border-color: var(--error-border);
  }

  .inline-form h4 {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-base);
  }

  .field {
    margin-bottom: var(--space-3);
  }

  .field label {
    display: block;
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
    margin-bottom: var(--space-1);
  }

  .field input {
    width: 100%;
  }

  .danger-outline {
    background: transparent;
    border: 1px solid var(--error-border);
    color: var(--error-text);
  }

  .danger-outline:hover {
    background: var(--error-bg);
  }

  button.danger {
    background: var(--error-text);
    border: 1px solid var(--error-text);
    color: white;
  }

  button.danger:hover:not(:disabled) {
    background: var(--error-border);
  }

  .empty {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin-bottom: var(--space-4);
  }

  .sso-list {
    list-style: none;
    padding: 0;
    margin: 0 0 var(--space-4) 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .sso-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-3);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    gap: var(--space-3);
  }

  .sso-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .sso-provider {
    font-weight: var(--font-medium);
  }

  .sso-id {
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .sso-meta {
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .sso-providers {
    padding-top: var(--space-4);
    border-top: 1px solid var(--border-color);
  }

  .sso-providers h4 {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .provider-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }

  .provider-btn {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-4);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    cursor: pointer;
    color: var(--text-primary);
  }

  .provider-btn:hover:not(:disabled) {
    border-color: var(--accent);
  }

  .provider-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .linked-badge {
    font-size: var(--text-xs);
    padding: var(--space-1) var(--space-2);
    background: var(--success-bg);
    color: var(--success-text);
    border-radius: var(--radius-sm);
  }

  .section-description {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin: 0 0 var(--space-4) 0;
  }

  .toggle-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-3);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
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
    width: 52px;
    height: 28px;
    padding: 0;
    background: var(--border-color);
    border: none;
    border-radius: 14px;
    cursor: pointer;
    transition: background 0.2s ease;
    flex-shrink: 0;
  }

  .toggle-button.on {
    background: var(--accent);
  }

  .toggle-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .toggle-slider {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 24px;
    height: 24px;
    background: white;
    border-radius: 50%;
    transition: transform 0.2s ease;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
  }

  .toggle-button.on .toggle-slider {
    transform: translateX(24px);
  }

  .warning-box {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius-md);
    padding: var(--space-3);
    margin-bottom: var(--space-4);
  }

  .warning-box strong {
    color: var(--warning-text);
    font-size: var(--text-sm);
  }

  .info-box {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: var(--space-3);
  }

  .info-box strong {
    font-size: var(--text-sm);
    display: block;
    margin-bottom: var(--space-1);
  }

  .info-box p {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin: 0;
  }

  .empty-hint {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin: 0;
  }

  .hint-text {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin: var(--space-2) 0 0 0;
  }

  .device-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .device-card {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
  }

  .device-header {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    flex: 1;
    min-width: 0;
  }

  .device-name {
    font-weight: var(--font-medium);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .edit-name-input {
    flex: 1;
    padding: var(--space-2);
    font-size: var(--text-sm);
    min-width: 0;
  }

  .edit-actions {
    display: flex;
    gap: var(--space-2);
    flex-shrink: 0;
  }

  .icon-btn {
    background: none;
    border: none;
    padding: var(--space-1);
    cursor: pointer;
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  .icon-btn:hover {
    color: var(--accent);
  }

  .device-details {
    display: flex;
    gap: var(--space-3);
    flex-shrink: 0;
  }

  .device-details .detail {
    font-size: var(--text-xs);
    color: var(--text-secondary);
    white-space: nowrap;
  }

  .device-details .expiring-soon {
    color: var(--warning-text);
  }

  button.danger-outline {
    background: transparent;
    border: 1px solid var(--error-border);
    color: var(--error-text);
  }

  button.danger-outline:hover {
    background: var(--error-bg);
  }

  @media (max-width: 500px) {
    .passkey-item {
      flex-direction: column;
      align-items: stretch;
    }

    .passkey-actions {
      width: 100%;
    }

    .passkey-actions button {
      flex: 1;
    }

    .add-passkey {
      flex-direction: column;
    }

    .device-card {
      flex-direction: column;
      align-items: stretch;
    }

    .device-details {
      flex-direction: column;
      gap: var(--space-1);
    }

    .device-card > button {
      width: 100%;
    }
  }
</style>
