<script lang="ts">
  import { onMount } from 'svelte'
  import { api, ApiError } from '../../lib/api'
  import { _ } from '../../lib/i18n'
  import { formatDate } from '../../lib/date'
  import type { Session } from '../../lib/types/api'
  import { toast } from '../../lib/toast.svelte'
  import ReauthModal from '../ReauthModal.svelte'
  import SsoIcon from '../SsoIcon.svelte'
  import PasskeySection from './PasskeySection.svelte'
  import TotpSection from './TotpSection.svelte'
  import PasswordSection from './PasswordSection.svelte'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  let hasPassword = $state(true)
  let passkeyCount = $state(0)
  let totpEnabled = $state(false)

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

  function handleReauthRequired(methods: string[], retryAction: () => Promise<void>) {
    reauthMethods = methods
    pendingAction = retryAction
    showReauthModal = true
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
      loadSsoProviders(),
      loadLinkedAccounts(),
      loadLegacyLoginPreference(),
      loadTrustedDevices()
    ])
  })

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
          handleReauthRequired(e.reauthMethods || ['password'], () => handleLinkAccount(provider))
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
          handleReauthRequired(e.reauthMethods || ['password'], () => handleUnlinkAccount(id))
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
          handleReauthRequired(e.reauthMethods || ['password'], handleToggleLegacyLogin)
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
</script>

<div class="security">
  <PasskeySection
    {session}
    {hasPassword}
    onPasskeysChanged={(count) => passkeyCount = count}
  />

  <TotpSection
    {session}
    onStatusChanged={(enabled, _hasBackup) => totpEnabled = enabled}
  />

  <PasswordSection
    {session}
    {passkeyCount}
    onPasswordChanged={(has) => hasPassword = has}
    onReauthRequired={handleReauthRequired}
  />

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
                  class="sm danger-outline"
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
                <button type="button" class="icon" onclick={() => startEditDevice(device)} title={$_('security.rename')}>
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
</div>

<ReauthModal
  bind:show={showReauthModal}
  availableMethods={reauthMethods}
  onSuccess={handleReauthSuccess}
  onCancel={handleReauthCancel}
/>
