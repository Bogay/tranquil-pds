<script lang="ts">
  import { onMount } from 'svelte'
  import { _ } from '../../lib/i18n'
  import { api, ApiError } from '../../lib/api'
  import { toast } from '../../lib/toast.svelte'
  import type { Session } from '../../lib/types/api'
  import { formatDate } from '../../lib/date'
  import { unsafeAsDid } from '../../lib/types/branded'
  import {
    setServerName as setGlobalServerName,
    setColors as setGlobalColors,
    setHasLogo as setGlobalHasLogo
  } from '../../lib/serverConfig.svelte'
  import LoadMoreSentinel from '../LoadMoreSentinel.svelte'
  import { portal } from '../../lib/portal'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  interface ServerStats {
    userCount: number
    repoCount: number
    recordCount: number
    blobStorageBytes: number
  }

  interface User {
    did: string
    handle: string
    email?: string
    indexedAt: string
    emailConfirmedAt?: string
    deactivatedAt?: string
  }

  let stats = $state<ServerStats | null>(null)
  let users = $state<User[]>([])
  let loading = $state(true)
  let usersLoading = $state(false)
  let searchQuery = $state('')
  let usersCursor = $state<string | undefined>(undefined)
  let usersHasMore = $state(true)
  let searchDebounce: ReturnType<typeof setTimeout> | null = null

  let selectedUser = $state<User | null>(null)
  let userActionLoading = $state(false)
  let userDetailLoading = $state(false)

  let serverName = $state('')
  let serverNameInput = $state('')
  let primaryColor = $state('')
  let primaryColorInput = $state('')
  let primaryColorDark = $state('')
  let primaryColorDarkInput = $state('')
  let secondaryColor = $state('')
  let secondaryColorInput = $state('')
  let secondaryColorDark = $state('')
  let secondaryColorDarkInput = $state('')
  let logoCid = $state<string | null>(null)
  let originalLogoCid = $state<string | null>(null)
  let logoFile = $state<File | null>(null)
  let logoPreview = $state<string | null>(null)
  let serverConfigLoading = $state(false)

  let signalEnabled = $state(false)
  let signalLinked = $state(false)
  let signalQr = $state<string | null>(null)
  let signalLoading = $state(false)
  let signalPollTimer: ReturnType<typeof setInterval> | null = null
  let signalLinkTimeout: ReturnType<typeof setTimeout> | null = null

  function stopSignalPolling() {
    if (signalPollTimer) {
      clearInterval(signalPollTimer)
      signalPollTimer = null
    }
    if (signalLinkTimeout) {
      clearTimeout(signalLinkTimeout)
      signalLinkTimeout = null
    }
  }

  onMount(async () => {
    await Promise.all([loadStats(), loadServerConfig(), loadUsers(true), loadSignalStatus()])
    return () => stopSignalPolling()
  })

  async function loadStats() {
    loading = true
    try {
      stats = await api.getServerStats(session.accessJwt)
    } catch {
      toast.error($_('admin.failedToLoadStats'))
    } finally {
      loading = false
    }
  }

  async function loadUsers(reset = false) {
    usersLoading = true
    if (reset) {
      users = []
      usersCursor = undefined
      usersHasMore = true
    }
    try {
      const result = await api.searchAccounts(session.accessJwt, {
        handle: searchQuery || undefined,
        cursor: reset ? undefined : usersCursor,
        limit: 25,
      })
      users = reset ? result.accounts : [...users, ...result.accounts]
      usersCursor = result.cursor
      usersHasMore = !!result.cursor
    } catch {
      toast.error($_('admin.failedToLoadUsers'))
    } finally {
      usersLoading = false
    }
  }

  function onSearchInput(value: string) {
    searchQuery = value
    if (searchDebounce) clearTimeout(searchDebounce)
    searchDebounce = setTimeout(() => loadUsers(true), 300)
  }

  function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B'
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  }

  function formatNumber(num: number): string {
    return num.toLocaleString()
  }

  async function loadServerConfig() {
    try {
      const config = await api.getServerConfig()
      serverName = config.serverName
      serverNameInput = config.serverName
      primaryColor = config.primaryColor || ''
      primaryColorInput = config.primaryColor || ''
      primaryColorDark = config.primaryColorDark || ''
      primaryColorDarkInput = config.primaryColorDark || ''
      secondaryColor = config.secondaryColor || ''
      secondaryColorInput = config.secondaryColor || ''
      secondaryColorDark = config.secondaryColorDark || ''
      secondaryColorDarkInput = config.secondaryColorDark || ''
      logoCid = config.logoCid
      originalLogoCid = config.logoCid
      if (config.logoCid) {
        logoPreview = '/favicon.ico'
      }
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('admin.failedToLoadConfig'))
    }
  }

  async function saveServerConfig(e: Event) {
    e.preventDefault()
    serverConfigLoading = true
    try {
      let newLogoCid = logoCid
      if (logoFile) {
        const result = await api.uploadBlob(session.accessJwt, logoFile)
        newLogoCid = result.blob.ref.$link
      }
      await api.updateServerConfig(session.accessJwt, {
        serverName: serverNameInput,
        primaryColor: primaryColorInput,
        primaryColorDark: primaryColorDarkInput,
        secondaryColor: secondaryColorInput,
        secondaryColorDark: secondaryColorDarkInput,
        logoCid: newLogoCid ?? '',
      })
      serverName = serverNameInput
      primaryColor = primaryColorInput
      primaryColorDark = primaryColorDarkInput
      secondaryColor = secondaryColorInput
      secondaryColorDark = secondaryColorDarkInput
      logoCid = newLogoCid
      originalLogoCid = newLogoCid
      logoFile = null
      setGlobalServerName(serverNameInput)
      setGlobalColors({
        primaryColor: primaryColorInput || null,
        primaryColorDark: primaryColorDarkInput || null,
        secondaryColor: secondaryColorInput || null,
        secondaryColorDark: secondaryColorDarkInput || null,
      })
      setGlobalHasLogo(!!newLogoCid)
      toast.success($_('admin.configSaved'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('admin.failedToSaveConfig'))
    } finally {
      serverConfigLoading = false
    }
  }

  function handleLogoChange(e: Event) {
    const input = e.target as HTMLInputElement
    const file = input.files?.[0]
    if (file) {
      logoFile = file
      logoPreview = URL.createObjectURL(file)
    }
  }

  function removeLogo() {
    logoFile = null
    logoCid = null
    logoPreview = null
  }

  function hasConfigChanges(): boolean {
    const logoChanged = logoFile !== null || logoCid !== originalLogoCid
    return serverNameInput !== serverName ||
      primaryColorInput !== primaryColor ||
      primaryColorDarkInput !== primaryColorDark ||
      secondaryColorInput !== secondaryColor ||
      secondaryColorDarkInput !== secondaryColorDark ||
      logoChanged
  }

  let signalPollErrors = $state(0)

  async function loadSignalStatus() {
    if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return
    try {
      const status = await api.getSignalStatus(session.accessJwt)
      signalEnabled = status.enabled
      signalLinked = status.linked
      signalPollErrors = 0
      if (signalLinked && signalQr) {
        signalQr = null
        stopSignalPolling()
        toast.success($_('admin.signalLinkSuccess'))
      }
    } catch (e) {
      signalPollErrors += 1
      if (signalPollErrors >= 3 && signalQr) {
        stopSignalPolling()
        signalQr = null
        toast.error(e instanceof ApiError ? e.message : $_('admin.signalFailedToLoad'))
      }
    }
  }

  async function linkSignal() {
    signalLoading = true
    try {
      const result = await api.linkSignalDevice(session.accessJwt)
      signalQr = result.qrBase64
      signalPollTimer = setInterval(() => loadSignalStatus(), 2000)
      signalLinkTimeout = setTimeout(() => {
        if (!signalLinked) {
          signalQr = null
          stopSignalPolling()
          toast.error($_('admin.signalLinkTimedOut'))
        }
      }, 130_000)
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('admin.signalLinkFailed'))
    } finally {
      signalLoading = false
    }
  }

  async function unlinkSignal() {
    if (!confirm($_('admin.signalUnlinkConfirm'))) return
    signalLoading = true
    try {
      await api.unlinkSignalDevice(session.accessJwt)
      signalLinked = false
      toast.success($_('admin.signalUnlinkSuccess'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('admin.signalUnlinkFailed'))
    } finally {
      signalLoading = false
    }
  }

  async function showUserDetail(user: User) {
    selectedUser = user
    userDetailLoading = true
    try {
      const details = await api.getAccountInfo(session.accessJwt, unsafeAsDid(user.did))
      selectedUser = {
        did: details.did,
        handle: details.handle,
        email: details.email,
        indexedAt: details.indexedAt,
        emailConfirmedAt: details.emailConfirmedAt,
        deactivatedAt: details.deactivatedAt,
      }
    } catch {
    } finally {
      userDetailLoading = false
    }
  }

  function closeUserDetail() {
    selectedUser = null
  }

  async function deleteUserAccount() {
    if (!selectedUser) return
    if (!confirm($_('admin.deleteConfirm', { values: { handle: selectedUser.handle } }))) return
    userActionLoading = true
    try {
      await api.adminDeleteAccount(session.accessJwt, unsafeAsDid(selectedUser.did))
      users = users.filter(u => u.did !== selectedUser!.did)
      selectedUser = null
      toast.success($_('admin.userDeleted'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('admin.failedToDeleteAccount'))
    } finally {
      userActionLoading = false
    }
  }
</script>

<div class="admin">
  <section class="config-section">
    <h3>{$_('admin.serverConfig')}</h3>
    <form onsubmit={saveServerConfig}>
      <div>
        <label for="server-name">{$_('admin.serverName')}</label>
        <input
          id="server-name"
          type="text"
          bind:value={serverNameInput}
          placeholder={$_('admin.serverNamePlaceholder')}
          disabled={serverConfigLoading}
        />
        <span class="field-help">{$_('admin.serverNameHelp')}</span>
      </div>

      <div>
        <label for="server-logo">{$_('admin.serverLogo')}</label>
        <div class="logo-section">
          {#if logoPreview}
            <div class="logo-preview">
              <img src={logoPreview} alt={$_('admin.logoPreview')} />
              <button type="button" class="remove-logo" onclick={removeLogo}>
                {$_('admin.removeLogo')}
              </button>
            </div>
          {/if}
          <input id="server-logo" type="file" accept="image/*" onchange={handleLogoChange} disabled={serverConfigLoading} />
        </div>
        <span class="field-help">{$_('admin.logoHelp')}</span>
      </div>

      <div class="colors-grid">
        <h4>{$_('admin.themeColors')}</h4>
        <span class="field-help">{$_('admin.themeColorsHint')}</span>
        <div class="color-fields">
          <div class="color-field">
            <label for="primary-light">{$_('admin.primaryLight')}</label>
            <div class="color-input-row">
              <input type="color" bind:value={primaryColorInput} disabled={serverConfigLoading} />
              <input id="primary-light" type="text" bind:value={primaryColorInput} placeholder="#1A1D1D" disabled={serverConfigLoading} />
            </div>
          </div>
          <div class="color-field">
            <label for="primary-dark">{$_('admin.primaryDark')}</label>
            <div class="color-input-row">
              <input type="color" bind:value={primaryColorDarkInput} disabled={serverConfigLoading} />
              <input id="primary-dark" type="text" bind:value={primaryColorDarkInput} placeholder="#E6E8E8" disabled={serverConfigLoading} />
            </div>
          </div>
          <div class="color-field">
            <label for="secondary-light">{$_('admin.secondaryLight')}</label>
            <div class="color-input-row">
              <input type="color" bind:value={secondaryColorInput} disabled={serverConfigLoading} />
              <input id="secondary-light" type="text" bind:value={secondaryColorInput} placeholder="#1A1D1D" disabled={serverConfigLoading} />
            </div>
          </div>
          <div class="color-field">
            <label for="secondary-dark">{$_('admin.secondaryDark')}</label>
            <div class="color-input-row">
              <input type="color" bind:value={secondaryColorDarkInput} disabled={serverConfigLoading} />
              <input id="secondary-dark" type="text" bind:value={secondaryColorDarkInput} placeholder="#E6E8E8" disabled={serverConfigLoading} />
            </div>
          </div>
        </div>
      </div>

      <button type="submit" disabled={serverConfigLoading || !hasConfigChanges()}>
        {serverConfigLoading ? $_('common.saving') : $_('admin.saveConfig')}
      </button>
    </form>
  </section>

  {#if signalEnabled}
    <section class="config-section">
      <div class="section-header-row">
        <h3>{$_('admin.signalIntegration')}</h3>
        {#if signalLinked}
          <span class="badge verified">{$_('admin.signalLinked')}</span>
        {:else if !signalQr}
          <span class="badge unverified">{$_('admin.signalNotLinked')}</span>
        {/if}
      </div>

      {#if signalQr}
        <div class="qr-container">
          <p>{$_('admin.signalLinking')}</p>
          <img src="data:image/png;base64,{signalQr}" alt="Signal QR" class="qr-code" />
        </div>
      {:else if signalLinked}
        <button type="button" class="danger sm" onclick={unlinkSignal} disabled={signalLoading}>
          {$_('admin.signalUnlinkDevice')}
        </button>
      {:else}
        <button type="button" onclick={linkSignal} disabled={signalLoading}>
          {signalLoading ? $_('common.loading') : $_('admin.signalLinkDevice')}
        </button>
      {/if}
    </section>
  {/if}

  <section class="stats-section">
    <div class="section-header-row">
      <h3>{$_('admin.serverStats')}</h3>
      <button type="button" class="sm tertiary" onclick={loadStats} disabled={loading}>
        {$_('admin.refreshStats')}
      </button>
    </div>
    {#if loading}
      <div class="loading">{$_('common.loading')}</div>
    {:else if stats}
      <div class="stats-grid">
        <div class="stat-item">
          <span class="stat-value">{formatNumber(stats.userCount)}</span>
          <span class="stat-label">{$_('admin.users')}</span>
        </div>
        <div class="stat-item">
          <span class="stat-value">{formatNumber(stats.repoCount)}</span>
          <span class="stat-label">{$_('admin.repos')}</span>
        </div>
        <div class="stat-item">
          <span class="stat-value">{formatNumber(stats.recordCount)}</span>
          <span class="stat-label">{$_('admin.records')}</span>
        </div>
        <div class="stat-item">
          <span class="stat-value">{formatBytes(stats.blobStorageBytes)}</span>
          <span class="stat-label">{$_('admin.blobStorage')}</span>
        </div>
      </div>
    {/if}
  </section>

  <section class="users-section">
    <h3>{$_('admin.userManagement')}</h3>

    <input
      type="text"
      value={searchQuery}
      oninput={(e) => onSearchInput(e.currentTarget.value)}
      placeholder={$_('admin.searchPlaceholder')}
    />

    {#if users.length === 0 && !usersLoading}
      <p class="empty">{$_('admin.searchToSeeUsers')}</p>
    {:else}
      <ul class="user-list">
        {#each users as user}
          <li class="user-item">
            <button type="button" class="user-item-btn" onclick={() => showUserDetail(user)}>
              <div class="user-info">
                <span class="user-handle">@{user.handle}</span>
                <span class="user-did">{user.did}</span>
                {#if user.email}
                  <span class="user-email">{user.email}</span>
                {/if}
                <span class="user-date">{$_('admin.created')}: {formatDate(user.indexedAt)}</span>
              </div>
              <div class="user-badges">
                {#if user.emailConfirmedAt}
                  <span class="badge verified">{$_('admin.verified')}</span>
                {:else}
                  <span class="badge unverified">{$_('admin.unverified')}</span>
                {/if}
                {#if user.deactivatedAt}
                  <span class="badge deactivated">{$_('admin.deactivated')}</span>
                {/if}
              </div>
            </button>
          </li>
        {/each}
      </ul>
      <LoadMoreSentinel hasMore={usersHasMore} loading={usersLoading} onLoadMore={() => loadUsers(false)} />
    {/if}
  </section>

</div>

{#if selectedUser}
  <div class="modal-backdrop" use:portal onclick={closeUserDetail} onkeydown={(e) => e.key === 'Escape' && closeUserDetail()} role="presentation">
    <div class="modal" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="dialog" aria-modal="true" tabindex="-1">
      <div class="modal-header">
        <h2>{$_('admin.userDetails')}</h2>
        <button class="close-btn" onclick={closeUserDetail}>&times;</button>
      </div>
      <div class="modal-body">
        {#if userDetailLoading}
          <div class="loading">{$_('common.loading')}</div>
        {/if}
        <dl class="definition-list">
          <dt>{$_('admin.handle')}</dt>
          <dd>@{selectedUser.handle}</dd>
          <dt>{$_('admin.did')}</dt>
          <dd class="definition-mono">{selectedUser.did}</dd>
          <dt>{$_('admin.email')}</dt>
          <dd>{selectedUser.email || '-'}</dd>
          <dt>{$_('admin.created')}</dt>
          <dd>{formatDate(selectedUser.indexedAt)}</dd>
          <dt>{$_('admin.status')}</dt>
          <dd>
            {#if selectedUser.deactivatedAt}
              <span class="badge deactivated">{$_('admin.deactivated')}</span>
            {:else if selectedUser.emailConfirmedAt}
              <span class="badge verified">{$_('admin.verified')}</span>
            {:else}
              <span class="badge unverified">{$_('admin.unverified')}</span>
            {/if}
          </dd>
        </dl>
        <div class="modal-actions">
          <button
            class="danger"
            onclick={deleteUserAccount}
            disabled={userActionLoading}
          >
            {$_('admin.deleteAccount')}
          </button>
        </div>
      </div>
    </div>
  </div>
{/if}
