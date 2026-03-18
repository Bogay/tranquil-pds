<script lang="ts">
  import { onMount } from 'svelte'
  import { refreshSession, logout } from '../../lib/auth.svelte'
  import { api, ApiError } from '../../lib/api'
  import { locale, setLocale, getSupportedLocales, localeNames, _, type SupportedLocale } from '../../lib/i18n'
  import { toast } from '../../lib/toast.svelte'
  import { unsafeAsHandle } from '../../lib/types/branded'
  import type { Session } from '../../lib/types/api'
  import { getSessionEmail } from '../../lib/types/api'
  import { formatDate } from '../../lib/date'
  import { navigate, routes } from '../../lib/router.svelte'
  import HandleInput from '../HandleInput.svelte'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  const supportedLocales = getSupportedLocales()
  let availableDomains = $state<string[]>([])
  let selectedDomain = $state('')
  let pdsHostname = $derived(selectedDomain || null)

  onMount(() => {
    const init = async () => {
      try {
        const info = await api.describeServer()
        if (info.availableUserDomains?.length) {
          availableDomains = info.availableUserDomains
          selectedDomain = info.availableUserDomains[0]
        }
      } catch {}
      loadBackups()
    }
    init()
    return () => stopEmailPolling()
  })

  let localeLoading = $state(false)
  async function handleLocaleChange(newLocale: SupportedLocale) {
    setLocale(newLocale)
    localeLoading = true
    try {
      await api.updateLocale(session.accessJwt, newLocale)
    } catch {}
    localeLoading = false
  }

  let emailLoading = $state(false)
  let newEmail = $state('')
  let emailToken = $state('')
  let emailTokenRequired = $state(false)
  let emailUpdateAuthorized = $state(false)
  let emailPollingInterval = $state<ReturnType<typeof setInterval> | null>(null)
  let newEmailInUse = $state(false)

  async function checkNewEmailInUse() {
    if (!newEmail.trim() || !newEmail.includes('@')) {
      newEmailInUse = false
      return
    }
    try {
      const result = await api.checkEmailInUse(newEmail.trim())
      newEmailInUse = result.inUse
    } catch {
      newEmailInUse = false
    }
  }

  async function handleRequestEmailUpdate() {
    if (!newEmail.trim()) return
    emailLoading = true
    try {
      const result = await api.requestEmailUpdate(session.accessJwt, newEmail.trim())
      emailTokenRequired = result.tokenRequired
      if (emailTokenRequired) {
        toast.success($_('settings.messages.emailCodeSentToCurrent'))
        startEmailPolling()
      } else {
        emailTokenRequired = true
      }
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.messages.emailUpdateFailed'))
    } finally {
      emailLoading = false
    }
  }

  function startEmailPolling() {
    if (emailPollingInterval) return
    emailPollingInterval = setInterval(async () => {
      try {
        const status = await api.checkEmailUpdateStatus(session.accessJwt)
        if (status.authorized) {
          emailUpdateAuthorized = true
          stopEmailPolling()
          await completeAuthorizedEmailUpdate()
        }
      } catch {}
    }, 3000)
  }

  function stopEmailPolling() {
    if (emailPollingInterval) {
      clearInterval(emailPollingInterval)
      emailPollingInterval = null
    }
  }

  async function completeAuthorizedEmailUpdate() {
    if (!newEmail.trim()) return
    emailLoading = true
    try {
      await api.updateEmail(session.accessJwt, newEmail.trim())
      await refreshSession()
      toast.success($_('settings.messages.emailUpdated'))
      newEmail = ''
      emailToken = ''
      emailTokenRequired = false
      emailUpdateAuthorized = false
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.messages.emailUpdateFailed'))
    } finally {
      emailLoading = false
    }
  }

  async function handleConfirmEmailUpdate(e: Event) {
    e.preventDefault()
    if (!newEmail || !emailToken) return
    emailLoading = true
    try {
      await api.updateEmail(session.accessJwt, newEmail, emailToken)
      await refreshSession()
      toast.success($_('settings.messages.emailUpdated'))
      newEmail = ''
      emailToken = ''
      emailTokenRequired = false
      stopEmailPolling()
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.messages.emailUpdateFailed'))
    } finally {
      emailLoading = false
    }
  }

  let handleLoading = $state(false)
  let newHandle = $state('')
  let showBYOHandle = $state(false)

  async function handleUpdateHandle(e: Event) {
    e.preventDefault()
    if (!newHandle) return
    handleLoading = true
    try {
      const fullHandle = showBYOHandle ? newHandle : `${newHandle}.${selectedDomain}`
      await api.updateHandle(session.accessJwt, unsafeAsHandle(fullHandle))
      await refreshSession()
      toast.success($_('settings.messages.handleUpdated'))
      newHandle = ''
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.messages.handleUpdateFailed'))
    } finally {
      handleLoading = false
    }
  }

  let exportLoading = $state(false)
  let exportBlobsLoading = $state(false)

  async function handleExportRepo() {
    exportLoading = true
    try {
      const buffer = await api.getRepo(session.accessJwt, session.did)
      const blob = new Blob([buffer], { type: 'application/vnd.ipld.car' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${session.handle}-repo.car`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      toast.success($_('settings.messages.repoExported'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.messages.exportFailed'))
    } finally {
      exportLoading = false
    }
  }

  async function handleExportBlobs() {
    exportBlobsLoading = true
    try {
      const blob = await api.exportBlobs(session.accessJwt)
      if (blob.size === 0) {
        toast.success($_('settings.messages.noBlobsToExport'))
        return
      }
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${session.handle}-blobs.zip`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      toast.success($_('settings.messages.blobsExported'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.messages.exportFailed'))
    } finally {
      exportBlobsLoading = false
    }
  }

  interface BackupInfo {
    id: string
    repoRev: string
    sizeBytes: number
    createdAt: string
  }
  let backups = $state<BackupInfo[]>([])
  let backupEnabled = $state(true)
  let backupsLoading = $state(false)
  let createBackupLoading = $state(false)
  let restoreFile = $state<File | null>(null)
  let restoreLoading = $state(false)

  async function loadBackups() {
    backupsLoading = true
    try {
      const result = await api.listBackups(session.accessJwt)
      backups = result.backups
      backupEnabled = result.backupEnabled
    } catch {}
    backupsLoading = false
  }

  async function handleCreateBackup() {
    createBackupLoading = true
    try {
      await api.createBackup(session.accessJwt)
      await loadBackups()
      toast.success($_('settings.backups.created'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.backups.createFailed'))
    } finally {
      createBackupLoading = false
    }
  }

  async function handleDownloadBackup(id: string, rev: string) {
    try {
      const blob = await api.getBackup(session.accessJwt, id)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${session.handle}-${rev}.car`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.backups.downloadFailed'))
    }
  }

  function handleRestoreFileChange(e: Event) {
    const input = e.target as HTMLInputElement
    if (input.files && input.files[0]) {
      restoreFile = input.files[0]
    }
  }

  async function handleRestore() {
    if (!restoreFile) return
    restoreLoading = true
    try {
      const buffer = await restoreFile.arrayBuffer()
      const car = new Uint8Array(buffer)
      await api.importRepo(session.accessJwt, car)
      toast.success($_('settings.backups.restored'))
      restoreFile = null
      await loadBackups()
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.backups.restoreFailed'))
    } finally {
      restoreLoading = false
    }
  }

  async function handleToggleBackup() {
    const newEnabled = !backupEnabled
    backupsLoading = true
    try {
      await api.setBackupEnabled(session.accessJwt, newEnabled)
      backupEnabled = newEnabled
      toast.success(newEnabled ? $_('settings.backups.enabled') : $_('settings.backups.disabled'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.backups.toggleFailed'))
    } finally {
      backupsLoading = false
    }
  }

  async function handleDeleteBackup(id: string) {
    try {
      await api.deleteBackup(session.accessJwt, id)
      await loadBackups()
      toast.success($_('settings.backups.deleted'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.backups.deleteFailed'))
    }
  }

  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  let deleteLoading = $state(false)
  let deletePassword = $state('')
  let deleteToken = $state('')
  let deleteTokenSent = $state(false)

  async function handleRequestDelete() {
    deleteLoading = true
    try {
      await api.requestAccountDelete(session.accessJwt)
      deleteTokenSent = true
      toast.success($_('settings.messages.deletionConfirmationSent'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.messages.deletionRequestFailed'))
    } finally {
      deleteLoading = false
    }
  }

  async function handleConfirmDelete(e: Event) {
    e.preventDefault()
    if (!deletePassword || !deleteToken) return
    if (!confirm($_('settings.messages.deleteConfirmation'))) {
      return
    }
    deleteLoading = true
    try {
      await api.deleteAccount(session.did, deletePassword, deleteToken)
      await logout()
      navigate(routes.login)
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.messages.deletionFailed'))
    } finally {
      deleteLoading = false
    }
  }
</script>

<div class="settings">
  <section>
    <h3>{$_('settings.language')}</h3>
    <select
      class="language-select"
      value={$locale}
      disabled={localeLoading}
      onchange={(e) => handleLocaleChange(e.currentTarget.value as SupportedLocale)}
    >
      {#each supportedLocales as loc}
        <option value={loc}>{localeNames[loc]}</option>
      {/each}
    </select>
  </section>

  <section>
    <h3>{$_('settings.changeEmail')}</h3>
    {#if getSessionEmail(session)}
      <p class="current">{$_('settings.currentEmail', { values: { email: getSessionEmail(session) } })}</p>
    {/if}
    {#if emailTokenRequired}
      <form onsubmit={handleConfirmEmailUpdate}>
        {#if emailUpdateAuthorized}
          <p class="hint success">{$_('settings.emailUpdateAuthorized')}</p>
        {:else}
          <div>
            <label for="email-token">{$_('settings.verificationCode')}</label>
            <input
              id="email-token"
              type="text"
              bind:value={emailToken}
              placeholder={$_('settings.verificationCodePlaceholder')}
              disabled={emailLoading}
            />
            <p class="hint">{$_('settings.emailTokenHint')}</p>
          </div>
        {/if}
        <div>
          <label for="new-email">{$_('settings.newEmail')}</label>
          <input
            id="new-email"
            type="email"
            bind:value={newEmail}
            onblur={checkNewEmailInUse}
            placeholder={$_('settings.newEmailPlaceholder')}
            disabled={emailLoading || emailUpdateAuthorized}
            required
          />
          {#if newEmailInUse}
            <p class="hint warning">{$_('settings.emailInUseWarning')}</p>
          {/if}
        </div>
        <div class="actions">
          <button type="submit" disabled={emailLoading || (!emailToken && !emailUpdateAuthorized) || !newEmail}>
            {emailLoading ? $_('settings.updating') : $_('settings.confirmEmailChange')}
          </button>
          <button type="button" class="secondary" onclick={() => { emailTokenRequired = false; emailToken = ''; newEmail = ''; emailUpdateAuthorized = false; stopEmailPolling() }}>
            {$_('common.cancel')}
          </button>
        </div>
      </form>
    {:else}
      <form onsubmit={(e) => { e.preventDefault(); handleRequestEmailUpdate() }}>
        <div>
          <label for="new-email">{$_('settings.newEmail')}</label>
          <input
            id="new-email"
            type="email"
            bind:value={newEmail}
            onblur={checkNewEmailInUse}
            placeholder={$_('settings.newEmailPlaceholder')}
            disabled={emailLoading}
            required
          />
          {#if newEmailInUse}
            <p class="hint warning">{$_('settings.emailInUseWarning')}</p>
          {/if}
        </div>
        <button type="submit" disabled={emailLoading || !newEmail.trim()}>
          {emailLoading ? $_('settings.requesting') : $_('settings.changeEmailButton')}
        </button>
      </form>
    {/if}
  </section>

  <section>
    <h3>{$_('settings.changeHandle')}</h3>
    <p class="current">{$_('settings.currentHandle', { values: { handle: session.handle } })}</p>
    <div class="tabs">
      <button type="button" class="tab" class:active={!showBYOHandle} onclick={() => showBYOHandle = false}>
        {$_('settings.pdsHandle')}
      </button>
      <button type="button" class="tab" class:active={showBYOHandle} onclick={() => showBYOHandle = true}>
        {$_('settings.customDomain')}
      </button>
    </div>
    {#if showBYOHandle}
      <div class="byo-handle">
        <div class="verification-info">
          <h4>{$_('settings.setupInstructions')}</h4>
          <p>{$_('settings.setupMethodsIntro')}</p>
          <div class="method">
            <h5>{$_('settings.dnsMethod')}</h5>
            <p>{$_('settings.dnsMethodDesc')}</p>
            <code class="record">_atproto.{newHandle || 'yourdomain.com'} TXT "did={session.did}"</code>
          </div>
          <div class="method">
            <h5>{$_('settings.httpMethod')}</h5>
            <p>{$_('settings.httpMethodDesc')}</p>
            <code class="record">https://{newHandle || 'yourdomain.com'}/.well-known/atproto-did</code>
            <p>{$_('settings.httpMethodContent')}</p>
            <code class="record">{session.did}</code>
          </div>
        </div>
        <form onsubmit={handleUpdateHandle}>
          <div>
            <label for="new-handle-byo">{$_('settings.yourDomain')}</label>
            <input id="new-handle-byo" type="text" bind:value={newHandle} placeholder={$_('settings.yourDomainPlaceholder')} disabled={handleLoading} required />
          </div>
          <button type="submit" disabled={handleLoading || !newHandle}>
            {handleLoading ? $_('common.verifying') : $_('settings.verifyAndUpdate')}
          </button>
        </form>
      </div>
    {:else}
      <form onsubmit={handleUpdateHandle}>
        <div>
          <label for="new-handle">{$_('settings.newHandle')}</label>
          <HandleInput
            id="new-handle"
            value={newHandle}
            domains={availableDomains}
            {selectedDomain}
            placeholder={$_('settings.newHandlePlaceholder')}
            disabled={handleLoading}
            onInput={(v) => { newHandle = v }}
            onDomainChange={(d) => { selectedDomain = d }}
          />
        </div>
        <button type="submit" disabled={handleLoading || !newHandle || !selectedDomain}>
          {handleLoading ? $_('settings.updating') : $_('settings.changeHandleButton')}
        </button>
      </form>
    {/if}
  </section>

  <section>
    <h3>{$_('settings.exportData')}</h3>
    <div class="export-buttons">
      <button onclick={handleExportRepo} disabled={exportLoading}>
        {exportLoading ? $_('settings.exporting') : $_('settings.downloadRepo')}
      </button>
      <button class="secondary" onclick={handleExportBlobs} disabled={exportBlobsLoading}>
        {exportBlobsLoading ? $_('settings.exporting') : $_('settings.downloadBlobs')}
      </button>
    </div>
  </section>

  <section>
    <h3>{$_('settings.backups.title')}</h3>
    {#if backupsLoading}
      <div class="loading">{$_('common.loading')}</div>
    {:else}
      {#if backups.length > 0}
        <ul class="backup-list">
          {#each backups as backup}
            <li class="backup-item">
              <div class="backup-info">
                <span class="backup-date">{formatDate(backup.createdAt)}</span>
                <span class="backup-size">{formatBytes(backup.sizeBytes)}</span>
              </div>
              <div class="backup-item-actions">
                <button class="sm" onclick={() => handleDownloadBackup(backup.id, backup.repoRev)}>
                  {$_('settings.backups.download')}
                </button>
                <button class="sm danger-outline" onclick={() => handleDeleteBackup(backup.id)}>
                  {$_('settings.backups.delete')}
                </button>
              </div>
            </li>
          {/each}
        </ul>
      {:else}
        <p class="empty">{$_('settings.backups.noBackups')}</p>
      {/if}
      <div class="backup-toggle">
        <label class="toggle-label">
          <input type="checkbox" checked={backupEnabled} onchange={handleToggleBackup} disabled={backupsLoading} />
          {$_('settings.backups.autoBackup')}
        </label>
      </div>
      <div class="backup-actions">
        <button onclick={handleCreateBackup} disabled={createBackupLoading || !backupEnabled}>
          {createBackupLoading ? $_('common.creating') : $_('settings.backups.createNow')}
        </button>
      </div>

      <div class="restore-section">
        <h4>{$_('settings.backups.restoreTitle')}</h4>
        <p class="hint">{$_('settings.backups.restoreHint')}</p>
        <div class="restore-form">
          <input
            type="file"
            accept=".car"
            onchange={handleRestoreFileChange}
            disabled={restoreLoading}
          />
          <button
            onclick={handleRestore}
            disabled={restoreLoading || !restoreFile}
          >
            {restoreLoading ? $_('settings.backups.restoring') : $_('settings.backups.restore')}
          </button>
        </div>
        {#if restoreFile}
          <div class="restore-preview">
            <span class="file-name">{$_('settings.backups.selectedFile')}: {restoreFile.name}</span>
            <span class="file-size">({formatBytes(restoreFile.size)})</span>
          </div>
        {/if}
      </div>
    {/if}
  </section>

  <section class="danger-zone">
    <h3>{$_('settings.deleteAccount')}</h3>
    <p class="warning-text">{$_('settings.deleteWarning')}</p>
    {#if deleteTokenSent}
      <form onsubmit={handleConfirmDelete}>
        <div>
          <label for="delete-token">{$_('settings.confirmationCode')}</label>
          <input
            id="delete-token"
            type="text"
            bind:value={deleteToken}
            placeholder={$_('settings.confirmationCodePlaceholder')}
            disabled={deleteLoading}
            required
          />
        </div>
        <div>
          <label for="delete-password">{$_('settings.yourPassword')}</label>
          <input
            id="delete-password"
            type="password"
            bind:value={deletePassword}
            placeholder={$_('settings.yourPasswordPlaceholder')}
            disabled={deleteLoading}
            required
          />
        </div>
        <div class="actions">
          <button type="submit" class="danger" disabled={deleteLoading || !deleteToken || !deletePassword}>
            {deleteLoading ? $_('settings.deleting') : $_('settings.permanentlyDelete')}
          </button>
          <button type="button" class="secondary" onclick={() => { deleteTokenSent = false; deleteToken = ''; deletePassword = '' }}>
            {$_('common.cancel')}
          </button>
        </div>
      </form>
    {:else}
      <button class="danger" onclick={handleRequestDelete} disabled={deleteLoading}>
        {deleteLoading ? $_('settings.requesting') : $_('settings.requestDeletion')}
      </button>
    {/if}
  </section>
</div>
