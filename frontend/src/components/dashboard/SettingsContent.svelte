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

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  const supportedLocales = getSupportedLocales()
  let pdsHostname = $state<string | null>(null)

  onMount(() => {
    const init = async () => {
      try {
        const info = await api.describeServer()
        if (info.availableUserDomains?.length) {
          pdsHostname = info.availableUserDomains[0]
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
      const fullHandle = showBYOHandle ? newHandle : `${newHandle}.${pdsHostname}`
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
          <div class="field">
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
        <div class="field">
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
        <div class="field">
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
          <div class="field">
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
        <div class="field">
          <label for="new-handle">{$_('settings.newHandle')}</label>
          <div class="handle-input-wrapper">
            <input id="new-handle" type="text" bind:value={newHandle} placeholder={$_('settings.newHandlePlaceholder')} disabled={handleLoading} required />
            <span class="handle-suffix">.{pdsHostname ?? '...'}</span>
          </div>
        </div>
        <button type="submit" disabled={handleLoading || !newHandle || !pdsHostname}>
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
                <button class="small" onclick={() => handleDownloadBackup(backup.id, backup.repoRev)}>
                  {$_('settings.backups.download')}
                </button>
                <button class="small danger" onclick={() => handleDeleteBackup(backup.id)}>
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
        <div class="field">
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
        <div class="field">
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

<style>
  .settings {
    max-width: var(--width-lg);
  }

  section {
    background: var(--bg-secondary);
    padding: var(--space-5);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-5);
  }

  section h3 {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-base);
  }

  .current {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin: 0 0 var(--space-3) 0;
  }

  .language-select {
    width: 100%;
  }

  .field {
    margin-bottom: var(--space-3);
  }

  .field label {
    display: block;
    margin-bottom: var(--space-1);
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
  }

  .actions {
    display: flex;
    gap: var(--space-2);
    margin-top: var(--space-3);
  }

  .tabs {
    display: flex;
    gap: var(--space-1);
    margin-bottom: var(--space-4);
  }

  .tab {
    flex: 1;
    padding: var(--space-2) var(--space-4);
    background: transparent;
    border: 1px solid var(--border-color);
    cursor: pointer;
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .tab:first-child {
    border-radius: var(--radius-md) 0 0 var(--radius-md);
  }

  .tab:last-child {
    border-radius: 0 var(--radius-md) var(--radius-md) 0;
  }

  .tab.active {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--text-inverse);
  }

  .handle-input-wrapper {
    display: flex;
    align-items: center;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  .handle-input-wrapper input {
    flex: 1;
    border: none;
    border-radius: 0;
    background: transparent;
  }

  .handle-input-wrapper input:focus {
    outline: none;
    box-shadow: none;
  }

  .handle-suffix {
    padding: 0 var(--space-3);
    color: var(--text-secondary);
    font-size: var(--text-sm);
    white-space: nowrap;
    border-left: 1px solid var(--border-color);
    background: var(--bg-card);
  }

  .loading,
  .empty {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin-bottom: var(--space-4);
  }

  .backup-list {
    list-style: none;
    padding: 0;
    margin: 0 0 var(--space-4) 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .backup-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-3);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
  }

  .backup-info {
    display: flex;
    gap: var(--space-3);
    font-size: var(--text-sm);
  }

  .backup-date {
    font-weight: var(--font-medium);
  }

  .backup-size {
    color: var(--text-secondary);
  }

  .backup-actions {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--space-4);
    gap: var(--space-3);
    flex-wrap: wrap;
  }

  .backup-toggle {
    margin-bottom: var(--space-3);
  }

  .backup-toggle .toggle-label {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    cursor: pointer;
    font-size: var(--text-sm);
    white-space: nowrap;
  }

  .backup-toggle .toggle-label input[type="checkbox"] {
    width: 16px;
    height: 16px;
    flex-shrink: 0;
  }

  .backup-item-actions {
    display: flex;
    gap: var(--space-2);
  }

  .restore-section {
    margin-top: var(--space-5);
    padding-top: var(--space-4);
    border-top: 1px solid var(--border-color);
  }

  .restore-section h4 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
  }

  .restore-section .hint {
    margin-bottom: var(--space-3);
  }

  .restore-form {
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  .restore-form input[type="file"] {
    flex: 1;
    min-width: 200px;
  }

  .restore-preview {
    margin-top: var(--space-2);
    font-size: var(--text-sm);
    color: var(--text-secondary);
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  .restore-preview .file-name {
    font-weight: var(--font-medium);
    color: var(--text-primary);
  }

  .export-buttons {
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  button.small {
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-sm);
  }

  .danger-zone {
    border: 1px solid var(--error-border);
  }

  .danger-zone h3 {
    color: var(--error-text);
  }

  .warning-text {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin: 0 0 var(--space-4) 0;
  }

  button.danger {
    background: var(--error-text);
    border: 1px solid var(--error-text);
    color: white;
  }

  button.danger:hover:not(:disabled) {
    background: var(--error-border);
  }

  button.danger:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .hint {
    font-size: var(--text-xs);
    color: var(--text-secondary);
    margin: var(--space-1) 0 0 0;
  }

  .hint.warning {
    color: var(--warning-text);
  }

  .hint.success {
    color: var(--success-text);
    background: var(--success-bg);
    padding: var(--space-2);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-3);
  }

  .byo-handle {
    margin-top: var(--space-3);
  }

  .verification-info {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    margin-bottom: var(--space-4);
  }

  .verification-info h4 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
  }

  .verification-info h5 {
    margin: var(--space-3) 0 var(--space-1) 0;
    font-size: var(--text-xs);
    font-weight: var(--font-medium);
    color: var(--text-secondary);
  }

  .verification-info p {
    margin: var(--space-1) 0;
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .method {
    margin-top: var(--space-3);
    padding-top: var(--space-3);
    border-top: 1px solid var(--border-color);
  }

  .method:first-of-type {
    margin-top: var(--space-2);
    padding-top: 0;
    border-top: none;
  }

  code.record {
    display: block;
    background: var(--bg-input);
    padding: var(--space-2);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
    word-break: break-all;
    margin: var(--space-1) 0;
  }
</style>
