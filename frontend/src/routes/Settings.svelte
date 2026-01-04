<script lang="ts">
  import { onMount } from 'svelte'
  import { getAuthState, logout, refreshSession } from '../lib/auth.svelte'
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { locale, setLocale, getSupportedLocales, localeNames, _, type SupportedLocale } from '../lib/i18n'
  import { isOk } from '../lib/types/result'
  import type { Session } from '../lib/types/api'
  import { toast } from '../lib/toast.svelte'

  const auth = $derived(getAuthState())
  const supportedLocales = getSupportedLocales()
  let pdsHostname = $state<string | null>(null)

  function getSession(): Session | null {
    return auth.kind === 'authenticated' ? auth.session : null
  }

  function isLoading(): boolean {
    return auth.kind === 'loading'
  }

  const session = $derived(getSession())
  const loading = $derived(isLoading())

  onMount(() => {
    api.describeServer().then(info => {
      if (info.availableUserDomains?.length) {
        pdsHostname = info.availableUserDomains[0]
      }
    }).catch(() => {})
  })

  let localeLoading = $state(false)
  async function handleLocaleChange(newLocale: SupportedLocale) {
    if (!session) return
    setLocale(newLocale)
    localeLoading = true
    try {
      await api.updateLocale(session.accessJwt, newLocale)
    } catch (e) {
      console.error('Failed to save locale preference:', e)
    } finally {
      localeLoading = false
    }
  }

  let emailLoading = $state(false)
  let newEmail = $state('')
  let emailToken = $state('')
  let emailTokenRequired = $state(false)
  let handleLoading = $state(false)
  let newHandle = $state('')
  let deleteLoading = $state(false)
  let deletePassword = $state('')
  let deleteToken = $state('')
  let deleteTokenSent = $state(false)
  let exportLoading = $state(false)
  let exportBlobsLoading = $state(false)
  let passwordLoading = $state(false)
  let currentPassword = $state('')
  let newPassword = $state('')
  let confirmNewPassword = $state('')
  let showBYOHandle = $state(false)

  $effect(() => {
    if (!loading && !session) {
      navigate(routes.login)
    }
  })

  async function handleRequestEmailUpdate() {
    if (!session) return
    emailLoading = true
    try {
      const result = await api.requestEmailUpdate(session.accessJwt)
      emailTokenRequired = result.tokenRequired
      if (emailTokenRequired) {
        toast.success($_('settings.messages.emailCodeSentToCurrent'))
      } else {
        emailTokenRequired = true
      }
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.messages.emailUpdateFailed'))
    } finally {
      emailLoading = false
    }
  }

  async function handleConfirmEmailUpdate(e: Event) {
    e.preventDefault()
    if (!session || !newEmail || !emailToken) return
    emailLoading = true
    try {
      await api.updateEmail(session.accessJwt, newEmail, emailToken)
      await refreshSession()
      toast.success($_('settings.messages.emailUpdated'))
      newEmail = ''
      emailToken = ''
      emailTokenRequired = false
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.messages.emailUpdateFailed'))
    } finally {
      emailLoading = false
    }
  }

  async function handleUpdateHandle(e: Event) {
    e.preventDefault()
    if (!session || !newHandle) return
    handleLoading = true
    try {
      const fullHandle = showBYOHandle
        ? newHandle
        : `${newHandle}.${pdsHostname}`
      await api.updateHandle(session.accessJwt, fullHandle)
      await refreshSession()
      toast.success($_('settings.messages.handleUpdated'))
      newHandle = ''
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.messages.handleUpdateFailed'))
    } finally {
      handleLoading = false
    }
  }

  async function handleRequestDelete() {
    if (!session) return
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
    if (!session || !deletePassword || !deleteToken) return
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

  async function handleExportRepo() {
    if (!session) return
    exportLoading = true
    try {
      const response = await fetch(`/xrpc/com.atproto.sync.getRepo?did=${encodeURIComponent(session.did)}`, {
        headers: {
          'Authorization': `Bearer ${session.accessJwt}`
        }
      })
      if (!response.ok) {
        const err = await response.json().catch(() => ({ message: 'Export failed' }))
        throw new Error(err.message || 'Export failed')
      }
      const blob = await response.blob()
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
      toast.error(e instanceof Error ? e.message : $_('settings.messages.exportFailed'))
    } finally {
      exportLoading = false
    }
  }

  async function handleExportBlobs() {
    if (!session) return
    exportBlobsLoading = true
    try {
      const response = await fetch('/xrpc/_backup.exportBlobs', {
        headers: {
          'Authorization': `Bearer ${session.accessJwt}`
        }
      })
      if (!response.ok) {
        const err = await response.json().catch(() => ({ message: 'Export failed' }))
        throw new Error(err.message || 'Export failed')
      }
      const blob = await response.blob()
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
      toast.error(e instanceof Error ? e.message : $_('settings.messages.exportFailed'))
    } finally {
      exportBlobsLoading = false
    }
  }

  interface BackupInfo {
    id: string
    repoRev: string
    repoRootCid: string
    blockCount: number
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
    if (!session) return
    backupsLoading = true
    try {
      const result = await api.listBackups(session.accessJwt)
      backups = result.backups
      backupEnabled = result.backupEnabled
    } catch (e) {
      console.error('Failed to load backups:', e)
    } finally {
      backupsLoading = false
    }
  }

  onMount(() => {
    loadBackups()
  })

  async function handleToggleBackup() {
    if (!session) return
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

  async function handleCreateBackup() {
    if (!session) return
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
    if (!session) return
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

  async function handleDeleteBackup(id: string) {
    if (!session) return
    try {
      await api.deleteBackup(session.accessJwt, id)
      await loadBackups()
      toast.success($_('settings.backups.deleted'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.backups.deleteFailed'))
    }
  }

  function handleFileSelect(e: Event) {
    const input = e.target as HTMLInputElement
    if (input.files && input.files.length > 0) {
      restoreFile = input.files[0]
    }
  }

  async function handleRestore() {
    if (!session || !restoreFile) return
    restoreLoading = true
    try {
      const buffer = await restoreFile.arrayBuffer()
      const car = new Uint8Array(buffer)
      await api.importRepo(session.accessJwt, car)
      toast.success($_('settings.backups.restored'))
      restoreFile = null
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.backups.restoreFailed'))
    } finally {
      restoreLoading = false
    }
  }

  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  function formatDate(iso: string): string {
    return new Date(iso).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  async function handleChangePassword(e: Event) {
    e.preventDefault()
    if (!session || !currentPassword || !newPassword || !confirmNewPassword) return
    if (newPassword !== confirmNewPassword) {
      toast.error($_('settings.messages.passwordsDoNotMatch'))
      return
    }
    if (newPassword.length < 8) {
      toast.error($_('settings.messages.passwordTooShort'))
      return
    }
    passwordLoading = true
    try {
      await api.changePassword(session.accessJwt, currentPassword, newPassword)
      toast.success($_('settings.messages.passwordChanged'))
      currentPassword = ''
      newPassword = ''
      confirmNewPassword = ''
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('settings.messages.passwordChangeFailed'))
    } finally {
      passwordLoading = false
    }
  }
</script>
<div class="page">
  <header>
    <a href={getFullUrl(routes.dashboard)} class="back">{$_('common.backToDashboard')}</a>
    <h1>{$_('settings.title')}</h1>
  </header>
  <div class="sections-grid">
  <section>
    <h2>{$_('settings.language')}</h2>
    <p class="description">{$_('settings.languageDescription')}</p>
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
    <h2>{$_('settings.changeEmail')}</h2>
    {#if session?.email}
      <p class="current">{$_('settings.currentEmail', { values: { email: session.email } })}</p>
    {/if}
    {#if emailTokenRequired}
      <form onsubmit={handleConfirmEmailUpdate}>
        <div class="field">
          <label for="email-token">{$_('settings.verificationCode')}</label>
          <input
            id="email-token"
            type="text"
            bind:value={emailToken}
            placeholder={$_('settings.verificationCodePlaceholder')}
            disabled={emailLoading}
            required
          />
        </div>
        <div class="field">
          <label for="new-email">{$_('settings.newEmail')}</label>
          <input
            id="new-email"
            type="email"
            bind:value={newEmail}
            placeholder={$_('settings.newEmailPlaceholder')}
            disabled={emailLoading}
            required
          />
        </div>
        <div class="actions">
          <button type="submit" disabled={emailLoading || !emailToken || !newEmail}>
            {emailLoading ? $_('settings.updating') : $_('settings.confirmEmailChange')}
          </button>
          <button type="button" class="secondary" onclick={() => { emailTokenRequired = false; emailToken = ''; newEmail = '' }}>
            {$_('common.cancel')}
          </button>
        </div>
      </form>
    {:else}
      <button onclick={handleRequestEmailUpdate} disabled={emailLoading}>
        {emailLoading ? $_('settings.requesting') : $_('settings.changeEmailButton')}
      </button>
    {/if}
  </section>
  <section>
    <h2>{$_('settings.changeHandle')}</h2>
    {#if session}
      <p class="current">{$_('settings.currentHandle', { values: { handle: session.handle } })}</p>
    {/if}
    <div class="tabs">
      <button
        type="button"
        class="tab"
        class:active={!showBYOHandle}
        onclick={() => showBYOHandle = false}
      >
        {$_('settings.pdsHandle')}
      </button>
      <button
        type="button"
        class="tab"
        class:active={showBYOHandle}
        onclick={() => showBYOHandle = true}
      >
        {$_('settings.customDomain')}
      </button>
    </div>
    {#if showBYOHandle}
      <div class="byo-handle">
        <p class="description">{$_('settings.customDomainDescription')}</p>
        {#if session}
          <div class="verification-info">
            <h3>{$_('settings.setupInstructions')}</h3>
            <p>{$_('settings.setupMethodsIntro')}</p>
            <div class="method">
              <h4>{$_('settings.dnsMethod')}</h4>
              <p>{$_('settings.dnsMethodDesc')}</p>
              <code class="record">_atproto.{newHandle || 'yourdomain.com'} TXT "did={session.did}"</code>
            </div>
            <div class="method">
              <h4>{$_('settings.httpMethod')}</h4>
              <p>{$_('settings.httpMethodDesc')}</p>
              <code class="record">https://{newHandle || 'yourdomain.com'}/.well-known/atproto-did</code>
              <p>{$_('settings.httpMethodContent')}</p>
              <code class="record">{session.did}</code>
            </div>
          </div>
        {/if}
        <form onsubmit={handleUpdateHandle}>
          <div class="field">
            <label for="new-handle-byo">{$_('settings.yourDomain')}</label>
            <input
              id="new-handle-byo"
              type="text"
              bind:value={newHandle}
              placeholder={$_('settings.yourDomainPlaceholder')}
              disabled={handleLoading}
              required
            />
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
            <input
              id="new-handle"
              type="text"
              bind:value={newHandle}
              placeholder={$_('settings.newHandlePlaceholder')}
              disabled={handleLoading}
              required
            />
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
    <h2>{$_('settings.changePassword')}</h2>
    <form onsubmit={handleChangePassword}>
      <div class="field">
        <label for="current-password">{$_('settings.currentPassword')}</label>
        <input
          id="current-password"
          type="password"
          bind:value={currentPassword}
          placeholder={$_('settings.currentPasswordPlaceholder')}
          disabled={passwordLoading}
          required
        />
      </div>
      <div class="field">
        <label for="new-password">{$_('settings.newPassword')}</label>
        <input
          id="new-password"
          type="password"
          bind:value={newPassword}
          placeholder={$_('settings.newPasswordPlaceholder')}
          disabled={passwordLoading}
          required
          minlength="8"
        />
      </div>
      <div class="field">
        <label for="confirm-new-password">{$_('settings.confirmNewPassword')}</label>
        <input
          id="confirm-new-password"
          type="password"
          bind:value={confirmNewPassword}
          placeholder={$_('settings.confirmNewPasswordPlaceholder')}
          disabled={passwordLoading}
          required
        />
      </div>
      <button type="submit" disabled={passwordLoading || !currentPassword || !newPassword || !confirmNewPassword}>
        {passwordLoading ? $_('settings.changing') : $_('settings.changePasswordButton')}
      </button>
    </form>
  </section>
  <section>
    <h2>{$_('settings.exportData')}</h2>
    <p class="description">{$_('settings.exportDataDescription')}</p>
    <div class="export-buttons">
      <button onclick={handleExportRepo} disabled={exportLoading}>
        {exportLoading ? $_('settings.exporting') : $_('settings.downloadRepo')}
      </button>
      <button onclick={handleExportBlobs} disabled={exportBlobsLoading} class="secondary">
        {exportBlobsLoading ? $_('settings.exporting') : $_('settings.downloadBlobs')}
      </button>
    </div>
  </section>
  <section class="backups-section">
    <h2>{$_('settings.backups.title')}</h2>
    <p class="description">{$_('settings.backups.description')}</p>

    <label class="checkbox-label">
      <input type="checkbox" checked={backupEnabled} onchange={handleToggleBackup} disabled={backupsLoading} />
      <span>{$_('settings.backups.enableAutomatic')}</span>
    </label>

    {#if !backupsLoading && backups.length > 0}
      <ul class="backup-list">
        {#each backups as backup}
          <li class="backup-item">
            <div class="backup-info">
              <span class="backup-date">{formatDate(backup.createdAt)}</span>
              <span class="backup-size">{formatBytes(backup.sizeBytes)}</span>
              <span class="backup-blocks">{backup.blockCount} {$_('settings.backups.blocks')}</span>
            </div>
            <div class="backup-actions">
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

    <button onclick={handleCreateBackup} disabled={createBackupLoading || !backupEnabled}>
      {createBackupLoading ? $_('common.creating') : $_('settings.backups.createNow')}
    </button>
  </section>
  <section class="restore-section">
    <h2>{$_('settings.backups.restoreTitle')}</h2>
    <p class="description">{$_('settings.backups.restoreDescription')}</p>

    <div class="field">
      <label for="restore-file">{$_('settings.backups.selectFile')}</label>
      <input
        id="restore-file"
        type="file"
        accept=".car"
        onchange={handleFileSelect}
        disabled={restoreLoading}
      />
    </div>

    {#if restoreFile}
      <div class="restore-preview">
        <p>{$_('settings.backups.selectedFile')}: {restoreFile.name} ({formatBytes(restoreFile.size)})</p>
        <button onclick={handleRestore} disabled={restoreLoading} class="danger">
          {restoreLoading ? $_('settings.backups.restoring') : $_('settings.backups.restore')}
        </button>
      </div>
    {/if}
  </section>
  </div>
  <section class="danger-zone">
    <h2>{$_('settings.deleteAccount')}</h2>
    <p class="warning">{$_('settings.deleteWarning')}</p>
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

  .danger-zone {
    margin-top: var(--space-6);
  }

  section h2 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-lg);
  }

  .current,
  .description {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin-bottom: var(--space-4);
  }

  .language-select {
    width: 100%;
  }

  form > button,
  form > .actions {
    margin-top: var(--space-4);
  }

  .actions {
    display: flex;
    gap: var(--space-2);
  }

  .danger-zone {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
  }

  .danger-zone h2 {
    color: var(--error-text);
  }

  .warning {
    color: var(--error-text);
    font-size: var(--text-sm);
    margin-bottom: var(--space-4);
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

  .tab:hover:not(.active) {
    background: var(--bg-card);
  }

  .byo-handle .description {
    margin-bottom: var(--space-4);
  }

  .verification-info {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
    margin-bottom: var(--space-4);
  }

  .verification-info h3 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-base);
  }

  .verification-info h4 {
    margin: var(--space-3) 0 var(--space-1) 0;
    font-size: var(--text-sm);
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
    min-width: 0;
  }

  .handle-input-wrapper input:focus {
    outline: none;
    box-shadow: none;
  }

  .handle-input-wrapper:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-muted);
  }

  .handle-suffix {
    padding: 0 var(--space-3);
    color: var(--text-secondary);
    font-size: var(--text-sm);
    white-space: nowrap;
    border-left: 1px solid var(--border-color);
    background: var(--bg-card);
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    cursor: pointer;
    margin-bottom: var(--space-4);
  }

  .checkbox-label input[type="checkbox"] {
    width: 18px;
    height: 18px;
    cursor: pointer;
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
    gap: var(--space-4);
  }

  .backup-info {
    display: flex;
    gap: var(--space-4);
    font-size: var(--text-sm);
    flex-wrap: wrap;
  }

  .backup-date {
    font-weight: 500;
  }

  .backup-size,
  .backup-blocks {
    color: var(--text-secondary);
  }

  .backup-actions {
    display: flex;
    gap: var(--space-2);
    flex-shrink: 0;
  }

  button.small {
    padding: var(--space-1) var(--space-2);
    font-size: var(--text-xs);
  }

  .empty,
  .loading {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin-bottom: var(--space-4);
  }

  .restore-preview {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: var(--space-4);
    margin-top: var(--space-3);
  }

  .restore-preview p {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-sm);
  }

  .export-buttons {
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  @media (max-width: 640px) {
    .backup-item {
      flex-direction: column;
      align-items: flex-start;
    }

    .backup-actions {
      width: 100%;
      margin-top: var(--space-2);
    }

    .backup-actions button {
      flex: 1;
    }
  }
</style>
