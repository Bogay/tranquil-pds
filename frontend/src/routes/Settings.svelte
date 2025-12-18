<script lang="ts">
  import { getAuthState, logout } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  const auth = getAuthState()
  let message = $state<{ type: 'success' | 'error'; text: string } | null>(null)
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
  let passwordLoading = $state(false)
  let currentPassword = $state('')
  let newPassword = $state('')
  let confirmNewPassword = $state('')
  let showBYOHandle = $state(false)
  $effect(() => {
    if (!auth.loading && !auth.session) {
      navigate('/login')
    }
  })
  function showMessage(type: 'success' | 'error', text: string) {
    message = { type, text }
    setTimeout(() => {
      if (message?.text === text) message = null
    }, 5000)
  }
  async function handleRequestEmailUpdate(e: Event) {
    e.preventDefault()
    if (!auth.session || !newEmail) return
    emailLoading = true
    message = null
    try {
      const result = await api.requestEmailUpdate(auth.session.accessJwt)
      emailTokenRequired = result.tokenRequired
      if (emailTokenRequired) {
        showMessage('success', 'Verification code sent to your current email')
      } else {
        await api.updateEmail(auth.session.accessJwt, newEmail)
        showMessage('success', 'Email updated successfully')
        newEmail = ''
      }
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : 'Failed to update email')
    } finally {
      emailLoading = false
    }
  }
  async function handleConfirmEmailUpdate(e: Event) {
    e.preventDefault()
    if (!auth.session || !newEmail || !emailToken) return
    emailLoading = true
    message = null
    try {
      await api.updateEmail(auth.session.accessJwt, newEmail, emailToken)
      showMessage('success', 'Email updated successfully')
      newEmail = ''
      emailToken = ''
      emailTokenRequired = false
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : 'Failed to update email')
    } finally {
      emailLoading = false
    }
  }
  async function handleUpdateHandle(e: Event) {
    e.preventDefault()
    if (!auth.session || !newHandle) return
    handleLoading = true
    message = null
    try {
      await api.updateHandle(auth.session.accessJwt, newHandle)
      showMessage('success', 'Handle updated successfully')
      newHandle = ''
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : 'Failed to update handle')
    } finally {
      handleLoading = false
    }
  }
  async function handleRequestDelete() {
    if (!auth.session) return
    deleteLoading = true
    message = null
    try {
      await api.requestAccountDelete(auth.session.accessJwt)
      deleteTokenSent = true
      showMessage('success', 'Deletion confirmation sent to your email')
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : 'Failed to request deletion')
    } finally {
      deleteLoading = false
    }
  }
  async function handleConfirmDelete(e: Event) {
    e.preventDefault()
    if (!auth.session || !deletePassword || !deleteToken) return
    if (!confirm('Are you absolutely sure you want to delete your account? This cannot be undone.')) {
      return
    }
    deleteLoading = true
    message = null
    try {
      await api.deleteAccount(auth.session.did, deletePassword, deleteToken)
      await logout()
      navigate('/login')
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : 'Failed to delete account')
    } finally {
      deleteLoading = false
    }
  }
  async function handleExportRepo() {
    if (!auth.session) return
    exportLoading = true
    message = null
    try {
      const response = await fetch(`/xrpc/com.atproto.sync.getRepo?did=${encodeURIComponent(auth.session.did)}`, {
        headers: {
          'Authorization': `Bearer ${auth.session.accessJwt}`
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
      a.download = `${auth.session.handle}-repo.car`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      showMessage('success', 'Repository exported successfully')
    } catch (e) {
      showMessage('error', e instanceof Error ? e.message : 'Failed to export repository')
    } finally {
      exportLoading = false
    }
  }
  async function handleChangePassword(e: Event) {
    e.preventDefault()
    if (!auth.session || !currentPassword || !newPassword || !confirmNewPassword) return
    if (newPassword !== confirmNewPassword) {
      showMessage('error', 'Passwords do not match')
      return
    }
    if (newPassword.length < 8) {
      showMessage('error', 'Password must be at least 8 characters')
      return
    }
    passwordLoading = true
    message = null
    try {
      await api.changePassword(auth.session.accessJwt, currentPassword, newPassword)
      showMessage('success', 'Password changed successfully')
      currentPassword = ''
      newPassword = ''
      confirmNewPassword = ''
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : 'Failed to change password')
    } finally {
      passwordLoading = false
    }
  }
</script>
<div class="page">
  <header>
    <a href="#/dashboard" class="back">&larr; Dashboard</a>
    <h1>Account Settings</h1>
  </header>
  {#if message}
    <div class="message {message.type}">{message.text}</div>
  {/if}
  <section>
    <h2>Change Email</h2>
    {#if auth.session?.email}
      <p class="current">Current: {auth.session.email}</p>
    {/if}
    {#if emailTokenRequired}
      <form onsubmit={handleConfirmEmailUpdate}>
        <div class="field">
          <label for="email-token">Verification Code</label>
          <input
            id="email-token"
            type="text"
            bind:value={emailToken}
            placeholder="Enter code from email"
            disabled={emailLoading}
            required
          />
        </div>
        <div class="actions">
          <button type="submit" disabled={emailLoading || !emailToken}>
            {emailLoading ? 'Updating...' : 'Confirm Email Change'}
          </button>
          <button type="button" class="secondary" onclick={() => { emailTokenRequired = false; emailToken = '' }}>
            Cancel
          </button>
        </div>
      </form>
    {:else}
      <form onsubmit={handleRequestEmailUpdate}>
        <div class="field">
          <label for="new-email">New Email</label>
          <input
            id="new-email"
            type="email"
            bind:value={newEmail}
            placeholder="new@example.com"
            disabled={emailLoading}
            required
          />
        </div>
        <button type="submit" disabled={emailLoading || !newEmail}>
          {emailLoading ? 'Requesting...' : 'Change Email'}
        </button>
      </form>
    {/if}
  </section>
  <section>
    <h2>Change Handle</h2>
    {#if auth.session}
      <p class="current">Current: @{auth.session.handle}</p>
    {/if}
    <div class="tabs">
      <button
        type="button"
        class="tab"
        class:active={!showBYOHandle}
        onclick={() => showBYOHandle = false}
      >
        PDS Handle
      </button>
      <button
        type="button"
        class="tab"
        class:active={showBYOHandle}
        onclick={() => showBYOHandle = true}
      >
        Custom Domain
      </button>
    </div>
    {#if showBYOHandle}
      <div class="byo-handle">
        <p class="description">Use your own domain as your handle. You need to verify domain ownership first.</p>
        {#if auth.session}
          <div class="verification-info">
            <h3>Setup Instructions</h3>
            <p>Choose one of these verification methods:</p>
            <div class="method">
              <h4>Option 1: DNS TXT Record (Recommended)</h4>
              <p>Add this TXT record to your domain:</p>
              <code class="record">_atproto.{newHandle || 'yourdomain.com'} TXT "did={auth.session.did}"</code>
            </div>
            <div class="method">
              <h4>Option 2: HTTP Well-Known File</h4>
              <p>Serve your DID at this URL:</p>
              <code class="record">https://{newHandle || 'yourdomain.com'}/.well-known/atproto-did</code>
              <p>The file should contain only:</p>
              <code class="record">{auth.session.did}</code>
            </div>
          </div>
        {/if}
        <form onsubmit={handleUpdateHandle}>
          <div class="field">
            <label for="new-handle-byo">Your Domain</label>
            <input
              id="new-handle-byo"
              type="text"
              bind:value={newHandle}
              placeholder="example.com"
              disabled={handleLoading}
              required
            />
          </div>
          <button type="submit" disabled={handleLoading || !newHandle}>
            {handleLoading ? 'Verifying...' : 'Verify & Update Handle'}
          </button>
        </form>
      </div>
    {:else}
      <form onsubmit={handleUpdateHandle}>
        <div class="field">
          <label for="new-handle">New Handle</label>
          <input
            id="new-handle"
            type="text"
            bind:value={newHandle}
            placeholder="yourhandle"
            disabled={handleLoading}
            required
          />
        </div>
        <button type="submit" disabled={handleLoading || !newHandle}>
          {handleLoading ? 'Updating...' : 'Change Handle'}
        </button>
      </form>
    {/if}
  </section>
  <section>
    <h2>Change Password</h2>
    <form onsubmit={handleChangePassword}>
      <div class="field">
        <label for="current-password">Current Password</label>
        <input
          id="current-password"
          type="password"
          bind:value={currentPassword}
          placeholder="Enter current password"
          disabled={passwordLoading}
          required
        />
      </div>
      <div class="field">
        <label for="new-password">New Password</label>
        <input
          id="new-password"
          type="password"
          bind:value={newPassword}
          placeholder="At least 8 characters"
          disabled={passwordLoading}
          required
          minlength="8"
        />
      </div>
      <div class="field">
        <label for="confirm-new-password">Confirm New Password</label>
        <input
          id="confirm-new-password"
          type="password"
          bind:value={confirmNewPassword}
          placeholder="Confirm new password"
          disabled={passwordLoading}
          required
        />
      </div>
      <button type="submit" disabled={passwordLoading || !currentPassword || !newPassword || !confirmNewPassword}>
        {passwordLoading ? 'Changing...' : 'Change Password'}
      </button>
    </form>
  </section>
  <section>
    <h2>Export Data</h2>
    <p class="description">Download your entire repository as a CAR (Content Addressable Archive) file. This includes all your posts, likes, follows, and other data.</p>
    <button onclick={handleExportRepo} disabled={exportLoading}>
      {exportLoading ? 'Exporting...' : 'Download Repository'}
    </button>
  </section>
  <section class="danger-zone">
    <h2>Delete Account</h2>
    <p class="warning">This action is irreversible. All your data will be permanently deleted.</p>
    {#if deleteTokenSent}
      <form onsubmit={handleConfirmDelete}>
        <div class="field">
          <label for="delete-token">Confirmation Code (from email)</label>
          <input
            id="delete-token"
            type="text"
            bind:value={deleteToken}
            placeholder="Enter confirmation code"
            disabled={deleteLoading}
            required
          />
        </div>
        <div class="field">
          <label for="delete-password">Your Password</label>
          <input
            id="delete-password"
            type="password"
            bind:value={deletePassword}
            placeholder="Enter your password"
            disabled={deleteLoading}
            required
          />
        </div>
        <div class="actions">
          <button type="submit" class="danger" disabled={deleteLoading || !deleteToken || !deletePassword}>
            {deleteLoading ? 'Deleting...' : 'Permanently Delete Account'}
          </button>
          <button type="button" class="secondary" onclick={() => { deleteTokenSent = false; deleteToken = ''; deletePassword = '' }}>
            Cancel
          </button>
        </div>
      </form>
    {:else}
      <button class="danger" onclick={handleRequestDelete} disabled={deleteLoading}>
        {deleteLoading ? 'Requesting...' : 'Request Account Deletion'}
      </button>
    {/if}
  </section>
</div>
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
  .current, .description {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin-bottom: 1rem;
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
    background: var(--bg-secondary);
  }
  button.danger {
    background: var(--error-text);
  }
  button.danger:hover:not(:disabled) {
    background: #900;
  }
  .actions {
    display: flex;
    gap: 0.5rem;
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
    font-size: 0.875rem;
    margin-bottom: 1rem;
  }
  .tabs {
    display: flex;
    gap: 0.25rem;
    margin-bottom: 1rem;
  }
  .tab {
    flex: 1;
    padding: 0.5rem 1rem;
    background: transparent;
    border: 1px solid var(--border-color-light);
    cursor: pointer;
    font-size: 0.875rem;
    color: var(--text-secondary);
  }
  .tab:first-child {
    border-radius: 4px 0 0 4px;
  }
  .tab:last-child {
    border-radius: 0 4px 4px 0;
  }
  .tab.active {
    background: var(--accent);
    border-color: var(--accent);
    color: white;
  }
  .tab:hover:not(.active) {
    background: var(--bg-card);
  }
  .byo-handle .description {
    margin-bottom: 1rem;
  }
  .verification-info {
    background: var(--bg-card);
    border: 1px solid var(--border-color-light);
    border-radius: 6px;
    padding: 1rem;
    margin-bottom: 1rem;
  }
  .verification-info h3 {
    margin: 0 0 0.5rem 0;
    font-size: 1rem;
  }
  .verification-info h4 {
    margin: 0.75rem 0 0.25rem 0;
    font-size: 0.875rem;
    color: var(--text-secondary);
  }
  .verification-info p {
    margin: 0.25rem 0;
    font-size: 0.8rem;
    color: var(--text-secondary);
  }
  .method {
    margin-top: 0.75rem;
    padding-top: 0.75rem;
    border-top: 1px solid var(--border-color-light);
  }
  .method:first-of-type {
    margin-top: 0.5rem;
    padding-top: 0;
    border-top: none;
  }
  code.record {
    display: block;
    background: var(--bg-input);
    padding: 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    word-break: break-all;
    margin: 0.25rem 0;
  }
</style>
