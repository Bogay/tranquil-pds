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

    <form onsubmit={handleUpdateHandle}>
      <div class="field">
        <label for="new-handle">New Handle</label>
        <input
          id="new-handle"
          type="text"
          bind:value={newHandle}
          placeholder="newhandle.bsky.social"
          disabled={handleLoading}
          required
        />
      </div>
      <button type="submit" disabled={handleLoading || !newHandle}>
        {handleLoading ? 'Updating...' : 'Change Handle'}
      </button>
    </form>
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

  .current {
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
</style>
