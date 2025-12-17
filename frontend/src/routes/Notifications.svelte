<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  const auth = getAuthState()
  let loading = $state(true)
  let saving = $state(false)
  let error = $state<string | null>(null)
  let success = $state<string | null>(null)
  let preferredChannel = $state('email')
  let email = $state('')
  let discordId = $state('')
  let discordVerified = $state(false)
  let telegramUsername = $state('')
  let telegramVerified = $state(false)
  let signalNumber = $state('')
  let signalVerified = $state(false)
  let verifyingChannel = $state<string | null>(null)
  let verificationCode = $state('')
  let verificationError = $state<string | null>(null)
  let verificationSuccess = $state<string | null>(null)
  let historyLoading = $state(false)
  let historyError = $state<string | null>(null)
  let notifications = $state<Array<{
    createdAt: string
    channel: string
    notificationType: string
    status: string
    subject: string | null
    body: string
  }>>([])
  let showHistory = $state(false)
  $effect(() => {
    if (!auth.loading && !auth.session) {
      navigate('/login')
    }
  })
  $effect(() => {
    if (auth.session) {
      loadPrefs()
    }
  })
  async function loadPrefs() {
    if (!auth.session) return
    loading = true
    error = null
    try {
      const prefs = await api.getNotificationPrefs(auth.session.accessJwt)
      preferredChannel = prefs.preferredChannel
      email = prefs.email
      discordId = prefs.discordId ?? ''
      discordVerified = prefs.discordVerified
      telegramUsername = prefs.telegramUsername ?? ''
      telegramVerified = prefs.telegramVerified
      signalNumber = prefs.signalNumber ?? ''
      signalVerified = prefs.signalVerified
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to load notification preferences'
    } finally {
      loading = false
    }
  }
  async function handleSave(e: Event) {
    e.preventDefault()
    if (!auth.session) return
    saving = true
    error = null
    success = null
    try {
      await api.updateNotificationPrefs(auth.session.accessJwt, {
        preferredChannel,
        discordId: discordId || undefined,
        telegramUsername: telegramUsername || undefined,
        signalNumber: signalNumber || undefined,
      })
      success = 'Notification preferences saved'
      await loadPrefs()
    } catch (e) {
      error = e instanceof ApiError ? e.message : 'Failed to save preferences'
    } finally {
      saving = false
    }
  }
  async function handleVerify(channel: string) {
    if (!auth.session || !verificationCode) return
    verificationError = null
    verificationSuccess = null
    try {
      await api.confirmChannelVerification(auth.session.accessJwt, channel, verificationCode)
      verificationSuccess = `${channel} verified successfully`
      verificationCode = ''
      verifyingChannel = null
      await loadPrefs()
    } catch (e) {
      verificationError = e instanceof ApiError ? e.message : 'Failed to verify channel'
    }
  }
  async function loadHistory() {
    if (!auth.session) return
    historyLoading = true
    historyError = null
    try {
      const result = await api.getNotificationHistory(auth.session.accessJwt)
      notifications = result.notifications
      showHistory = true
    } catch (e) {
      historyError = e instanceof ApiError ? e.message : 'Failed to load notification history'
    } finally {
      historyLoading = false
    }
  }
  function formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleString()
  }
  const channels = [
    { id: 'email', name: 'Email', description: 'Receive notifications via email' },
    { id: 'discord', name: 'Discord', description: 'Receive notifications via Discord DM' },
    { id: 'telegram', name: 'Telegram', description: 'Receive notifications via Telegram' },
    { id: 'signal', name: 'Signal', description: 'Receive notifications via Signal' },
  ]
  function canSelectChannel(channelId: string): boolean {
    if (channelId === 'email') return true
    if (channelId === 'discord') return !!discordId
    if (channelId === 'telegram') return !!telegramUsername
    if (channelId === 'signal') return !!signalNumber
    return false
  }
  function needsVerification(channelId: string): boolean {
    if (channelId === 'discord') return !!discordId && !discordVerified
    if (channelId === 'telegram') return !!telegramUsername && !telegramVerified
    if (channelId === 'signal') return !!signalNumber && !signalVerified
    return false
  }
</script>
<div class="page">
  <header>
    <a href="#/dashboard" class="back">&larr; Dashboard</a>
    <h1>Notification Preferences</h1>
  </header>
  <p class="description">
    Choose how you want to receive important notifications like password resets,
    security alerts, and account updates.
  </p>
  {#if loading}
    <p class="loading">Loading...</p>
  {:else}
    {#if error}
      <div class="message error">{error}</div>
    {/if}
    {#if success}
      <div class="message success">{success}</div>
    {/if}
    <form onsubmit={handleSave}>
      <section>
        <h2>Preferred Channel</h2>
        <p class="section-description">
          Select your preferred way to receive notifications. You must configure a channel before you can select it.
        </p>
        <div class="channel-options">
          {#each channels as channel}
            <label class="channel-option" class:disabled={!canSelectChannel(channel.id)}>
              <input
                type="radio"
                name="preferredChannel"
                value={channel.id}
                bind:group={preferredChannel}
                disabled={!canSelectChannel(channel.id) || saving}
              />
              <div class="channel-info">
                <span class="channel-name">{channel.name}</span>
                <span class="channel-description">{channel.description}</span>
                {#if channel.id !== 'email' && !canSelectChannel(channel.id)}
                  <span class="channel-hint">Configure below to enable</span>
                {/if}
              </div>
            </label>
          {/each}
        </div>
      </section>
      <section>
        <h2>Channel Configuration</h2>
        <div class="channel-config">
          <div class="config-item">
            <label for="email">Email</label>
            <div class="config-input">
              <input
                id="email"
                type="email"
                value={email}
                disabled
                class="readonly"
              />
              <span class="status verified">Primary</span>
            </div>
            <p class="config-hint">Your email is managed in Account Settings</p>
          </div>
          <div class="config-item">
            <label for="discord">Discord User ID</label>
            <div class="config-input">
              <input
                id="discord"
                type="text"
                bind:value={discordId}
                placeholder="e.g., 123456789012345678"
                disabled={saving}
              />
              {#if discordId}
                {#if discordVerified}
                  <span class="status verified">Verified</span>
                {:else}
                  <span class="status unverified">Not verified</span>
                  <button type="button" class="verify-btn" onclick={() => verifyingChannel = 'discord'}>Verify</button>
                {/if}
              {/if}
            </div>
            <p class="config-hint">Your Discord user ID (not username). Enable Developer Mode in Discord to copy it.</p>
            {#if verifyingChannel === 'discord'}
              <div class="verify-form">
                <input
                  type="text"
                  bind:value={verificationCode}
                  placeholder="Enter verification code"
                  maxlength="6"
                />
                <button type="button" onclick={() => handleVerify('discord')}>Submit</button>
                <button type="button" class="cancel" onclick={() => { verifyingChannel = null; verificationCode = '' }}>Cancel</button>
              </div>
            {/if}
          </div>
          <div class="config-item">
            <label for="telegram">Telegram Username</label>
            <div class="config-input">
              <input
                id="telegram"
                type="text"
                bind:value={telegramUsername}
                placeholder="e.g., username"
                disabled={saving}
              />
              {#if telegramUsername}
                {#if telegramVerified}
                  <span class="status verified">Verified</span>
                {:else}
                  <span class="status unverified">Not verified</span>
                  <button type="button" class="verify-btn" onclick={() => verifyingChannel = 'telegram'}>Verify</button>
                {/if}
              {/if}
            </div>
            <p class="config-hint">Your Telegram username without the @ symbol</p>
            {#if verifyingChannel === 'telegram'}
              <div class="verify-form">
                <input
                  type="text"
                  bind:value={verificationCode}
                  placeholder="Enter verification code"
                  maxlength="6"
                />
                <button type="button" onclick={() => handleVerify('telegram')}>Submit</button>
                <button type="button" class="cancel" onclick={() => { verifyingChannel = null; verificationCode = '' }}>Cancel</button>
              </div>
            {/if}
          </div>
          <div class="config-item">
            <label for="signal">Signal Phone Number</label>
            <div class="config-input">
              <input
                id="signal"
                type="tel"
                bind:value={signalNumber}
                placeholder="e.g., +1234567890"
                disabled={saving}
              />
              {#if signalNumber}
                {#if signalVerified}
                  <span class="status verified">Verified</span>
                {:else}
                  <span class="status unverified">Not verified</span>
                  <button type="button" class="verify-btn" onclick={() => verifyingChannel = 'signal'}>Verify</button>
                {/if}
              {/if}
            </div>
            <p class="config-hint">Your Signal phone number with country code</p>
            {#if verifyingChannel === 'signal'}
              <div class="verify-form">
                <input
                  type="text"
                  bind:value={verificationCode}
                  placeholder="Enter verification code"
                  maxlength="6"
                />
                <button type="button" onclick={() => handleVerify('signal')}>Submit</button>
                <button type="button" class="cancel" onclick={() => { verifyingChannel = null; verificationCode = '' }}>Cancel</button>
              </div>
            {/if}
          </div>
        </div>
        {#if verificationError}
          <div class="message error" style="margin-top: 1rem">{verificationError}</div>
        {/if}
        {#if verificationSuccess}
          <div class="message success" style="margin-top: 1rem">{verificationSuccess}</div>
        {/if}
      </section>
      <div class="actions">
        <button type="submit" disabled={saving}>
          {saving ? 'Saving...' : 'Save Preferences'}
        </button>
      </div>
    </form>
    <section class="history-section">
      <h2>Notification History</h2>
      <p class="section-description">View recent notifications sent to your account.</p>
      {#if !showHistory}
        <button class="load-history" onclick={loadHistory} disabled={historyLoading}>
          {historyLoading ? 'Loading...' : 'Load History'}
        </button>
      {:else}
        <button class="load-history" onclick={() => showHistory = false}>Hide History</button>
        {#if historyError}
          <div class="message error">{historyError}</div>
        {:else if notifications.length === 0}
          <p class="no-notifications">No notifications found.</p>
        {:else}
          <div class="notification-list">
            {#each notifications as notification}
              <div class="notification-item">
                <div class="notification-header">
                  <span class="notification-type">{notification.notificationType}</span>
                  <span class="notification-channel">{notification.channel}</span>
                  <span class="notification-status" class:sent={notification.status === 'sent'} class:failed={notification.status === 'failed'}>{notification.status}</span>
                </div>
                {#if notification.subject}
                  <div class="notification-subject">{notification.subject}</div>
                {/if}
                <div class="notification-body">{notification.body}</div>
                <div class="notification-date">{formatDate(notification.createdAt)}</div>
              </div>
            {/each}
          </div>
        {/if}
      {/if}
    </section>
  {/if}
</div>
<style>
  .page {
    max-width: 600px;
    margin: 0 auto;
    padding: 2rem;
  }
  header {
    margin-bottom: 1rem;
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
  .description {
    color: var(--text-secondary);
    margin-bottom: 2rem;
  }
  .loading {
    text-align: center;
    color: var(--text-secondary);
    padding: 2rem;
  }
  .message {
    padding: 0.75rem;
    border-radius: 4px;
    margin-bottom: 1rem;
  }
  .message.error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-text);
  }
  .message.success {
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    color: var(--success-text);
  }
  section {
    background: var(--bg-secondary);
    padding: 1.5rem;
    border-radius: 8px;
    margin-bottom: 1.5rem;
  }
  section h2 {
    margin: 0 0 0.5rem 0;
    font-size: 1.125rem;
  }
  .section-description {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin: 0 0 1rem 0;
  }
  .channel-options {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .channel-option {
    display: flex;
    align-items: flex-start;
    gap: 0.75rem;
    padding: 0.75rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    cursor: pointer;
    transition: border-color 0.15s;
  }
  .channel-option:hover:not(.disabled) {
    border-color: var(--accent);
  }
  .channel-option.disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .channel-option input {
    margin-top: 0.25rem;
  }
  .channel-info {
    display: flex;
    flex-direction: column;
    gap: 0.125rem;
  }
  .channel-name {
    font-weight: 500;
  }
  .channel-description {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }
  .channel-hint {
    font-size: 0.75rem;
    color: var(--text-muted);
    font-style: italic;
  }
  .channel-config {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }
  .config-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .config-item label {
    font-size: 0.875rem;
    font-weight: 500;
  }
  .config-input {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .config-input input {
    flex: 1;
    padding: 0.75rem;
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    font-size: 1rem;
    background: var(--bg-input);
    color: var(--text-primary);
  }
  .config-input input:focus {
    outline: none;
    border-color: var(--accent);
  }
  .config-input input.readonly {
    background: var(--bg-input-disabled);
    color: var(--text-secondary);
  }
  .status {
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    white-space: nowrap;
  }
  .status.verified {
    background: var(--success-bg);
    color: var(--success-text);
  }
  .status.unverified {
    background: var(--warning-bg);
    color: var(--warning-text);
  }
  .config-hint {
    font-size: 0.75rem;
    color: var(--text-secondary);
    margin: 0;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
  }
  .actions button {
    padding: 0.75rem 2rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
  }
  .actions button:hover:not(:disabled) {
    background: var(--accent-hover);
  }
  .actions button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .verify-btn {
    padding: 0.25rem 0.5rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 0.75rem;
    cursor: pointer;
  }
  .verify-btn:hover {
    background: var(--accent-hover);
  }
  .verify-form {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.5rem;
    align-items: center;
  }
  .verify-form input {
    padding: 0.5rem;
    border: 1px solid var(--border-color-light);
    border-radius: 4px;
    font-size: 0.875rem;
    width: 150px;
    background: var(--bg-input);
    color: var(--text-primary);
  }
  .verify-form button {
    padding: 0.5rem 0.75rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 0.875rem;
    cursor: pointer;
  }
  .verify-form button:hover {
    background: var(--accent-hover);
  }
  .verify-form button.cancel {
    background: transparent;
    border: 1px solid var(--border-color);
    color: var(--text-secondary);
  }
  .verify-form button.cancel:hover {
    background: var(--bg-secondary);
  }
  .history-section {
    background: var(--bg-secondary);
    padding: 1.5rem;
    border-radius: 8px;
    margin-top: 1.5rem;
  }
  .history-section h2 {
    margin: 0 0 0.5rem 0;
    font-size: 1.125rem;
  }
  .load-history {
    padding: 0.5rem 1rem;
    background: transparent;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    cursor: pointer;
    color: var(--text-primary);
    margin-top: 0.5rem;
  }
  .load-history:hover:not(:disabled) {
    background: var(--bg-card);
    border-color: var(--accent);
  }
  .load-history:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .no-notifications {
    color: var(--text-secondary);
    font-style: italic;
    margin-top: 1rem;
  }
  .notification-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    margin-top: 1rem;
  }
  .notification-item {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    padding: 0.75rem;
  }
  .notification-header {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 0.5rem;
    flex-wrap: wrap;
    align-items: center;
  }
  .notification-type {
    font-weight: 500;
    font-size: 0.875rem;
  }
  .notification-channel {
    font-size: 0.75rem;
    padding: 0.125rem 0.375rem;
    background: var(--bg-secondary);
    border-radius: 4px;
    color: var(--text-secondary);
  }
  .notification-status {
    font-size: 0.75rem;
    padding: 0.125rem 0.375rem;
    border-radius: 4px;
    margin-left: auto;
  }
  .notification-status.sent {
    background: var(--success-bg);
    color: var(--success-text);
  }
  .notification-status.failed {
    background: var(--error-bg);
    color: var(--error-text);
  }
  .notification-subject {
    font-weight: 500;
    font-size: 0.875rem;
    margin-bottom: 0.25rem;
  }
  .notification-body {
    font-size: 0.875rem;
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-word;
  }
  .notification-date {
    font-size: 0.75rem;
    color: var(--text-muted);
    margin-top: 0.5rem;
  }
</style>
