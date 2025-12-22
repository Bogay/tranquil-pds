<script lang="ts">
  import { getAuthState, refreshSession } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import { formatDateTime } from '../lib/date'
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
  let messages = $state<Array<{
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
      await refreshSession()
      success = $_('comms.preferencesSaved')
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
      await refreshSession()
      verificationSuccess = $_('comms.verifiedSuccess', { values: { channel } })
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
      messages = result.notifications
      showHistory = true
    } catch (e) {
      historyError = e instanceof ApiError ? e.message : 'Failed to load notification history'
    } finally {
      historyLoading = false
    }
  }
  function formatDate(dateStr: string): string {
    return formatDateTime(dateStr)
  }
  const channels = ['email', 'discord', 'telegram', 'signal']
  function getChannelName(id: string): string {
    switch (id) {
      case 'email': return $_('register.email')
      case 'discord': return $_('register.discord')
      case 'telegram': return $_('register.telegram')
      case 'signal': return $_('register.signal')
      default: return id
    }
  }
  function getChannelDescription(id: string): string {
    switch (id) {
      case 'email': return $_('comms.emailVia')
      case 'discord': return $_('comms.discordVia')
      case 'telegram': return $_('comms.telegramVia')
      case 'signal': return $_('comms.signalVia')
      default: return ''
    }
  }
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
    <a href="#/dashboard" class="back">{$_('common.backToDashboard')}</a>
    <h1>{$_('comms.title')}</h1>
  </header>
  <p class="description">
    {$_('comms.description')}
  </p>
  {#if loading}
    <p class="loading">{$_('common.loading')}</p>
  {:else}
    {#if error}
      <div class="message error">{error}</div>
    {/if}
    {#if success}
      <div class="message success">{success}</div>
    {/if}
    <form onsubmit={handleSave}>
      <section>
        <h2>{$_('comms.preferredChannel')}</h2>
        <p class="section-description">
          {$_('comms.preferredChannelDescription')}
        </p>
        <div class="channel-options">
          {#each channels as channelId}
            <label class="channel-option" class:disabled={!canSelectChannel(channelId)}>
              <input
                type="radio"
                name="preferredChannel"
                value={channelId}
                bind:group={preferredChannel}
                disabled={!canSelectChannel(channelId) || saving}
              />
              <div class="channel-info">
                <span class="channel-name">{getChannelName(channelId)}</span>
                <span class="channel-description">{getChannelDescription(channelId)}</span>
                {#if channelId !== 'email' && !canSelectChannel(channelId)}
                  <span class="channel-hint">{$_('comms.configureToEnable')}</span>
                {/if}
              </div>
            </label>
          {/each}
        </div>
      </section>
      <section>
        <h2>{$_('comms.channelConfiguration')}</h2>
        <div class="channel-config">
          <div class="config-item">
            <label for="email">{$_('register.email')}</label>
            <div class="config-input">
              <input
                id="email"
                type="email"
                value={email}
                disabled
                class="readonly"
              />
              <span class="status verified">{$_('comms.primary')}</span>
            </div>
            <p class="config-hint">{$_('comms.emailManagedInSettings')}</p>
          </div>
          <div class="config-item">
            <label for="discord">{$_('register.discordId')}</label>
            <div class="config-input">
              <input
                id="discord"
                type="text"
                bind:value={discordId}
                placeholder={$_('register.discordIdPlaceholder')}
                disabled={saving}
              />
              {#if discordId}
                {#if discordVerified}
                  <span class="status verified">{$_('comms.verified')}</span>
                {:else}
                  <span class="status unverified">{$_('comms.notVerified')}</span>
                  <button type="button" class="verify-btn" onclick={() => verifyingChannel = 'discord'}>{$_('comms.verifyButton')}</button>
                {/if}
              {/if}
            </div>
            <p class="config-hint">{$_('comms.discordIdHint')}</p>
            {#if verifyingChannel === 'discord'}
              <div class="verify-form">
                <input
                  type="text"
                  bind:value={verificationCode}
                  placeholder={$_('comms.verifyCodePlaceholder')}
                  maxlength="6"
                />
                <button type="button" onclick={() => handleVerify('discord')}>{$_('comms.submit')}</button>
                <button type="button" class="cancel" onclick={() => { verifyingChannel = null; verificationCode = '' }}>{$_('common.cancel')}</button>
              </div>
            {/if}
          </div>
          <div class="config-item">
            <label for="telegram">{$_('register.telegramUsername')}</label>
            <div class="config-input">
              <input
                id="telegram"
                type="text"
                bind:value={telegramUsername}
                placeholder={$_('register.telegramUsernamePlaceholder')}
                disabled={saving}
              />
              {#if telegramUsername}
                {#if telegramVerified}
                  <span class="status verified">{$_('comms.verified')}</span>
                {:else}
                  <span class="status unverified">{$_('comms.notVerified')}</span>
                  <button type="button" class="verify-btn" onclick={() => verifyingChannel = 'telegram'}>{$_('comms.verifyButton')}</button>
                {/if}
              {/if}
            </div>
            <p class="config-hint">{$_('comms.telegramHint')}</p>
            {#if verifyingChannel === 'telegram'}
              <div class="verify-form">
                <input
                  type="text"
                  bind:value={verificationCode}
                  placeholder={$_('comms.verifyCodePlaceholder')}
                  maxlength="6"
                />
                <button type="button" onclick={() => handleVerify('telegram')}>{$_('comms.submit')}</button>
                <button type="button" class="cancel" onclick={() => { verifyingChannel = null; verificationCode = '' }}>{$_('common.cancel')}</button>
              </div>
            {/if}
          </div>
          <div class="config-item">
            <label for="signal">{$_('register.signalNumber')}</label>
            <div class="config-input">
              <input
                id="signal"
                type="tel"
                bind:value={signalNumber}
                placeholder={$_('register.signalNumberPlaceholder')}
                disabled={saving}
              />
              {#if signalNumber}
                {#if signalVerified}
                  <span class="status verified">{$_('comms.verified')}</span>
                {:else}
                  <span class="status unverified">{$_('comms.notVerified')}</span>
                  <button type="button" class="verify-btn" onclick={() => verifyingChannel = 'signal'}>{$_('comms.verifyButton')}</button>
                {/if}
              {/if}
            </div>
            <p class="config-hint">{$_('comms.signalHint')}</p>
            {#if verifyingChannel === 'signal'}
              <div class="verify-form">
                <input
                  type="text"
                  bind:value={verificationCode}
                  placeholder={$_('comms.verifyCodePlaceholder')}
                  maxlength="6"
                />
                <button type="button" onclick={() => handleVerify('signal')}>{$_('comms.submit')}</button>
                <button type="button" class="cancel" onclick={() => { verifyingChannel = null; verificationCode = '' }}>{$_('common.cancel')}</button>
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
          {saving ? $_('comms.saving') : $_('comms.savePreferences')}
        </button>
      </div>
    </form>
    <section class="history-section">
      <h2>{$_('comms.messageHistory')}</h2>
      <p class="section-description">{$_('comms.historyDescription')}</p>
      {#if !showHistory}
        <button class="load-history" onclick={loadHistory} disabled={historyLoading}>
          {historyLoading ? $_('common.loading') : $_('comms.loadHistory')}
        </button>
      {:else}
        <button class="load-history" onclick={() => showHistory = false}>{$_('comms.hideHistory')}</button>
        {#if historyError}
          <div class="message error">{historyError}</div>
        {:else if messages.length === 0}
          <p class="no-messages">{$_('comms.noMessages')}</p>
        {:else}
          <div class="message-list">
            {#each messages as msg}
              <div class="message-item">
                <div class="message-header">
                  <span class="message-type">{msg.notificationType}</span>
                  <span class="message-channel">{msg.channel}</span>
                  <span class="message-status" class:sent={msg.status === 'sent'} class:failed={msg.status === 'failed'}>{msg.status}</span>
                </div>
                {#if msg.subject}
                  <div class="message-subject">{msg.subject}</div>
                {/if}
                <div class="message-body">{msg.body}</div>
                <div class="message-date">{formatDate(msg.createdAt)}</div>
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
    max-width: var(--width-md);
    margin: 0 auto;
    padding: var(--space-7);
  }

  header {
    margin-bottom: var(--space-4);
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

  .description {
    color: var(--text-secondary);
    margin-bottom: var(--space-7);
  }

  .loading {
    text-align: center;
    color: var(--text-secondary);
    padding: var(--space-7);
  }

  section {
    background: var(--bg-secondary);
    padding: var(--space-6);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-6);
  }

  section h2 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-lg);
  }

  .section-description {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin: 0 0 var(--space-4) 0;
  }

  .channel-options {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .channel-option {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: var(--space-3);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    cursor: pointer;
    transition: border-color var(--transition-fast);
  }

  .channel-option:hover:not(.disabled) {
    border-color: var(--accent);
  }

  .channel-option.disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .channel-option input[type="radio"] {
    flex-shrink: 0;
    width: 16px;
    height: 16px;
    margin-top: 2px;
  }

  .channel-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .channel-name {
    font-weight: var(--font-medium);
  }

  .channel-description {
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .channel-hint {
    font-size: var(--text-xs);
    color: var(--text-muted);
    font-style: italic;
  }

  .channel-config {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }

  .config-item {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .config-item label {
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
  }

  .config-input {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }

  .config-input input {
    flex: 1;
  }

  .config-input input.readonly {
    background: var(--bg-input-disabled);
    color: var(--text-secondary);
  }

  .status {
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
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
    font-size: var(--text-xs);
    color: var(--text-secondary);
    margin: 0;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
  }

  .verify-btn {
    padding: var(--space-1) var(--space-2);
    background: var(--accent);
    color: var(--text-inverse);
    border: none;
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
    cursor: pointer;
  }

  .verify-btn:hover {
    background: var(--accent-hover);
  }

  .verify-form {
    display: flex;
    gap: var(--space-2);
    margin-top: var(--space-2);
    align-items: center;
  }

  .verify-form input {
    padding: var(--space-2);
    font-size: var(--text-sm);
    width: 150px;
  }

  .verify-form button {
    padding: var(--space-2) var(--space-3);
    background: var(--accent);
    color: var(--text-inverse);
    border: none;
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
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
    padding: var(--space-6);
    border-radius: var(--radius-xl);
    margin-top: var(--space-6);
  }

  .history-section h2 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-lg);
  }

  .load-history {
    padding: var(--space-2) var(--space-4);
    background: transparent;
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    cursor: pointer;
    color: var(--text-primary);
    margin-top: var(--space-2);
  }

  .load-history:hover:not(:disabled) {
    background: var(--bg-card);
    border-color: var(--accent);
  }

  .load-history:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .no-messages {
    color: var(--text-secondary);
    font-style: italic;
    margin-top: var(--space-4);
  }

  .message-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    margin-top: var(--space-4);
  }

  .message-item {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: var(--space-3);
  }

  .message-header {
    display: flex;
    gap: var(--space-2);
    margin-bottom: var(--space-2);
    flex-wrap: wrap;
    align-items: center;
  }

  .message-type {
    font-weight: var(--font-medium);
    font-size: var(--text-sm);
  }

  .message-channel {
    font-size: var(--text-xs);
    padding: var(--space-1) var(--space-2);
    background: var(--bg-secondary);
    border-radius: var(--radius-md);
    color: var(--text-secondary);
  }

  .message-status {
    font-size: var(--text-xs);
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-md);
    margin-left: auto;
  }

  .message-status.sent {
    background: var(--success-bg);
    color: var(--success-text);
  }

  .message-status.failed {
    background: var(--error-bg);
    color: var(--error-text);
  }

  .message-subject {
    font-weight: var(--font-medium);
    font-size: var(--text-sm);
    margin-bottom: var(--space-1);
  }

  .message-body {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-word;
  }

  .message-date {
    font-size: var(--text-xs);
    color: var(--text-muted);
    margin-top: var(--space-2);
  }
</style>
