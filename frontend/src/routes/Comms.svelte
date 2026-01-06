<script lang="ts">
  import { getAuthState, refreshSession } from '../lib/auth.svelte'
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import { formatDateTime } from '../lib/date'
  import type { Session } from '../lib/types/api'
  import { toast } from '../lib/toast.svelte'

  const auth = $derived(getAuthState())

  function getSession(): Session | null {
    return auth.kind === 'authenticated' ? auth.session : null
  }

  function isLoading(): boolean {
    return auth.kind === 'loading'
  }

  const session = $derived(getSession())
  const authLoading = $derived(isLoading())
  let loading = $state(true)
  let saving = $state(false)
  let preferredChannel = $state('email')
  let availableCommsChannels = $state<string[]>(['email'])
  let email = $state('')
  let discordId = $state('')
  let discordVerified = $state(false)
  let telegramUsername = $state('')
  let telegramVerified = $state(false)
  let signalNumber = $state('')
  let signalVerified = $state(false)
  let verifyingChannel = $state<string | null>(null)
  let verificationCode = $state('')
  let historyLoading = $state(true)
  let messages = $state<Array<{
    createdAt: string
    channel: string
    notificationType: string
    status: string
    subject: string | null
    body: string
  }>>([])
  $effect(() => {
    if (!authLoading && !session) {
      navigate(routes.login)
    }
  })
  $effect(() => {
    if (session) {
      loadPrefs()
      loadHistory()
    }
  })
  async function loadPrefs() {
    if (!session) return
    loading = true
    try {
      const [prefs, serverInfo] = await Promise.all([
        api.getNotificationPrefs(session.accessJwt),
        api.describeServer()
      ])
      preferredChannel = prefs.preferredChannel
      email = prefs.email
      discordId = prefs.discordId ?? ''
      discordVerified = prefs.discordVerified
      telegramUsername = prefs.telegramUsername ?? ''
      telegramVerified = prefs.telegramVerified
      signalNumber = prefs.signalNumber ?? ''
      signalVerified = prefs.signalVerified
      availableCommsChannels = serverInfo.availableCommsChannels ?? ['email']
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('comms.failedToLoad'))
    } finally {
      loading = false
    }
  }
  async function handleSave(e: Event) {
    e.preventDefault()
    if (!session) return
    saving = true
    try {
      await api.updateNotificationPrefs(session.accessJwt, {
        preferredChannel,
        discordId: discordId || undefined,
        telegramUsername: telegramUsername || undefined,
        signalNumber: signalNumber || undefined,
      })
      await refreshSession()
      toast.success($_('comms.preferencesSaved'))
      await loadPrefs()
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('comms.failedToSave'))
    } finally {
      saving = false
    }
  }
  async function handleVerify(channel: string) {
    if (!session || !verificationCode) return

    let identifier = ''
    switch (channel) {
      case 'discord': identifier = discordId; break
      case 'telegram': identifier = telegramUsername; break
      case 'signal': identifier = signalNumber; break
    }
    if (!identifier) return

    try {
      await api.confirmChannelVerification(session.accessJwt, channel, identifier, verificationCode)
      await refreshSession()
      toast.success($_('comms.verifiedSuccess', { values: { channel } }))
      verificationCode = ''
      verifyingChannel = null
      await loadPrefs()
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('comms.failedToVerify'))
    }
  }
  async function loadHistory() {
    if (!session) return
    historyLoading = true
    try {
      const result = await api.getNotificationHistory(session.accessJwt)
      messages = result.notifications
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('comms.failedToLoadHistory'))
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
  function isChannelAvailableOnServer(channelId: string): boolean {
    return availableCommsChannels.includes(channelId)
  }
  function canSelectChannel(channelId: string): boolean {
    if (!isChannelAvailableOnServer(channelId)) return false
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
    <a href={getFullUrl(routes.dashboard)} class="back">{$_('common.backToDashboard')}</a>
    <h1>{$_('comms.title')}</h1>
    <p class="description">{$_('comms.description')}</p>
  </header>

  {#if loading}
    <div class="skeleton-sections">
      <div class="skeleton-section"></div>
      <div class="skeleton-section"></div>
    </div>
  {:else}
    <div class="split-layout sidebar-right">
      <div class="main-column">
        <form onsubmit={handleSave}>
          <section>
            <h2>{$_('comms.preferredChannel')}</h2>
            <p class="section-description">{$_('comms.preferredChannelDescription')}</p>
            <div class="channel-options">
              {#each channels as channelId}
                <label class="channel-option" class:disabled={!canSelectChannel(channelId)} class:unavailable={!isChannelAvailableOnServer(channelId)}>
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
                    {#if !isChannelAvailableOnServer(channelId)}
                      <span class="channel-hint server-unavailable">{$_('comms.notConfiguredOnServer')}</span>
                    {:else if channelId !== 'email' && !canSelectChannel(channelId)}
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
                <div class="config-header">
                  <label for="email">{$_('register.email')}</label>
                  <span class="status verified">{$_('comms.primary')}</span>
                </div>
                <input id="email" type="email" value={email} disabled class="readonly" />
                <p class="config-hint">{$_('comms.emailManagedInSettings')}</p>
              </div>

              <div class="config-item" class:unavailable={!isChannelAvailableOnServer('discord')}>
                <div class="config-header">
                  <label for="discord">{$_('register.discordId')}</label>
                  {#if !isChannelAvailableOnServer('discord')}
                    <span class="status unavailable">{$_('comms.notConfiguredOnServer')}</span>
                  {:else if discordId}
                    {#if discordVerified}
                      <span class="status verified">{$_('comms.verified')}</span>
                    {:else}
                      <span class="status unverified">{$_('comms.notVerified')}</span>
                    {/if}
                  {/if}
                </div>
                <div class="config-input">
                  <input
                    id="discord"
                    type="text"
                    bind:value={discordId}
                    placeholder={$_('register.discordIdPlaceholder')}
                    disabled={saving || !isChannelAvailableOnServer('discord')}
                  />
                  {#if discordId && !discordVerified && isChannelAvailableOnServer('discord')}
                    <button type="button" class="verify-btn" onclick={() => verifyingChannel = 'discord'}>{$_('comms.verifyButton')}</button>
                  {/if}
                </div>
                <p class="config-hint">{$_('comms.discordIdHint')}</p>
                {#if verifyingChannel === 'discord'}
                  <div class="verify-form">
                    <input type="text" bind:value={verificationCode} placeholder={$_('comms.verifyCodePlaceholder')} maxlength="6" />
                    <button type="button" onclick={() => handleVerify('discord')}>{$_('comms.submit')}</button>
                    <button type="button" class="cancel" onclick={() => { verifyingChannel = null; verificationCode = '' }}>{$_('common.cancel')}</button>
                  </div>
                {/if}
              </div>

              <div class="config-item" class:unavailable={!isChannelAvailableOnServer('telegram')}>
                <div class="config-header">
                  <label for="telegram">{$_('register.telegramUsername')}</label>
                  {#if !isChannelAvailableOnServer('telegram')}
                    <span class="status unavailable">{$_('comms.notConfiguredOnServer')}</span>
                  {:else if telegramUsername}
                    {#if telegramVerified}
                      <span class="status verified">{$_('comms.verified')}</span>
                    {:else}
                      <span class="status unverified">{$_('comms.notVerified')}</span>
                    {/if}
                  {/if}
                </div>
                <div class="config-input">
                  <input
                    id="telegram"
                    type="text"
                    bind:value={telegramUsername}
                    placeholder={$_('register.telegramUsernamePlaceholder')}
                    disabled={saving || !isChannelAvailableOnServer('telegram')}
                  />
                  {#if telegramUsername && !telegramVerified && isChannelAvailableOnServer('telegram')}
                    <button type="button" class="verify-btn" onclick={() => verifyingChannel = 'telegram'}>{$_('comms.verifyButton')}</button>
                  {/if}
                </div>
                <p class="config-hint">{$_('comms.telegramHint')}</p>
                {#if verifyingChannel === 'telegram'}
                  <div class="verify-form">
                    <input type="text" bind:value={verificationCode} placeholder={$_('comms.verifyCodePlaceholder')} maxlength="6" />
                    <button type="button" onclick={() => handleVerify('telegram')}>{$_('comms.submit')}</button>
                    <button type="button" class="cancel" onclick={() => { verifyingChannel = null; verificationCode = '' }}>{$_('common.cancel')}</button>
                  </div>
                {/if}
              </div>

              <div class="config-item" class:unavailable={!isChannelAvailableOnServer('signal')}>
                <div class="config-header">
                  <label for="signal">{$_('register.signalNumber')}</label>
                  {#if !isChannelAvailableOnServer('signal')}
                    <span class="status unavailable">{$_('comms.notConfiguredOnServer')}</span>
                  {:else if signalNumber}
                    {#if signalVerified}
                      <span class="status verified">{$_('comms.verified')}</span>
                    {:else}
                      <span class="status unverified">{$_('comms.notVerified')}</span>
                    {/if}
                  {/if}
                </div>
                <div class="config-input">
                  <input
                    id="signal"
                    type="tel"
                    bind:value={signalNumber}
                    placeholder={$_('register.signalNumberPlaceholder')}
                    disabled={saving || !isChannelAvailableOnServer('signal')}
                  />
                  {#if signalNumber && !signalVerified && isChannelAvailableOnServer('signal')}
                    <button type="button" class="verify-btn" onclick={() => verifyingChannel = 'signal'}>{$_('comms.verifyButton')}</button>
                  {/if}
                </div>
                <p class="config-hint">{$_('comms.signalHint')}</p>
                {#if verifyingChannel === 'signal'}
                  <div class="verify-form">
                    <input type="text" bind:value={verificationCode} placeholder={$_('comms.verifyCodePlaceholder')} maxlength="6" />
                    <button type="button" onclick={() => handleVerify('signal')}>{$_('comms.submit')}</button>
                    <button type="button" class="cancel" onclick={() => { verifyingChannel = null; verificationCode = '' }}>{$_('common.cancel')}</button>
                  </div>
                {/if}
              </div>
            </div>

          </section>

          <div class="actions">
            <button type="submit" disabled={saving}>
              {saving ? $_('common.saving') : $_('comms.savePreferences')}
            </button>
          </div>
        </form>
      </div>

      <div class="side-column">
        <section class="history-section">
          <h2>{$_('comms.messageHistory')}</h2>
          <p class="section-description">{$_('comms.historyDescription')}</p>
          {#if historyLoading}
            <div class="skeleton-list">
              {#each [1, 2, 3] as _}
                <div class="skeleton-item">
                  <div class="skeleton-header">
                    <div class="skeleton-line short"></div>
                    <div class="skeleton-line tiny"></div>
                  </div>
                  <div class="skeleton-line"></div>
                  <div class="skeleton-line medium"></div>
                </div>
              {/each}
            </div>
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
        </section>
      </div>
    </div>
  {/if}
</div>
<style>
  .page {
    max-width: var(--width-xl);
    margin: 0 auto;
    padding: var(--space-7);
  }

  header {
    margin-bottom: var(--space-6);
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
    margin: var(--space-2) 0 0 0;
  }

  section {
    background: var(--bg-secondary);
    padding: var(--space-6);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-6);
  }

  .side-column section {
    margin-bottom: 0;
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

  .channel-option.unavailable {
    opacity: 0.5;
    background: var(--bg-input-disabled);
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

  .channel-hint.server-unavailable {
    color: var(--warning-text);
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

  .config-item.unavailable {
    opacity: 0.6;
  }

  .config-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    margin-bottom: var(--space-1);
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
    min-width: 0;
  }

  .config-item input.readonly {
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

  .status.unavailable {
    background: var(--bg-input-disabled);
    color: var(--text-muted);
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

  .history-section h2 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-lg);
  }

  .skeleton-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .skeleton-item {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: var(--space-3);
  }

  .skeleton-header {
    display: flex;
    gap: var(--space-2);
    margin-bottom: var(--space-2);
  }

  .skeleton-line {
    height: 14px;
    background: var(--bg-tertiary);
    border-radius: var(--radius-sm);
    animation: skeleton-pulse 1.5s ease-in-out infinite;
  }

  .skeleton-line.short {
    width: 80px;
  }

  .skeleton-line.tiny {
    width: 50px;
  }

  .skeleton-line.medium {
    width: 60%;
  }

  .skeleton-line:not(.short):not(.tiny):not(.medium) {
    width: 100%;
    margin-bottom: var(--space-1);
  }

  @keyframes skeleton-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
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

  .skeleton-sections {
    display: flex;
    flex-direction: column;
    gap: var(--space-6);
  }

  .skeleton-section {
    height: 180px;
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
    animation: skeleton-pulse 1.5s ease-in-out infinite;
  }

  @keyframes skeleton-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
</style>
