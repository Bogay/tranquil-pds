<script lang="ts">
  import { onMount } from 'svelte'
  import { refreshSession } from '../../lib/auth.svelte'
  import { api, ApiError } from '../../lib/api'
  import { _ } from '../../lib/i18n'
  import { formatDateTime } from '../../lib/date'
  import type { Session } from '../../lib/types/api'
  import { toast } from '../../lib/toast.svelte'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

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
  let discordInUse = $state(false)
  let telegramInUse = $state(false)
  let signalInUse = $state(false)
  let messages = $state<Array<{
    createdAt: string
    channel: string
    notificationType: string
    status: string
    subject: string | null
    body: string
  }>>([])

  onMount(() => {
    loadPrefs()
    loadHistory()
  })

  async function loadPrefs() {
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
    if (!verificationCode) return

    const identifierMap: Record<string, string> = {
      discord: discordId,
      telegram: telegramUsername,
      signal: signalNumber
    }
    const identifier = identifierMap[channel]
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

  async function checkChannelInUse(channel: 'discord' | 'telegram' | 'signal', identifier: string) {
    const trimmed = identifier.trim()
    if (!trimmed) {
      const resetMap = { discord: () => discordInUse = false, telegram: () => telegramInUse = false, signal: () => signalInUse = false }
      resetMap[channel]()
      return
    }
    try {
      const result = await api.checkCommsChannelInUse(channel, trimmed)
      const setMap = { discord: (v: boolean) => discordInUse = v, telegram: (v: boolean) => telegramInUse = v, signal: (v: boolean) => signalInUse = v }
      setMap[channel](result.inUse)
    } catch {
      const resetMap = { discord: () => discordInUse = false, telegram: () => telegramInUse = false, signal: () => signalInUse = false }
      resetMap[channel]()
    }
  }

  const channels = ['email', 'discord', 'telegram', 'signal']

  function getChannelName(id: string): string {
    const names: Record<string, () => string> = {
      email: () => $_('register.email'),
      discord: () => $_('register.discord'),
      telegram: () => $_('register.telegram'),
      signal: () => $_('register.signal')
    }
    return names[id]?.() ?? id
  }

  function getChannelDescription(id: string): string {
    const descriptions: Record<string, () => string> = {
      email: () => $_('comms.emailVia'),
      discord: () => $_('comms.discordVia'),
      telegram: () => $_('comms.telegramVia'),
      signal: () => $_('comms.signalVia')
    }
    return descriptions[id]?.() ?? ''
  }

  function isChannelAvailableOnServer(channelId: string): boolean {
    return availableCommsChannels.includes(channelId)
  }

  function canSelectChannel(channelId: string): boolean {
    if (!isChannelAvailableOnServer(channelId)) return false
    if (channelId === 'email') return true
    const hasIdentifier: Record<string, boolean> = {
      discord: !!discordId,
      telegram: !!telegramUsername,
      signal: !!signalNumber
    }
    return hasIdentifier[channelId] ?? false
  }
</script>

<div class="comms">
  {#if loading}
    <div class="loading">{$_('common.loading')}</div>
  {:else}
    <form onsubmit={handleSave}>
      <section>
        <h3>{$_('comms.preferredChannel')}</h3>
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
                <span class="channel-desc">{getChannelDescription(channelId)}</span>
              </div>
              {#if !isChannelAvailableOnServer(channelId)}
                <span class="channel-hint">{$_('comms.notConfiguredOnServer')}</span>
              {:else if channelId !== 'email' && !canSelectChannel(channelId)}
                <span class="channel-hint">{$_('comms.configureToEnable')}</span>
              {/if}
            </label>
          {/each}
        </div>
      </section>

      <section>
        <h3>{$_('comms.channelConfiguration')}</h3>
        <div class="channel-config">
          <div class="config-item">
            <div class="config-header">
              <label for="email">{$_('register.email')}</label>
              <span class="status verified">{$_('comms.primary')}</span>
            </div>
            <input id="email" type="email" value={email} disabled class="readonly" />
          </div>

          {#if isChannelAvailableOnServer('discord')}
            <div class="config-item">
              <div class="config-header">
                <label for="discord">{$_('register.discordId')}</label>
                {#if discordId}
                  <span class="status" class:verified={discordVerified} class:unverified={!discordVerified}>
                    {discordVerified ? $_('comms.verified') : $_('comms.notVerified')}
                  </span>
                {/if}
              </div>
              <div class="config-input">
                <input
                  id="discord"
                  type="text"
                  bind:value={discordId}
                  onblur={() => checkChannelInUse('discord', discordId)}
                  placeholder={$_('register.discordIdPlaceholder')}
                  disabled={saving}
                />
                {#if discordId && !discordVerified}
                  <button type="button" class="verify-btn" onclick={() => verifyingChannel = 'discord'}>{$_('comms.verifyButton')}</button>
                {/if}
              </div>
              {#if discordInUse}
                <p class="hint warning">{$_('comms.discordInUseWarning')}</p>
              {/if}
              {#if verifyingChannel === 'discord'}
                <div class="verify-form">
                  <input type="text" bind:value={verificationCode} placeholder={$_('comms.verifyCodePlaceholder')} maxlength="6" />
                  <button type="button" onclick={() => handleVerify('discord')}>{$_('comms.submit')}</button>
                  <button type="button" class="cancel" onclick={() => { verifyingChannel = null; verificationCode = '' }}>{$_('common.cancel')}</button>
                </div>
              {/if}
            </div>
          {/if}

          {#if isChannelAvailableOnServer('telegram')}
            <div class="config-item">
              <div class="config-header">
                <label for="telegram">{$_('register.telegramUsername')}</label>
                {#if telegramUsername}
                  <span class="status" class:verified={telegramVerified} class:unverified={!telegramVerified}>
                    {telegramVerified ? $_('comms.verified') : $_('comms.notVerified')}
                  </span>
                {/if}
              </div>
              <div class="config-input">
                <input
                  id="telegram"
                  type="text"
                  bind:value={telegramUsername}
                  onblur={() => checkChannelInUse('telegram', telegramUsername)}
                  placeholder={$_('register.telegramUsernamePlaceholder')}
                  disabled={saving}
                />
                {#if telegramUsername && !telegramVerified}
                  <button type="button" class="verify-btn" onclick={() => verifyingChannel = 'telegram'}>{$_('comms.verifyButton')}</button>
                {/if}
              </div>
              {#if telegramInUse}
                <p class="hint warning">{$_('comms.telegramInUseWarning')}</p>
              {/if}
              {#if verifyingChannel === 'telegram'}
                <div class="verify-form">
                  <input type="text" bind:value={verificationCode} placeholder={$_('comms.verifyCodePlaceholder')} maxlength="6" />
                  <button type="button" onclick={() => handleVerify('telegram')}>{$_('comms.submit')}</button>
                  <button type="button" class="cancel" onclick={() => { verifyingChannel = null; verificationCode = '' }}>{$_('common.cancel')}</button>
                </div>
              {/if}
            </div>
          {/if}

          {#if isChannelAvailableOnServer('signal')}
            <div class="config-item">
              <div class="config-header">
                <label for="signal">{$_('register.signalNumber')}</label>
                {#if signalNumber}
                  <span class="status" class:verified={signalVerified} class:unverified={!signalVerified}>
                    {signalVerified ? $_('comms.verified') : $_('comms.notVerified')}
                  </span>
                {/if}
              </div>
              <div class="config-input">
                <input
                  id="signal"
                  type="tel"
                  bind:value={signalNumber}
                  onblur={() => checkChannelInUse('signal', signalNumber)}
                  placeholder={$_('register.signalNumberPlaceholder')}
                  disabled={saving}
                />
                {#if signalNumber && !signalVerified}
                  <button type="button" class="verify-btn" onclick={() => verifyingChannel = 'signal'}>{$_('comms.verifyButton')}</button>
                {/if}
              </div>
              {#if signalInUse}
                <p class="hint warning">{$_('comms.signalInUseWarning')}</p>
              {/if}
              {#if verifyingChannel === 'signal'}
                <div class="verify-form">
                  <input type="text" bind:value={verificationCode} placeholder={$_('comms.verifyCodePlaceholder')} maxlength="6" />
                  <button type="button" onclick={() => handleVerify('signal')}>{$_('comms.submit')}</button>
                  <button type="button" class="cancel" onclick={() => { verifyingChannel = null; verificationCode = '' }}>{$_('common.cancel')}</button>
                </div>
              {/if}
            </div>
          {/if}
        </div>
      </section>

      <div class="actions">
        <button type="submit" disabled={saving}>
          {saving ? $_('common.saving') : $_('comms.savePreferences')}
        </button>
      </div>
    </form>

    <section class="history-section">
      <h3>{$_('comms.messageHistory')}</h3>
      {#if historyLoading}
        <div class="loading">{$_('common.loading')}</div>
      {:else if messages.length === 0}
        <p class="empty">{$_('comms.noMessages')}</p>
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
  {/if}
</div>

<style>
  .comms {
    max-width: var(--width-lg);
  }

  .loading,
  .empty {
    color: var(--text-secondary);
    padding: var(--space-4);
  }

  section {
    background: var(--bg-secondary);
    padding: var(--space-5);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-5);
  }

  section h3 {
    margin: 0 0 var(--space-4) 0;
    font-size: var(--text-base);
  }

  .channel-options {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .channel-option {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-4);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    cursor: pointer;
  }

  .channel-option input[type="radio"] {
    margin: 0;
    width: 18px;
    height: 18px;
    flex-shrink: 0;
    accent-color: var(--accent);
  }

  .channel-option:hover:not(.disabled) {
    border-color: var(--accent);
  }

  .channel-option.disabled,
  .channel-option.unavailable {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .channel-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .channel-name {
    font-weight: var(--font-medium);
  }

  .channel-desc {
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .channel-hint {
    font-size: var(--text-xs);
    color: var(--text-muted);
    margin-left: auto;
  }

  .channel-config {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .config-item {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .config-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .config-input {
    display: flex;
    gap: var(--space-2);
  }

  .config-input input {
    flex: 1;
  }

  input.readonly {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
  }

  .status {
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
  }

  .status.verified {
    background: var(--success-bg);
    color: var(--success-text);
  }

  .status.unverified {
    background: var(--warning-bg);
    color: var(--warning-text);
  }

  .hint {
    font-size: var(--text-xs);
    color: var(--text-secondary);
    margin: 0;
  }

  .hint.warning {
    color: var(--warning-text);
  }

  .verify-btn {
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-sm);
  }

  .verify-form {
    display: flex;
    gap: var(--space-2);
    align-items: center;
  }

  .verify-form input {
    width: 120px;
  }

  .verify-form button {
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-sm);
  }

  .verify-form button.cancel {
    background: transparent;
    border: 1px solid var(--border-color);
    color: var(--text-secondary);
  }

  .actions {
    margin-bottom: var(--space-5);
  }

  .history-section {
    margin-top: var(--space-6);
  }

  .message-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
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
    align-items: center;
    margin-bottom: var(--space-2);
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
  }

  .message-date {
    font-size: var(--text-xs);
    color: var(--text-muted);
    margin-top: var(--space-2);
  }
</style>
