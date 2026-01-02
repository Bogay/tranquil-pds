<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import { formatDateTime } from '../lib/date'

  interface TrustedDevice {
    id: string
    userAgent: string | null
    friendlyName: string | null
    trustedAt: string | null
    trustedUntil: string | null
    lastSeenAt: string
  }

  const auth = getAuthState()
  let devices = $state<TrustedDevice[]>([])
  let loading = $state(true)
  let message = $state<{ type: 'success' | 'error'; text: string } | null>(null)
  let editingDeviceId = $state<string | null>(null)
  let editDeviceName = $state('')

  $effect(() => {
    if (!auth.loading && !auth.session) {
      navigate('/login')
    }
  })

  $effect(() => {
    if (auth.session) {
      loadDevices()
    }
  })

  async function loadDevices() {
    if (!auth.session) return
    loading = true
    try {
      const result = await api.listTrustedDevices(auth.session.accessJwt)
      devices = result.devices
    } catch {
      showMessage('error', $_('trustedDevices.failedToLoad'))
    } finally {
      loading = false
    }
  }

  function showMessage(type: 'success' | 'error', text: string) {
    message = { type, text }
    setTimeout(() => {
      if (message?.text === text) message = null
    }, 5000)
  }

  async function handleRevoke(deviceId: string) {
    if (!auth.session) return
    if (!confirm($_('trustedDevices.revokeConfirm'))) return
    try {
      await api.revokeTrustedDevice(auth.session.accessJwt, deviceId)
      await loadDevices()
      showMessage('success', $_('trustedDevices.deviceRevoked'))
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : $_('common.error'))
    }
  }

  function startEditDevice(device: TrustedDevice) {
    editingDeviceId = device.id
    editDeviceName = device.friendlyName || ''
  }

  function cancelEditDevice() {
    editingDeviceId = null
    editDeviceName = ''
  }

  async function handleSaveDeviceName() {
    if (!auth.session || !editingDeviceId || !editDeviceName.trim()) return
    try {
      await api.updateTrustedDevice(auth.session.accessJwt, editingDeviceId, editDeviceName.trim())
      await loadDevices()
      editingDeviceId = null
      editDeviceName = ''
      showMessage('success', $_('trustedDevices.deviceRenamed'))
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : $_('common.error'))
    }
  }

  function formatDate(dateStr: string): string {
    return formatDateTime(dateStr)
  }

  function parseUserAgent(ua: string | null): string {
    if (!ua) return $_('trustedDevices.unknownDevice')
    if (ua.includes('Firefox')) return 'Firefox'
    if (ua.includes('Chrome')) return 'Chrome'
    if (ua.includes('Safari')) return 'Safari'
    if (ua.includes('Edge')) return 'Edge'
    return 'Browser'
  }

  function getDaysRemaining(trustedUntil: string | null): number {
    if (!trustedUntil) return 0
    const now = new Date()
    const until = new Date(trustedUntil)
    const diff = until.getTime() - now.getTime()
    return Math.ceil(diff / (1000 * 60 * 60 * 24))
  }
</script>

<div class="page">
  <header>
    <a href="/app/security" class="back">{$_('trustedDevices.backToSecurity')}</a>
    <h1>{$_('trustedDevices.title')}</h1>
  </header>

  {#if message}
    <div class="message {message.type}">{message.text}</div>
  {/if}

  <div class="description">
    <p>
      {$_('trustedDevices.description')}
    </p>
  </div>

  {#if loading}
    <div class="loading">{$_('common.loading')}</div>
  {:else if devices.length === 0}
    <div class="empty-state">
      <p>{$_('trustedDevices.noDevices')}</p>
      <p class="hint">{$_('trustedDevices.noDevicesHint')}</p>
    </div>
  {:else}
    <div class="device-list">
      {#each devices as device}
        <div class="device-card">
          <div class="device-header">
            {#if editingDeviceId === device.id}
              <input
                type="text"
                class="edit-name-input"
                bind:value={editDeviceName}
                placeholder={$_('trustedDevices.deviceNamePlaceholder')}
              />
              <div class="edit-actions">
                <button class="btn-small btn-primary" onclick={handleSaveDeviceName}>{$_('common.save')}</button>
                <button class="btn-small btn-secondary" onclick={cancelEditDevice}>{$_('common.cancel')}</button>
              </div>
            {:else}
              <h3>{device.friendlyName || parseUserAgent(device.userAgent)}</h3>
              <button class="btn-icon" onclick={() => startEditDevice(device)} title={$_('security.rename')}>
                &#9998;
              </button>
            {/if}
          </div>

          <div class="device-details">
            {#if device.userAgent && !device.friendlyName}
              <p class="detail"><span class="label">{$_('trustedDevices.browser')}</span> {device.userAgent}</p>
            {:else if device.userAgent}
              <p class="detail"><span class="label">{$_('trustedDevices.browser')}</span> {parseUserAgent(device.userAgent)}</p>
            {/if}
            <p class="detail">
              <span class="label">{$_('trustedDevices.lastSeen')}</span> {formatDate(device.lastSeenAt)}
            </p>
            {#if device.trustedAt}
              <p class="detail">
                <span class="label">{$_('trustedDevices.trustedSince')}</span> {formatDate(device.trustedAt)}
              </p>
            {/if}
            {#if device.trustedUntil}
              {@const daysRemaining = getDaysRemaining(device.trustedUntil)}
              <p class="detail trust-expiry" class:expiring-soon={daysRemaining <= 7}>
                <span class="label">{$_('trustedDevices.trustExpires')}</span>
                {#if daysRemaining <= 0}
                  {$_('trustedDevices.expired')}
                {:else if daysRemaining === 1}
                  {$_('trustedDevices.tomorrow')}
                {:else}
                  {$_('trustedDevices.inDays', { values: { days: daysRemaining } })}
                {/if}
              </p>
            {/if}
          </div>

          <div class="device-actions">
            <button class="btn-danger" onclick={() => handleRevoke(device.id)}>
              {$_('trustedDevices.revoke')}
            </button>
          </div>
        </div>
      {/each}
    </div>
  {/if}
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

  .back {
    display: inline-block;
    margin-bottom: var(--space-4);
    color: var(--accent);
    text-decoration: none;
    font-size: var(--text-sm);
  }

  .back:hover {
    text-decoration: underline;
  }

  h1 {
    margin: 0;
    font-size: var(--text-2xl);
  }

  .description {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-xl);
    padding: var(--space-4);
    margin-bottom: var(--space-6);
  }

  .description p {
    margin: 0;
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  .loading {
    text-align: center;
    padding: var(--space-7);
    color: var(--text-secondary);
  }

  .empty-state {
    text-align: center;
    padding: var(--space-8) var(--space-4);
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-xl);
  }

  .empty-state p {
    margin: 0;
    color: var(--text-secondary);
  }

  .empty-state .hint {
    margin-top: var(--space-2);
    font-size: var(--text-sm);
    color: var(--text-muted);
  }

  .device-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .device-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-xl);
    padding: var(--space-4);
  }

  .device-header {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-bottom: var(--space-3);
  }

  .device-header h3 {
    margin: 0;
    flex: 1;
    font-size: var(--text-base);
  }

  .edit-name-input {
    flex: 1;
    padding: var(--space-2);
    font-size: var(--text-sm);
  }

  .edit-actions {
    display: flex;
    gap: var(--space-2);
  }

  .btn-icon {
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    padding: var(--space-1);
    font-size: var(--text-base);
  }

  .btn-icon:hover {
    color: var(--text-primary);
  }

  .device-details {
    margin-bottom: var(--space-3);
  }

  .detail {
    margin: var(--space-1) 0;
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .detail .label {
    color: var(--text-muted);
  }

  .trust-expiry.expiring-soon {
    color: var(--warning-text);
  }

  .device-actions {
    display: flex;
    justify-content: flex-end;
    padding-top: var(--space-3);
    border-top: 1px solid var(--border-color);
  }

  .btn-small {
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
    cursor: pointer;
  }

  .btn-primary {
    background: var(--accent);
    color: var(--text-inverse);
    border: none;
  }

  .btn-primary:hover {
    background: var(--accent-hover);
  }

  .btn-secondary {
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    color: var(--text-secondary);
  }

  .btn-secondary:hover {
    background: var(--bg-secondary);
  }

  .btn-danger {
    background: transparent;
    border: 1px solid var(--error-border);
    color: var(--error-text);
    padding: var(--space-2) var(--space-4);
    border-radius: var(--radius-md);
    cursor: pointer;
    font-size: var(--text-sm);
  }

  .btn-danger:hover {
    background: var(--error-bg);
  }
</style>
