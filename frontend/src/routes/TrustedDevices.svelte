<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate, routes, getFullUrl } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'
  import { _ } from '../lib/i18n'
  import { formatDateTime } from '../lib/date'
  import type { Session } from '../lib/types/api'
  import { toast } from '../lib/toast.svelte'

  interface TrustedDevice {
    id: string
    userAgent: string | null
    friendlyName: string | null
    trustedAt: string | null
    trustedUntil: string | null
    lastSeenAt: string
  }

  const auth = $derived(getAuthState())

  function getSession(): Session | null {
    return auth.kind === 'authenticated' ? auth.session : null
  }

  function isLoading(): boolean {
    return auth.kind === 'loading'
  }

  const session = $derived(getSession())
  const authLoading = $derived(isLoading())
  let devices = $state<TrustedDevice[]>([])
  let loading = $state(true)
  let editingDeviceId = $state<string | null>(null)
  let editDeviceName = $state('')

  $effect(() => {
    if (!authLoading && !session) {
      navigate(routes.login)
    }
  })

  $effect(() => {
    if (session) {
      loadDevices()
    }
  })

  async function loadDevices() {
    if (!session) return
    loading = true
    try {
      const result = await api.listTrustedDevices(session.accessJwt)
      devices = result.devices
    } catch {
      toast.error($_('trustedDevices.failedToLoad'))
    } finally {
      loading = false
    }
  }

  async function handleRevoke(deviceId: string) {
    if (!session) return
    if (!confirm($_('trustedDevices.revokeConfirm'))) return
    try {
      await api.revokeTrustedDevice(session.accessJwt, deviceId)
      await loadDevices()
      toast.success($_('trustedDevices.deviceRevoked'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('common.error'))
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
    if (!session || !editingDeviceId || !editDeviceName.trim()) return
    try {
      await api.updateTrustedDevice(session.accessJwt, editingDeviceId, editDeviceName.trim())
      await loadDevices()
      editingDeviceId = null
      editDeviceName = ''
      toast.success($_('trustedDevices.deviceRenamed'))
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('common.error'))
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
    <a href={getFullUrl(routes.security)} class="back">{$_('trustedDevices.backToSecurity')}</a>
    <h1>{$_('trustedDevices.title')}</h1>
  </header>

  <div class="description">
    <p>
      {$_('trustedDevices.description')}
    </p>
  </div>

  {#if loading}
    <div class="skeleton-list">
      {#each Array(2) as _}
        <div class="skeleton-card"></div>
      {/each}
    </div>
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
                <button class="sm" onclick={handleSaveDeviceName}>{$_('common.save')}</button>
                <button class="sm ghost" onclick={cancelEditDevice}>{$_('common.cancel')}</button>
              </div>
            {:else}
              <h3>{device.friendlyName || parseUserAgent(device.userAgent)}</h3>
              <button class="icon" onclick={() => startEditDevice(device)} title={$_('security.rename')}>
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
            <button class="sm danger-outline" onclick={() => handleRevoke(device.id)}>
              {$_('trustedDevices.revoke')}
            </button>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
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

  .skeleton-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
</style>
