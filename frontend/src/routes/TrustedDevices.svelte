<script lang="ts">
  import { getAuthState } from '../lib/auth.svelte'
  import { navigate } from '../lib/router.svelte'
  import { api, ApiError } from '../lib/api'

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
      showMessage('error', 'Failed to load trusted devices')
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
    if (!confirm('Are you sure you want to revoke trust for this device? You will need to enter your 2FA code next time you log in from this device.')) return
    try {
      await api.revokeTrustedDevice(auth.session.accessJwt, deviceId)
      await loadDevices()
      showMessage('success', 'Device trust revoked')
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : 'Failed to revoke device')
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
      showMessage('success', 'Device renamed')
    } catch (e) {
      showMessage('error', e instanceof ApiError ? e.message : 'Failed to rename device')
    }
  }

  function formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  function parseUserAgent(ua: string | null): string {
    if (!ua) return 'Unknown device'
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
    <a href="#/security" class="back">&larr; Security Settings</a>
    <h1>Trusted Devices</h1>
  </header>

  {#if message}
    <div class="message {message.type}">{message.text}</div>
  {/if}

  <div class="description">
    <p>
      Trusted devices can skip two-factor authentication when logging in.
      Trust is granted for 30 days and automatically extends when you use the device.
    </p>
  </div>

  {#if loading}
    <div class="loading">Loading...</div>
  {:else if devices.length === 0}
    <div class="empty-state">
      <p>No trusted devices yet.</p>
      <p class="hint">When you log in with two-factor authentication enabled, you can choose to trust the device for 30 days.</p>
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
                placeholder="Device name"
              />
              <div class="edit-actions">
                <button class="btn-small btn-primary" onclick={handleSaveDeviceName}>Save</button>
                <button class="btn-small btn-secondary" onclick={cancelEditDevice}>Cancel</button>
              </div>
            {:else}
              <h3>{device.friendlyName || parseUserAgent(device.userAgent)}</h3>
              <button class="btn-icon" onclick={() => startEditDevice(device)} title="Rename">
                &#9998;
              </button>
            {/if}
          </div>

          <div class="device-details">
            {#if device.userAgent && !device.friendlyName}
              <p class="detail"><span class="label">Browser:</span> {device.userAgent}</p>
            {:else if device.userAgent}
              <p class="detail"><span class="label">Browser:</span> {parseUserAgent(device.userAgent)}</p>
            {/if}
            <p class="detail">
              <span class="label">Last seen:</span> {formatDate(device.lastSeenAt)}
            </p>
            {#if device.trustedAt}
              <p class="detail">
                <span class="label">Trusted since:</span> {formatDate(device.trustedAt)}
              </p>
            {/if}
            {#if device.trustedUntil}
              {@const daysRemaining = getDaysRemaining(device.trustedUntil)}
              <p class="detail trust-expiry" class:expiring-soon={daysRemaining <= 7}>
                <span class="label">Trust expires:</span>
                {#if daysRemaining <= 0}
                  Expired
                {:else if daysRemaining === 1}
                  Tomorrow
                {:else}
                  In {daysRemaining} days
                {/if}
              </p>
            {/if}
          </div>

          <div class="device-actions">
            <button class="btn-danger" onclick={() => handleRevoke(device.id)}>
              Revoke Trust
            </button>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .page {
    max-width: 600px;
    margin: 0 auto;
    padding: 2rem 1rem;
  }

  header {
    margin-bottom: 2rem;
  }

  .back {
    display: inline-block;
    margin-bottom: 1rem;
    color: var(--accent);
    text-decoration: none;
    font-size: 0.875rem;
  }

  .back:hover {
    text-decoration: underline;
  }

  h1 {
    margin: 0;
    font-size: 1.75rem;
  }

  .message {
    padding: 0.75rem 1rem;
    border-radius: 4px;
    margin-bottom: 1rem;
  }

  .message.success {
    background: var(--success-bg);
    color: var(--success-text);
    border: 1px solid var(--success-border);
  }

  .message.error {
    background: var(--error-bg);
    color: var(--error-text);
    border: 1px solid var(--error-border);
  }

  .description {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1.5rem;
  }

  .description p {
    margin: 0;
    color: var(--text-secondary);
    font-size: 0.9rem;
  }

  .loading {
    text-align: center;
    padding: 2rem;
    color: var(--text-secondary);
  }

  .empty-state {
    text-align: center;
    padding: 3rem 1rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
  }

  .empty-state p {
    margin: 0;
    color: var(--text-secondary);
  }

  .empty-state .hint {
    margin-top: 0.5rem;
    font-size: 0.875rem;
    color: var(--text-muted);
  }

  .device-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .device-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1rem;
  }

  .device-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.75rem;
  }

  .device-header h3 {
    margin: 0;
    flex: 1;
    font-size: 1rem;
  }

  .edit-name-input {
    flex: 1;
    padding: 0.5rem;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 0.9rem;
  }

  .edit-actions {
    display: flex;
    gap: 0.5rem;
  }

  .btn-icon {
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    padding: 0.25rem;
    font-size: 1rem;
  }

  .btn-icon:hover {
    color: var(--text-primary);
  }

  .device-details {
    margin-bottom: 0.75rem;
  }

  .detail {
    margin: 0.25rem 0;
    font-size: 0.875rem;
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
    padding-top: 0.75rem;
    border-top: 1px solid var(--border-color);
  }

  .btn-small {
    padding: 0.375rem 0.75rem;
    border-radius: 4px;
    font-size: 0.8rem;
    cursor: pointer;
  }

  .btn-primary {
    background: var(--accent);
    color: white;
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
    padding: 0.5rem 1rem;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.875rem;
  }

  .btn-danger:hover {
    background: var(--error-bg);
  }
</style>
