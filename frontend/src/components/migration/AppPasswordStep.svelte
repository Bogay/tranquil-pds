<script lang="ts">
  import { _ } from '../../lib/i18n'

  interface Props {
    appPassword: string
    appPasswordName: string
    loading: boolean
    onContinue: () => void
  }

  let {
    appPassword,
    appPasswordName,
    loading,
    onContinue,
  }: Props = $props()

  let copied = $state(false)
  let acknowledged = $state(false)

  function copyPassword() {
    navigator.clipboard.writeText(appPassword)
    copied = true
  }
</script>

<div class="step-content">
  <h2>{$_('migration.inbound.appPassword.title')}</h2>
  <p>{$_('migration.inbound.appPassword.desc')}</p>

  <div class="warning-box">
    <strong>{$_('migration.inbound.appPassword.warning')}</strong>
  </div>

  <div class="app-password-display">
    <div class="app-password-label">
      {$_('migration.inbound.appPassword.label')}: <strong>{appPasswordName}</strong>
    </div>
    <code class="app-password-code">{appPassword}</code>
    <button type="button" class="copy-btn" onclick={copyPassword}>
      {copied ? $_('common.copied') : $_('common.copyToClipboard')}
    </button>
  </div>

  <label class="checkbox-label">
    <input type="checkbox" bind:checked={acknowledged} />
    <span>{$_('migration.inbound.appPassword.saved')}</span>
  </label>

  <div class="button-row">
    <button onclick={onContinue} disabled={!acknowledged || loading}>
      {loading ? $_('migration.inbound.common.continue') : $_('migration.inbound.appPassword.continue')}
    </button>
  </div>
</div>
