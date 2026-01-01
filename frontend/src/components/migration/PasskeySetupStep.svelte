<script lang="ts">
  import { _ } from '../../lib/i18n'

  interface Props {
    passkeyName: string
    loading: boolean
    error: string | null
    onPasskeyNameChange: (name: string) => void
    onRegister: () => void
  }

  let {
    passkeyName,
    loading,
    error,
    onPasskeyNameChange,
    onRegister,
  }: Props = $props()
</script>

<div class="step-content">
  <h2>{$_('migration.inbound.passkeySetup.title')}</h2>
  <p>{$_('migration.inbound.passkeySetup.desc')}</p>

  {#if error}
    <div class="message error">
      {error}
    </div>
  {/if}

  <div class="field">
    <label for="passkey-name">{$_('migration.inbound.passkeySetup.nameLabel')}</label>
    <input
      id="passkey-name"
      type="text"
      placeholder={$_('migration.inbound.passkeySetup.namePlaceholder')}
      value={passkeyName}
      oninput={(e) => onPasskeyNameChange((e.target as HTMLInputElement).value)}
      disabled={loading}
    />
    <p class="hint">{$_('migration.inbound.passkeySetup.nameHint')}</p>
  </div>

  <div class="passkey-section">
    <p>{$_('migration.inbound.passkeySetup.instructions')}</p>
    <button class="primary" onclick={onRegister} disabled={loading}>
      {loading ? $_('migration.inbound.passkeySetup.registering') : $_('migration.inbound.passkeySetup.register')}
    </button>
  </div>
</div>

<style>
  .passkey-section {
    margin-top: 16px;
  }
  .passkey-section button {
    width: 100%;
    margin-top: 12px;
  }
</style>
