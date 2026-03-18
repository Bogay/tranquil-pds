<script lang="ts">
  import { _ } from '../../lib/i18n'

  interface Props {
    email: string
    token: string
    loading: boolean
    error: string | null
    onTokenChange: (token: string) => void
    onSubmit: (e: Event) => void
    onResend: () => void
  }

  let {
    email,
    token,
    loading,
    error,
    onTokenChange,
    onSubmit,
    onResend,
  }: Props = $props()
</script>

<div class="step-content">
  <h2>{$_('migration.inbound.emailVerify.title')}</h2>
  <p>{@html $_('migration.inbound.emailVerify.desc', { values: { email: `<strong>${email}</strong>` } })}</p>

  <div class="info-box">
    <p>
      {$_('migration.inbound.emailVerify.hint')}
    </p>
  </div>

  {#if error}
    <div class="message error">
      {error}
    </div>
  {/if}

  <form onsubmit={onSubmit}>
    <div>
      <label for="email-verify-token">{$_('migration.inbound.emailVerify.tokenLabel')}</label>
      <input
        id="email-verify-token"
        type="text"
        placeholder={$_('migration.inbound.emailVerify.tokenPlaceholder')}
        value={token}
        oninput={(e) => onTokenChange((e.target as HTMLInputElement).value)}
        disabled={loading}
        required
      />
    </div>

    <div class="button-row">
      <button type="button" class="ghost" onclick={onResend} disabled={loading}>
        {$_('migration.inbound.emailVerify.resend')}
      </button>
      <button type="submit" disabled={loading || !token}>
        {loading ? $_('common.verifying') : $_('common.verify')}
      </button>
    </div>
  </form>
</div>
