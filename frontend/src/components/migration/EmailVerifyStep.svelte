<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import type { VerificationChannel } from '../../lib/migration/types'
  import { api } from '../../lib/api'
  import { _ } from '../../lib/i18n'

  interface Props {
    channel: VerificationChannel
    identifier: string
    token: string
    loading: boolean
    error: string | null
    handle?: string
    onTokenChange: (token: string) => void
    onSubmit: (e: Event) => void
    onResend: () => void
    onVerified?: () => void
  }

  let {
    channel,
    identifier,
    token,
    loading,
    error,
    handle,
    onTokenChange,
    onSubmit,
    onResend,
    onVerified,
  }: Props = $props()

  let telegramBotUsername = $state<string | undefined>(undefined)
  let discordBotUsername = $state<string | undefined>(undefined)
  let discordAppId = $state<string | undefined>(undefined)

  const isTelegram = $derived(channel === 'telegram')
  const isDiscord = $derived(channel === 'discord')
  const isBotChannel = $derived(isTelegram || isDiscord)

  onMount(async () => {
    if (isBotChannel) {
      try {
        const serverInfo = await api.describeServer()
        telegramBotUsername = serverInfo.telegramBotUsername
        discordBotUsername = serverInfo.discordBotUsername
        discordAppId = serverInfo.discordAppId
      } catch {}
    }
  })

  function channelLabel(ch: string): string {
    switch (ch) {
      case 'email': return 'email'
      case 'discord': return 'Discord'
      case 'telegram': return 'Telegram'
      case 'signal': return 'Signal'
      default: return ch
    }
  }
</script>

<div class="step-content">
  <h2>{$_('migration.inbound.emailVerify.title')}</h2>

  {#if isTelegram && telegramBotUsername && handle}
    {@const encodedHandle = handle.replaceAll('.', '_')}
    <p>{$_('migration.inbound.emailVerify.telegramInstructions')}</p>
    <div class="info-box">
      <p>
        <a href="https://t.me/{telegramBotUsername}?start={encodedHandle}" target="_blank" rel="noopener">{$_('migration.inbound.emailVerify.openTelegram')}</a>,
        or send <code>/start {handle}</code> to <code>@{telegramBotUsername}</code>
      </p>
    </div>
    <p class="hint">{$_('migration.inbound.emailVerify.waitingForVerification')}</p>
  {:else if isDiscord && discordAppId && handle}
    <p>{$_('migration.inbound.emailVerify.discordInstructions')}</p>
    <div class="info-box">
      <p>
        <a href="https://discord.com/users/{discordAppId}" target="_blank" rel="noopener">{$_('migration.inbound.emailVerify.openDiscord')}</a>,
        or send <code>/start {handle}</code> to <strong>{discordBotUsername ?? 'the bot'}</strong>
      </p>
    </div>
    <p class="hint">{$_('migration.inbound.emailVerify.waitingForVerification')}</p>
  {:else}
    <p>{@html $_('migration.inbound.emailVerify.desc', { values: { email: `<strong>${identifier}</strong>`, channel: channelLabel(channel) } })}</p>

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
  {/if}
</div>
