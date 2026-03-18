<script lang="ts">
  import type { VerificationChannel } from '../lib/types/api'
  import { _ } from '../lib/i18n'

  interface Props {
    channel: VerificationChannel
    email: string
    discordUsername: string
    telegramUsername: string
    signalUsername: string
    availableChannels: VerificationChannel[]
    disabled?: boolean
    onChannelChange: (channel: VerificationChannel) => void
    onEmailChange: (value: string) => void
    onDiscordChange: (value: string) => void
    onTelegramChange: (value: string) => void
    onSignalChange: (value: string) => void
  }

  let {
    channel,
    email,
    discordUsername,
    telegramUsername,
    signalUsername,
    availableChannels,
    disabled = false,
    onChannelChange,
    onEmailChange,
    onDiscordChange,
    onTelegramChange,
    onSignalChange,
  }: Props = $props()

  function channelLabel(ch: string): string {
    switch (ch) {
      case 'email': return $_('register.email')
      case 'discord': return $_('register.discord')
      case 'telegram': return $_('register.telegram')
      case 'signal': return $_('register.signal')
      default: return ch
    }
  }

  function isAvailable(ch: VerificationChannel): boolean {
    return availableChannels.includes(ch)
  }
</script>

<div>
  <label for="verification-channel">{$_('register.verificationMethod')}</label>
  <select id="verification-channel" value={channel} onchange={(e) => onChannelChange((e.target as HTMLSelectElement).value as VerificationChannel)} {disabled}>
    <option value="email">{channelLabel('email')}</option>
    {#if isAvailable('discord')}
      <option value="discord">{channelLabel('discord')}</option>
    {/if}
    {#if isAvailable('telegram')}
      <option value="telegram">{channelLabel('telegram')}</option>
    {/if}
    {#if isAvailable('signal')}
      <option value="signal">{channelLabel('signal')}</option>
    {/if}
  </select>
</div>

{#if channel === 'email'}
  <div>
    <label for="comms-email">{$_('register.emailAddress')}</label>
    <input
      id="comms-email"
      type="email"
      value={email}
      oninput={(e) => onEmailChange((e.target as HTMLInputElement).value)}
      placeholder={$_('register.emailPlaceholder')}
      {disabled}
      required
    />
  </div>
{:else if channel === 'discord'}
  <div>
    <label for="comms-discord">{$_('register.discordUsername')}</label>
    <input
      id="comms-discord"
      type="text"
      value={discordUsername}
      oninput={(e) => onDiscordChange((e.target as HTMLInputElement).value)}
      placeholder={$_('register.discordUsernamePlaceholder')}
      {disabled}
      required
    />
  </div>
{:else if channel === 'telegram'}
  <div>
    <label for="comms-telegram">{$_('register.telegramUsername')}</label>
    <input
      id="comms-telegram"
      type="text"
      value={telegramUsername}
      oninput={(e) => onTelegramChange((e.target as HTMLInputElement).value)}
      placeholder={$_('register.telegramUsernamePlaceholder')}
      {disabled}
      required
    />
  </div>
{:else if channel === 'signal'}
  <div>
    <label for="comms-signal">{$_('register.signalUsername')}</label>
    <input
      id="comms-signal"
      type="tel"
      value={signalUsername}
      oninput={(e) => onSignalChange((e.target as HTMLInputElement).value)}
      placeholder={$_('register.signalUsernamePlaceholder')}
      {disabled}
      required
    />
    <p class="hint">{$_('register.signalUsernameHint')}</p>
  </div>
{/if}
