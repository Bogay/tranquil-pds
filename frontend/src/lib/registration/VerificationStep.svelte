<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import { api, ApiError } from '../api'
  import { resendVerification } from '../auth.svelte'
  import type { RegistrationFlow } from './flow.svelte'

  interface Props {
    flow: RegistrationFlow
  }

  let { flow }: Props = $props()

  let verificationCode = $state('')
  let resending = $state(false)
  let resendMessage = $state<string | null>(null)
  let telegramBotUsername = $state<string | undefined>(undefined)

  let pollingInterval: ReturnType<typeof setInterval> | null = null

  const isTelegram = $derived(flow.info.verificationChannel === 'telegram')

  onMount(async () => {
    if (isTelegram) {
      try {
        const serverInfo = await api.describeServer()
        telegramBotUsername = serverInfo.telegramBotUsername
      } catch {
      }
    }
  })

  $effect(() => {
    if (flow.state.step === 'verify' && flow.account && (isTelegram || !verificationCode.trim())) {
      pollingInterval = setInterval(async () => {
        if (!isTelegram && verificationCode.trim()) return
        const advanced = await flow.checkAndAdvanceIfVerified()
        if (advanced && pollingInterval) {
          clearInterval(pollingInterval)
          pollingInterval = null
        }
      }, 3000)
    }

    return () => {
      if (pollingInterval) {
        clearInterval(pollingInterval)
        pollingInterval = null
      }
    }
  })

  onDestroy(() => {
    if (pollingInterval) {
      clearInterval(pollingInterval)
      pollingInterval = null
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

  async function handleSubmit(e: Event) {
    e.preventDefault()
    if (!verificationCode.trim()) return
    resendMessage = null
    await flow.verifyAccount(verificationCode)
  }

  async function handleResend() {
    if (resending || !flow.account) return
    resending = true
    resendMessage = null
    flow.clearError()

    try {
      await resendVerification(flow.account.did)
      resendMessage = 'Verification code resent!'
    } catch (err) {
      if (err instanceof ApiError) {
        flow.setError(err.message || 'Failed to resend code')
      } else if (err instanceof Error) {
        flow.setError(err.message || 'Failed to resend code')
      } else {
        flow.setError('Failed to resend code')
      }
    } finally {
      resending = false
    }
  }
</script>

<div class="verification-step">
  {#if isTelegram && telegramBotUsername}
    {@const handle = flow.account?.handle ?? `${flow.info.handle.trim()}.${flow.state.pdsHostname}`}
    {@const encodedHandle = handle.replaceAll('.', '_')}
    <p class="info-text">
      <a href="https://t.me/{telegramBotUsername}?start={encodedHandle}" target="_blank" rel="noopener">Open Telegram to verify</a>,
      or send <code>/start {handle}</code> to <code>@{telegramBotUsername}</code> manually.
    </p>
    <p class="info-text waiting">Waiting for verification...</p>
  {:else}
    <p class="info-text">
      We've sent a verification code to your {channelLabel(flow.info.verificationChannel)}.
      Enter it below to continue.
    </p>

    {#if resendMessage}
      <div class="message success">{resendMessage}</div>
    {/if}

    <form onsubmit={handleSubmit}>
      <div class="field">
        <label for="verification-code">Verification Code</label>
        <input
          id="verification-code"
          type="text"
          bind:value={verificationCode}
          placeholder="XXXX-XXXX-XXXX-XXXX"
          disabled={flow.state.submitting}
          required
          autocomplete="one-time-code"
          class="code-input"
        />
        <span class="hint">Copy the entire code from your message, including dashes.</span>
      </div>

      <button type="submit" disabled={flow.state.submitting || !verificationCode.trim()}>
        {flow.state.submitting ? 'Verifying...' : 'Verify'}
      </button>

      <button type="button" class="secondary" onclick={handleResend} disabled={resending}>
        {resending ? 'Resending...' : 'Resend Code'}
      </button>
    </form>
  {/if}
</div>

<style>
  .verification-step {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .info-text {
    color: var(--text-secondary);
    margin: 0;
  }

  .info-text.waiting {
    font-size: var(--text-sm);
  }

  .info-text code {
    font-family: var(--font-mono, monospace);
    background: var(--bg-secondary);
    padding: 0.1em 0.3em;
    border-radius: var(--radius-sm);
  }

  .code-input {
    font-family: var(--font-mono, monospace);
    font-size: var(--text-base);
    letter-spacing: 0.05em;
  }

  .hint {
    display: block;
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin-top: var(--space-1);
  }
</style>
