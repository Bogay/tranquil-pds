<script lang="ts">
  import type { RegistrationFlow } from './flow.svelte'

  interface Props {
    flow: RegistrationFlow
  }

  let { flow }: Props = $props()

  let copied = $state(false)
  let acknowledged = $state(false)

  function copyToClipboard() {
    if (flow.account?.appPassword) {
      navigator.clipboard.writeText(flow.account.appPassword)
      copied = true
    }
  }
</script>

<div class="app-password-step">
  <div class="warning-box">
    <strong>Important: Save this app password!</strong>
    <p>
      This app password is required to sign into apps that don't support passkeys yet (like bsky.app).
      You will only see this password once.
    </p>
  </div>

  <div class="app-password-display">
    <div class="app-password-label">
      App Password for: <strong>{flow.account?.appPasswordName}</strong>
    </div>
    <code class="app-password-code">{flow.account?.appPassword}</code>
    <button type="button" class="copy-btn" onclick={copyToClipboard}>
      {copied ? 'Copied!' : 'Copy to Clipboard'}
    </button>
  </div>

  <div class="field">
    <label class="checkbox-label">
      <input type="checkbox" bind:checked={acknowledged} />
      <span>I have saved my app password in a secure location</span>
    </label>
  </div>

  <button onclick={() => flow.proceedFromAppPassword()} disabled={!acknowledged}>
    Continue
  </button>
</div>

