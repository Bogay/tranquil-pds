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

<style>
  .app-password-step {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .warning-box {
    padding: var(--space-5);
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius-lg);
    font-size: var(--text-sm);
  }

  .warning-box strong {
    display: block;
    margin-bottom: var(--space-3);
    color: var(--warning-text);
  }

  .warning-box p {
    margin: 0;
    color: var(--warning-text);
  }

  .app-password-display {
    background: var(--bg-card);
    border: 2px solid var(--accent);
    border-radius: var(--radius-xl);
    padding: var(--space-6);
    text-align: center;
  }

  .app-password-label {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin-bottom: var(--space-4);
  }

  .app-password-code {
    display: block;
    font-size: var(--text-xl);
    font-family: ui-monospace, monospace;
    letter-spacing: 0.1em;
    padding: var(--space-5);
    background: var(--bg-input);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-4);
    user-select: all;
  }

  .copy-btn {
    padding: var(--space-3) var(--space-5);
    font-size: var(--text-sm);
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    cursor: pointer;
    font-weight: var(--font-normal);
  }

  .checkbox-label input[type="checkbox"] {
    width: auto;
    padding: 0;
  }
</style>
