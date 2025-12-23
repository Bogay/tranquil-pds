<script lang="ts">
  import type { RegistrationFlow } from './flow.svelte'

  interface Props {
    flow: RegistrationFlow
    type: 'initial' | 'updated'
    onConfirm: () => void
    onBack?: () => void
  }

  let { flow, type, onConfirm, onBack }: Props = $props()

  let copied = $state(false)
  let confirmed = $state(false)

  const didDocument = $derived(
    type === 'initial'
      ? flow.externalDidWeb.initialDidDocument
      : flow.externalDidWeb.updatedDidDocument
  )

  const title = $derived(
    type === 'initial'
      ? 'Step 1: Upload your DID document'
      : 'Step 2: Update your DID document'
  )

  const description = $derived(
    type === 'initial'
      ? 'Copy the JSON below and save it at:'
      : 'The PDS has assigned a new signing key for your account. Update your DID document with this new key:'
  )

  const confirmLabel = $derived(
    type === 'initial'
      ? 'I have uploaded the DID document to my domain'
      : 'I have updated the DID document on my domain'
  )

  const buttonLabel = $derived(
    type === 'initial' ? 'Continue' : 'Activate Account'
  )

  function copyToClipboard() {
    if (didDocument) {
      navigator.clipboard.writeText(didDocument)
      copied = true
    }
  }

  function handleConfirm() {
    if (!confirmed) {
      flow.setError(`Please confirm you have ${type === 'initial' ? 'uploaded' : 'updated'} the DID document`)
      return
    }
    onConfirm()
  }
</script>

<div class="did-doc-step">
  <div class="warning-box">
    <strong>{title}</strong>
    <p>{description}</p>
    <code class="did-url">https://{flow.extractDomain(flow.info.externalDid || '')}/.well-known/did.json</code>
  </div>

  <div class="did-doc-display">
    <pre class="did-doc-code">{didDocument}</pre>
    <button type="button" class="copy-btn" onclick={copyToClipboard}>
      {copied ? 'Copied!' : 'Copy to Clipboard'}
    </button>
  </div>

  <div class="field">
    <label class="checkbox-label">
      <input type="checkbox" bind:checked={confirmed} />
      <span>{confirmLabel}</span>
    </label>
  </div>

  <button onclick={handleConfirm} disabled={flow.state.submitting || !confirmed}>
    {flow.state.submitting ? (type === 'initial' ? 'Creating account...' : 'Activating...') : buttonLabel}
  </button>

  {#if onBack}
    <button type="button" class="secondary" onclick={onBack} disabled={flow.state.submitting}>
      Back
    </button>
  {/if}
</div>

<style>
  .did-doc-step {
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

  .did-url {
    display: block;
    margin-top: var(--space-3);
    padding: var(--space-3);
    background: var(--bg-input);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    word-break: break-all;
  }

  .did-doc-display {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }

  .did-doc-code {
    margin: 0;
    padding: var(--space-4);
    background: var(--bg-input);
    font-size: var(--text-xs);
    overflow-x: auto;
    white-space: pre;
    max-height: 300px;
    overflow-y: auto;
  }

  .copy-btn {
    width: 100%;
    border-radius: 0;
    margin: 0;
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
