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
