<script lang="ts">
  import type { RegistrationFlow } from './flow.svelte'

  interface Props {
    flow: RegistrationFlow
  }

  let { flow }: Props = $props()
</script>

<div class="key-choice-step">
  <div class="info-box">
    <strong>External did:web Setup</strong>
    <p>
      To use your own domain ({flow.extractDomain(flow.info.externalDid || '')}) as your identity,
      you'll need to host a DID document. Choose how you'd like to set up the signing key:
    </p>
  </div>

  <div class="key-choice-options">
    <button
      class="key-choice-btn"
      onclick={() => flow.selectKeyMode('reserved')}
      disabled={flow.state.submitting}
    >
      <span class="key-choice-title">Let the PDS generate a key</span>
      <span class="key-choice-desc">Simpler setup - we'll provide the public key for your DID document</span>
    </button>

    <button
      class="key-choice-btn"
      onclick={() => flow.selectKeyMode('byod')}
      disabled={flow.state.submitting}
    >
      <span class="key-choice-title">I'll provide my own key</span>
      <span class="key-choice-desc">Advanced - generate a key in your browser for initial authentication</span>
    </button>
  </div>

  {#if flow.state.submitting}
    <p class="loading">Generating key...</p>
  {/if}

  <button type="button" class="secondary" onclick={() => flow.goBack()} disabled={flow.state.submitting}>
    Back
  </button>
</div>
