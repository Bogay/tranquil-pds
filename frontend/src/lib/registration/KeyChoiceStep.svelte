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

<style>
  .key-choice-step {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .info-box {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: var(--space-5);
    font-size: var(--text-sm);
  }

  .info-box strong {
    display: block;
    margin-bottom: var(--space-3);
  }

  .info-box p {
    margin: 0;
    color: var(--text-secondary);
  }

  .key-choice-options {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .key-choice-btn {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-2);
    padding: var(--space-5);
    background: var(--bg-card);
    border: 2px solid var(--border-color);
    border-radius: var(--radius-lg);
    text-align: left;
    cursor: pointer;
    transition: border-color 0.2s;
  }

  .key-choice-btn:hover:not(:disabled) {
    border-color: var(--accent);
  }

  .key-choice-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .key-choice-title {
    font-weight: var(--font-semibold);
    color: var(--text-primary);
  }

  .key-choice-desc {
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .loading {
    text-align: center;
    color: var(--text-secondary);
  }
</style>
