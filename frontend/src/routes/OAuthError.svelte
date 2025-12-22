<script lang="ts">
  import { _ } from '../lib/i18n'

  function getError(): string {
    const params = new URLSearchParams(window.location.hash.split('?')[1] || '')
    return params.get('error') || 'Unknown error'
  }

  function getErrorDescription(): string | null {
    const params = new URLSearchParams(window.location.hash.split('?')[1] || '')
    return params.get('error_description')
  }

  function handleBack() {
    window.history.back()
  }

  let error = $derived(getError())
  let errorDescription = $derived(getErrorDescription())
</script>

<div class="oauth-error-container">
  <h1>{$_('oauth.error.title')}</h1>

  <div class="error-box">
    <div class="error-code">{error}</div>
    {#if errorDescription}
      <div class="error-description">{errorDescription}</div>
    {/if}
  </div>

  <button type="button" onclick={handleBack}>
    {$_('oauth.error.tryAgain')}
  </button>
</div>

<style>
  .oauth-error-container {
    max-width: var(--width-sm);
    margin: var(--space-9) auto;
    padding: var(--space-7);
    text-align: center;
  }

  h1 {
    margin: 0 0 var(--space-6) 0;
    color: var(--error-text);
  }

  .error-box {
    padding: var(--space-6);
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: var(--radius-xl);
    margin-bottom: var(--space-6);
  }

  .error-code {
    font-family: monospace;
    font-size: var(--text-base);
    color: var(--error-text);
    margin-bottom: var(--space-2);
  }

  .error-description {
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  button {
    padding: var(--space-3) var(--space-6);
    background: var(--accent);
    color: var(--text-inverse);
    border: none;
    border-radius: var(--radius-md);
    font-size: var(--text-base);
    cursor: pointer;
  }

  button:hover {
    background: var(--accent-hover);
  }
</style>
