<script lang="ts">
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
  <h1>Authorization Error</h1>

  <div class="error-box">
    <div class="error-code">{error}</div>
    {#if errorDescription}
      <div class="error-description">{errorDescription}</div>
    {/if}
  </div>

  <button type="button" onclick={handleBack}>
    Go Back
  </button>
</div>

<style>
  .oauth-error-container {
    max-width: 400px;
    margin: 4rem auto;
    padding: 2rem;
    text-align: center;
  }

  h1 {
    margin: 0 0 1.5rem 0;
    color: var(--error-text);
  }

  .error-box {
    padding: 1.5rem;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    border-radius: 8px;
    margin-bottom: 1.5rem;
  }

  .error-code {
    font-family: monospace;
    font-size: 1rem;
    color: var(--error-text);
    margin-bottom: 0.5rem;
  }

  .error-description {
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  button {
    padding: 0.75rem 1.5rem;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
  }

  button:hover {
    background: var(--accent-hover);
  }
</style>
