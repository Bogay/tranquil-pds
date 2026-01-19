<script lang="ts">
  import { _ } from '../lib/i18n'
  import { routes, buildUrl } from '../lib/types/routes'
  import { getRequestUriFromUrl } from '../lib/oauth'

  function getError(): string {
    const params = new URLSearchParams(window.location.search)
    return params.get('error') || 'Unknown error'
  }

  function getErrorDescription(): string | null {
    const params = new URLSearchParams(window.location.search)
    return params.get('error_description')
  }

  function handleBack() {
    window.history.back()
  }

  function handleSignIn() {
    const requestUri = getRequestUriFromUrl()
    const url = requestUri
      ? buildUrl(routes.oauthLogin, { request_uri: requestUri })
      : routes.login
    window.location.href = `/app${url}`
  }

  let error = $derived(getError())
  let errorDescription = $derived(getErrorDescription())
</script>

<div class="page-sm text-center">
  <h1>{$_('oauth.error.title')}</h1>

  <div class="error-box">
    <div class="error-code">{error}</div>
    {#if errorDescription}
      <div class="error-description">{errorDescription}</div>
    {/if}
  </div>

  <div class="actions">
    <button type="button" onclick={handleBack}>
      {$_('oauth.error.tryAgain')}
    </button>
    <button type="button" class="secondary" onclick={handleSignIn}>
      {$_('common.signIn')}
    </button>
  </div>
</div>

<style>
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
    font-family: var(--font-mono);
    font-size: var(--text-base);
    color: var(--error-text);
    margin-bottom: var(--space-2);
  }

  .error-description {
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  .actions {
    display: flex;
    gap: var(--space-3);
    justify-content: center;
  }
</style>
