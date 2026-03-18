<script lang="ts">
  import { startOAuthRegister } from '../lib/oauth'
  import { _ } from '../lib/i18n'

  let error = $state<string | null>(null)
  let initiated = false

  $effect(() => {
    if (!initiated) {
      initiated = true
      startOAuthRegister().catch((err) => {
        error = err instanceof Error ? err.message : 'Failed to start registration'
      })
    }
  })
</script>

<div class="register-redirect">
  {#if error}
    <div class="message error">{error}</div>
    <a href="/app/login">{$_('register.signIn')}</a>
  {:else}
    <div class="loading-content">
      <p>{$_('common.loading')}</p>
    </div>
  {/if}
</div>
