<script lang="ts">
  import { getToasts, dismissToast, type Toast } from '../lib/toast.svelte'

  const toasts = $derived(getToasts())

  function handleDismiss(id: number) {
    dismissToast(id)
  }

</script>

{#if toasts.length > 0}
  <div class="toast-container" role="region" aria-label="Notifications">
    {#each toasts as toast (toast.id)}
      <div
        class="toast toast-{toast.type}"
        role="alert"
        aria-live="polite"
      >
        <span class="toast-message">{toast.message}</span>
        <button
          type="button"
          class="toast-dismiss"
          onclick={() => handleDismiss(toast.id)}
          aria-label="Dismiss notification"
        >
          x
        </button>
      </div>
    {/each}
  </div>
{/if}
