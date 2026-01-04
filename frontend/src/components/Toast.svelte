<script lang="ts">
  import { getToasts, dismissToast, type Toast } from '../lib/toast.svelte'

  const toasts = $derived(getToasts())

  function handleDismiss(id: number) {
    dismissToast(id)
  }

  function getIcon(type: Toast['type']): string {
    switch (type) {
      case 'success':
        return '✓'
      case 'error':
        return '!'
      case 'warning':
        return '⚠'
      case 'info':
        return 'i'
    }
  }
</script>

{#if toasts.length > 0}
  <div class="toast-container" role="region" aria-label="Notifications">
    {#each toasts as toast (toast.id)}
      <div
        class="toast toast-{toast.type}"
        class:dismissing={toast.dismissing}
        role="alert"
        aria-live="polite"
      >
        <span class="toast-icon">{getIcon(toast.type)}</span>
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

<style>
  .toast-container {
    position: fixed;
    top: var(--space-6);
    right: var(--space-6);
    z-index: 9999;
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    max-width: min(400px, calc(100vw - var(--space-12)));
    pointer-events: none;
  }

  .toast {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: var(--space-4);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-lg);
    pointer-events: auto;
    animation: toast-in 0.1s ease-out;
  }

  .toast.dismissing {
    animation: toast-out 0.15s ease-in forwards;
  }

  @keyframes toast-in {
    from {
      opacity: 0;
      transform: scale(0.95);
    }
    to {
      opacity: 1;
      transform: scale(1);
    }
  }

  @keyframes toast-out {
    from {
      opacity: 1;
      transform: scale(1);
    }
    to {
      opacity: 0;
      transform: scale(0.95);
    }
  }

  .toast-success {
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    color: var(--success-text);
  }

  .toast-error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-text);
  }

  .toast-warning {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    color: var(--warning-text);
  }

  .toast-info {
    background: var(--accent-muted);
    border: 1px solid var(--accent);
    color: var(--text-primary);
  }

  .toast-icon {
    flex-shrink: 0;
    width: 20px;
    height: 20px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    font-size: var(--text-xs);
    font-weight: var(--font-bold);
  }

  .toast-success .toast-icon {
    background: var(--success-text);
    color: var(--success-bg);
  }

  .toast-error .toast-icon {
    background: var(--error-text);
    color: var(--error-bg);
  }

  .toast-warning .toast-icon {
    background: var(--warning-text);
    color: var(--warning-bg);
  }

  .toast-info .toast-icon {
    background: var(--accent);
    color: var(--bg-card);
  }

  .toast-message {
    flex: 1;
    font-size: var(--text-sm);
    line-height: 1.4;
  }

  .toast-dismiss {
    flex-shrink: 0;
    width: 20px;
    height: 20px;
    padding: 0;
    border: none;
    background: transparent;
    cursor: pointer;
    opacity: 0.6;
    font-size: var(--text-sm);
    line-height: 1;
    color: inherit;
    border-radius: var(--radius-sm);
  }

  .toast-dismiss:hover {
    opacity: 1;
    background: rgba(0, 0, 0, 0.1);
  }

  @media (max-width: 480px) {
    .toast-container {
      top: var(--space-4);
      right: var(--space-4);
      left: var(--space-4);
      max-width: none;
    }
  }
</style>
