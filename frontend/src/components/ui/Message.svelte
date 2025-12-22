<script lang="ts">
  import type { Snippet } from 'svelte'

  interface Props {
    variant: 'success' | 'error' | 'warning' | 'info'
    children: Snippet
  }

  let { variant, children }: Props = $props()
</script>

<div class="message message-{variant}">
  {@render children()}
</div>

<style>
  .message {
    padding: var(--space-4);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
  }

  .message-success {
    background: var(--success-bg);
    border: 1px solid var(--success-border);
    color: var(--success-text);
  }

  .message-error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-text);
  }

  .message-warning {
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    color: var(--warning-text);
  }

  .message-info {
    background: var(--accent-muted);
    border: 1px solid var(--accent);
    color: var(--text-primary);
  }
</style>
