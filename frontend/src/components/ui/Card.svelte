<script lang="ts">
  import type { Snippet } from 'svelte'
  import type { HTMLAttributes } from 'svelte/elements'

  interface Props extends HTMLAttributes<HTMLDivElement> {
    variant?: 'default' | 'interactive' | 'danger'
    padding?: 'none' | 'sm' | 'md' | 'lg'
    children: Snippet
  }

  let {
    variant = 'default',
    padding = 'md',
    children,
    ...rest
  }: Props = $props()
</script>

<div class="card card-{variant} padding-{padding}" {...rest}>
  {@render children()}
</div>

<style>
  .card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-xl);
  }

  .card-interactive {
    cursor: pointer;
    transition: border-color var(--transition-normal), box-shadow var(--transition-normal);
  }

  .card-interactive:hover {
    border-color: var(--accent);
    box-shadow: 0 2px 8px var(--accent-muted);
  }

  .card-danger {
    background: var(--error-bg);
    border-color: var(--error-border);
  }

  .padding-none { padding: 0; }
  .padding-sm { padding: var(--space-4); }
  .padding-md { padding: var(--space-6); }
  .padding-lg { padding: var(--space-7); }
</style>
