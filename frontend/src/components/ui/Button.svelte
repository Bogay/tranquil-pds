<script lang="ts">
  import type { Snippet } from 'svelte'
  import type { HTMLButtonAttributes } from 'svelte/elements'

  interface Props extends HTMLButtonAttributes {
    variant?: 'primary' | 'secondary' | 'tertiary' | 'danger' | 'ghost'
    size?: 'sm' | 'md' | 'lg'
    loading?: boolean
    fullWidth?: boolean
    children: Snippet
  }

  let {
    variant = 'primary',
    size = 'md',
    loading = false,
    fullWidth = false,
    disabled,
    children,
    ...rest
  }: Props = $props()
</script>

<button
  class="btn btn-{variant} btn-{size}"
  class:full-width={fullWidth}
  disabled={disabled || loading}
  {...rest}
>
  {#if loading}
    <span class="spinner"></span>
  {/if}
  {@render children()}
</button>

<style>
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--space-2);
  }

  .btn-sm {
    padding: var(--space-2) var(--space-4);
    font-size: var(--text-sm);
  }

  .btn-md {
    padding: var(--space-4) var(--space-6);
    font-size: var(--text-base);
  }

  .btn-lg {
    padding: var(--space-5) var(--space-7);
    font-size: var(--text-lg);
  }

  .full-width {
    width: 100%;
  }

  .spinner {
    width: 1em;
    height: 1em;
    border: 2px solid currentColor;
    border-right-color: transparent;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }

</style>
