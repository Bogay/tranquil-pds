<script lang="ts">
  import type { Snippet } from 'svelte'

  interface Props {
    title?: string
    description?: string
    variant?: 'default' | 'danger'
    children: Snippet
  }

  let {
    title,
    description,
    variant = 'default',
    children
  }: Props = $props()
</script>

<section class="section section-{variant}">
  {#if title}
    <h2>{title}</h2>
  {/if}
  {#if description}
    <p class="description">{description}</p>
  {/if}
  {@render children()}
</section>

<style>
  .section {
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
    padding: var(--space-6);
  }

  .section-danger {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
  }

  .section-danger h2 {
    color: var(--error-text);
  }

  h2 {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-lg);
  }

  .description {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin-bottom: var(--space-5);
  }
</style>
