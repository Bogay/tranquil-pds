<script lang="ts">
  type Variant = 'line' | 'circle' | 'card'
  type Size = 'tiny' | 'short' | 'medium' | 'full'

  interface Props {
    variant?: Variant
    size?: Size
    lines?: number
    class?: string
  }

  let { variant = 'line', size = 'full', lines = 1, class: className = '' }: Props = $props()
</script>

{#if variant === 'card'}
  <div class="skeleton-card {className}">
    <div class="skeleton-header">
      <div class="skeleton-line short"></div>
      <div class="skeleton-line tiny"></div>
    </div>
    {#each Array(lines) as _}
      <div class="skeleton-line"></div>
    {/each}
    <div class="skeleton-line medium"></div>
  </div>
{:else if variant === 'circle'}
  <div class="skeleton-circle {className}"></div>
{:else}
  {#each Array(lines) as _, i}
    <div class="skeleton-line {size} {className}" class:last={i === lines - 1}></div>
  {/each}
{/if}

<style>
  .skeleton-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: var(--space-3);
  }

  .skeleton-header {
    display: flex;
    gap: var(--space-2);
    margin-bottom: var(--space-2);
  }

  .skeleton-line {
    height: 14px;
    background: var(--bg-tertiary);
    border-radius: var(--radius-sm);
    animation: skeleton-pulse 1.5s ease-in-out infinite;
    margin-bottom: var(--space-1);
  }

  .skeleton-line.last {
    margin-bottom: 0;
  }

  .skeleton-line.tiny { width: 50px; }
  .skeleton-line.short { width: 80px; }
  .skeleton-line.medium { width: 60%; }
  .skeleton-line.full { width: 100%; }

  .skeleton-circle {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    background: var(--bg-tertiary);
    animation: skeleton-pulse 1.5s ease-in-out infinite;
  }

</style>
