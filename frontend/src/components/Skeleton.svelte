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
