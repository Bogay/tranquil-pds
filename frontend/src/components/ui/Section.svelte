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

<section class:danger={variant === 'danger'}>
  {#if title}
    <h2>{title}</h2>
  {/if}
  {#if description}
    <p class="description">{description}</p>
  {/if}
  {@render children()}
</section>
