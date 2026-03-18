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
