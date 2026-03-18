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
  class="{variant === 'primary' ? '' : variant} {size !== 'md' ? size : ''}"
  class:full-width={fullWidth}
  disabled={disabled || loading}
  {...rest}
>
  {@render children()}
</button>
