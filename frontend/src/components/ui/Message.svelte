<script lang="ts">
  import type { Snippet } from 'svelte'

  interface Props {
    variant: 'success' | 'error' | 'warning' | 'info'
    children: Snippet
  }

  let { variant, children }: Props = $props()
</script>

<div class="message {variant}">
  {@render children()}
</div>
