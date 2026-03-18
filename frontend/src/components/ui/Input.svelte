<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements'

  interface Props extends HTMLInputAttributes {
    label?: string
    hint?: string
    error?: string
  }

  let {
    label,
    hint,
    error,
    id,
    ...rest
  }: Props = $props()

  const fallbackId = `input-${Math.random().toString(36).slice(2, 9)}`
  let inputId = $derived(id || fallbackId)
</script>

<div>
  {#if label}
    <label for={inputId}>{label}</label>
  {/if}
  <input id={inputId} class:has-error={!!error} {...rest} />
  {#if error}
    <span class="hint error">{error}</span>
  {:else if hint}
    <span class="hint">{hint}</span>
  {/if}
</div>
