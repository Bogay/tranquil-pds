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

<div class="field">
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

<style>
  .has-error {
    border-color: var(--error-text);
  }

  .has-error:focus {
    border-color: var(--error-text);
    box-shadow: 0 0 0 2px var(--error-bg);
  }
</style>
