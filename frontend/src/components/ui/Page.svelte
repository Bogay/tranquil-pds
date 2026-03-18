<script lang="ts">
  import type { Snippet } from 'svelte'
  import { _ } from '../../lib/i18n'

  interface Props {
    title: string
    size?: 'sm' | 'md' | 'lg'
    backHref?: string
    backLabel?: string
    children: Snippet
    actions?: Snippet
  }

  let {
    title,
    size = 'md',
    backHref,
    backLabel,
    children,
    actions
  }: Props = $props()
</script>

<div class="page page-{size}">
  <header>
    {#if backHref}
      <a href={backHref} class="back-link">&larr; {backLabel || $_('common.backToDashboard')}</a>
    {/if}
    <div class="header-row">
      <h1>{title}</h1>
      {#if actions}
        <div class="actions">
          {@render actions()}
        </div>
      {/if}
    </div>
  </header>
  {@render children()}
</div>
