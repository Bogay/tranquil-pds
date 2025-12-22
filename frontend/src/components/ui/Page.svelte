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

<style>
  .page {
    margin: 0 auto;
    padding: var(--space-7);
  }

  .page-sm { max-width: var(--width-sm); }
  .page-md { max-width: var(--width-md); }
  .page-lg { max-width: var(--width-lg); }

  header {
    margin-bottom: var(--space-7);
  }

  .back-link {
    display: inline-block;
    color: var(--text-secondary);
    font-size: var(--text-sm);
    text-decoration: none;
    margin-bottom: var(--space-3);
  }

  .back-link:hover {
    color: var(--accent);
  }

  .header-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--space-4);
  }

  h1 {
    margin: 0;
  }

  .actions {
    display: flex;
    gap: var(--space-3);
  }
</style>
