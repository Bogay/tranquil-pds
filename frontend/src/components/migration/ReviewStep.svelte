<script lang="ts">
  import type { Snippet } from 'svelte'
  import { _ } from '../../lib/i18n'

  interface ReviewRow {
    label: string
    value: string
    mono?: boolean
  }

  interface Props {
    description: string
    rows: ReviewRow[]
    loading: boolean
    onBack: () => void
    onContinue: () => void
    warning?: Snippet
  }

  let { description, rows, loading, onBack, onContinue, warning }: Props = $props()
</script>

<div class="step-content">
  <h2>{$_('migration.inbound.review.title')}</h2>
  <p>{description}</p>

  <div class="review-card">
    {#each rows as row}
      <div class="review-row">
        <span class="label">{row.label}:</span>
        <span class="value" class:mono={row.mono}>{row.value}</span>
      </div>
    {/each}
  </div>

  {#if warning}
    <div class="warning-box">
      {@render warning()}
    </div>
  {/if}

  <div class="button-row">
    <button class="ghost" onclick={onBack} disabled={loading}>{$_('migration.inbound.common.back')}</button>
    <button onclick={onContinue} disabled={loading}>
      {loading ? $_('migration.inbound.review.starting') : $_('migration.inbound.review.startMigration')}
    </button>
  </div>
</div>
