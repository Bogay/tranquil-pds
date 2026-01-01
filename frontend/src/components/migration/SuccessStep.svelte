<script lang="ts">
  import type { Snippet } from 'svelte'
  import { _ } from '../../lib/i18n'

  interface Props {
    handle: string
    did: string
    description?: string
    extraContent?: Snippet
  }

  let { handle, did, description, extraContent }: Props = $props()
</script>

<div class="step-content success-content">
  <div class="success-icon">✓</div>
  <h2>{$_('migration.inbound.success.title')}</h2>
  <p>{description || $_('migration.inbound.success.desc')}</p>

  <div class="success-details">
    <div class="detail-row">
      <span class="label">{$_('migration.inbound.success.yourNewHandle')}:</span>
      <span class="value">{handle}</span>
    </div>
    <div class="detail-row">
      <span class="label">{$_('migration.inbound.success.did')}:</span>
      <span class="value mono">{did}</span>
    </div>
  </div>

  {#if extraContent}
    {@render extraContent()}
  {/if}

  <p class="redirect-text">{$_('migration.inbound.success.redirecting')}</p>
</div>
