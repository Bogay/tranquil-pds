<script lang="ts">
  import { _ } from '../../lib/i18n'
  import { navigate, routes } from '../../lib/router.svelte'
  import type { Session } from '../../lib/types/api'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  function startMigration(type: 'inbound' | 'offline') {
    const url = type === 'offline'
      ? `${routes.migrate}?flow=offline`
      : routes.migrate
    navigate(url as typeof routes.migrate)
  }
</script>

<div class="migration">
  <section>
    <h3>{$_('migration.migrateHere')}</h3>
    <p class="description">{$_('migration.migrateHereDesc')}</p>
    <ul class="feature-list">
      <li>{$_('migration.bringDid')}</li>
      <li>{$_('migration.transferData')}</li>
      <li>{$_('migration.keepFollowers')}</li>
    </ul>
    <button onclick={() => startMigration('inbound')}>
      {$_('migration.inbound.review.startMigration')}
    </button>
  </section>

  <section>
    <h3>{$_('migration.offlineRestore')}</h3>
    <p class="description">{$_('migration.offlineRestoreDesc')}</p>
    <ul class="feature-list">
      <li>{$_('migration.offlineFeature1')}</li>
      <li>{$_('migration.offlineFeature2')}</li>
      <li>{$_('migration.offlineFeature3')}</li>
    </ul>
    <button class="secondary" onclick={() => startMigration('offline')}>
      {$_('migration.offlineRestore')}
    </button>
  </section>

  {#if session.accountKind === 'migrated'}
    <section class="info-section">
      <h3>{$_('dashboard.migratedTitle')}</h3>
      <p>{$_('dashboard.migratedMessage', { values: { pds: session.migratedToPds || 'another PDS' } })}</p>
    </section>
  {/if}
</div>

<style>
  .migration {
    max-width: var(--width-md);
  }

  section {
    background: var(--bg-secondary);
    padding: var(--space-5);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-5);
  }

  section h3 {
    margin: 0 0 var(--space-2) 0;
    font-size: var(--text-base);
  }

  .description {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin: 0 0 var(--space-4) 0;
  }

  .feature-list {
    list-style: none;
    padding: 0;
    margin: 0 0 var(--space-4) 0;
  }

  .feature-list li {
    padding: var(--space-2) 0;
    padding-left: var(--space-4);
    position: relative;
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .feature-list li::before {
    content: '✓';
    position: absolute;
    left: 0;
    color: var(--success-text);
  }

  .info-section {
    background: var(--info-bg, #e0f2fe);
    border: 1px solid var(--info-border, #7dd3fc);
  }

  .info-section h3 {
    color: var(--info-text, #0369a1);
  }

  .info-section p {
    color: var(--info-text, #0369a1);
    font-size: var(--text-sm);
    margin: 0;
  }
</style>
