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
