<script lang="ts">
  import { _ } from '../../lib/i18n'
  import type { Session } from '../../lib/types/api'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()
</script>

<div class="overview">
  <dl>
    <dt>{$_('dashboard.handle')}</dt>
    <dd>
      @{session.handle}
      {#if session.isAdmin}
        <span class="badge admin">{$_('dashboard.admin')}</span>
      {/if}
      {#if session.accountKind === 'migrated'}
        <span class="badge migrated">{$_('dashboard.migrated')}</span>
      {:else if session.accountKind === 'deactivated'}
        <span class="badge deactivated">{$_('dashboard.deactivated')}</span>
      {/if}
    </dd>
    <dt>{$_('dashboard.did')}</dt>
    <dd class="mono">{session.did}</dd>
    {#if session.contactKind === 'channel'}
      <dt>{$_('dashboard.primaryContact')}</dt>
      <dd>
        {#if session.preferredChannel === 'email'}
          {session.email || $_('register.email')}
        {:else if session.preferredChannel === 'discord'}
          {$_('register.discord')}
        {:else if session.preferredChannel === 'telegram'}
          {$_('register.telegram')}
        {:else if session.preferredChannel === 'signal'}
          {$_('register.signal')}
        {:else}
          {session.preferredChannel}
        {/if}
        {#if session.preferredChannelVerified}
          <span class="badge success">{$_('dashboard.verified')}</span>
        {:else}
          <span class="badge warning">{$_('dashboard.unverified')}</span>
        {/if}
      </dd>
    {:else if session.contactKind === 'email'}
      <dt>{$_('register.email')}</dt>
      <dd>
        {session.email}
        {#if session.emailConfirmed}
          <span class="badge success">{$_('dashboard.verified')}</span>
        {:else}
          <span class="badge warning">{$_('dashboard.unverified')}</span>
        {/if}
      </dd>
    {/if}
  </dl>
</div>
