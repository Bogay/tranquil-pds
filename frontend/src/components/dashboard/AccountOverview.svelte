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

<style>
  .overview {
    background: var(--bg-secondary);
    padding: var(--space-6);
    border-radius: var(--radius-xl);
  }

  dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: var(--space-3) var(--space-5);
    margin: 0;
  }

  dt {
    font-weight: var(--font-medium);
    color: var(--text-secondary);
  }

  dd {
    margin: 0;
    min-width: 0;
  }

  .mono {
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    word-break: break-all;
  }

  .badge {
    display: inline-block;
    padding: var(--space-1) var(--space-3);
    border-radius: var(--radius-md);
    font-size: var(--text-xs);
    margin-left: var(--space-3);
  }

  .badge.success {
    background: var(--success-bg);
    color: var(--success-text);
  }

  .badge.warning {
    background: var(--warning-bg);
    color: var(--warning-text);
  }

  .badge.admin {
    background: var(--accent);
    color: var(--text-inverse);
  }

  .badge.deactivated {
    background: var(--warning-bg);
    color: var(--warning-text);
    border: 1px solid var(--warning-border);
  }

  .badge.migrated {
    background: var(--info-bg, #e0f2fe);
    color: var(--info-text, #0369a1);
    border: 1px solid var(--info-border, #7dd3fc);
  }

  @media (max-width: 500px) {
    dl {
      grid-template-columns: 1fr;
      gap: var(--space-2);
    }

    dt {
      margin-top: var(--space-3);
    }

    dt:first-child {
      margin-top: 0;
    }
  }
</style>
