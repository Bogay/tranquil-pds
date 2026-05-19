<script lang="ts">
  import { onMount } from 'svelte'
  import { _ } from '../../lib/i18n'
  import { api } from '../../lib/api'
  import { toast } from '../../lib/toast.svelte'
  import type { Session, ServerDescription, ServerStats } from '../../lib/types/api'

  interface Props {
    session: Session
  }

  let { session }: Props = $props()

  let serverInfo = $state<ServerDescription | null>(null)
  let serverStats = $state<ServerStats | null>(null)
  let loading = $state(true)

  onMount(async () => {
    try {
      serverInfo = await api.describeServer()
    } catch {
      // server info is best-effort — account and environment sections still render
    }
    if (session.isAdmin) {
      try {
        serverStats = await api.getServerStats(session.accessJwt)
      } catch {
        // stats are best-effort
      }
    }
    loading = false
  })

  const svelteVersion = __SVELTE_VERSION__
  const svelteI18nVersion = __SVELTE_I18N_VERSION__
  const viteVersion = __VITE_VERSION__
  const buildMode = import.meta.env.MODE
  const userAgent = globalThis.navigator?.userAgent ?? ''
  const browserLocale = globalThis.navigator?.language ?? ''
  const screenSize = $derived(
    `${globalThis.innerWidth ?? 0}x${globalThis.innerHeight ?? 0}`
  )
  const serverUrl = globalThis.location?.origin ?? ''

  async function copyDebugInfo() {
    const lines = [
      'Tranquil Debug Info',
      '---',
      `Server URL: ${serverUrl}`,
      `PDS Version: ${serverInfo?.version ?? $_('about.unknown')}`,
      `Server DID: ${serverInfo?.did ?? $_('about.unknown')}`,
      `Available Domains: ${serverInfo?.availableUserDomains?.join(', ') ?? $_('about.unknown')}`,
      `Invite Code Required: ${serverInfo?.inviteCodeRequired ? $_('about.yes') : $_('about.no')}`,
      `Self-Hosted DID:web: ${serverInfo?.selfHostedDidWebEnabled ? $_('about.enabled') : $_('about.disabled')}`,
      `Contact Email: ${serverInfo?.contact?.email ?? $_('about.notConfigured')}`,
      `Privacy Policy: ${serverInfo?.links?.privacyPolicy ?? $_('about.notConfigured')}`,
      `Terms of Service: ${serverInfo?.links?.termsOfService ?? $_('about.notConfigured')}`,
      ...(session.isAdmin ? [
        `User Count: ${serverStats?.userCount?.toLocaleString() ?? $_('about.unknown')}`,
        `Available Channels: ${serverInfo?.availableCommsChannels?.join(', ') ?? $_('about.unknown')}`,
        `Discord Bot: ${serverInfo?.discordBotUsername ?? $_('about.notConfigured')}`,
        `Discord App ID: ${serverInfo?.discordAppId ?? $_('about.notConfigured')}`,
        `Telegram Bot: ${serverInfo?.telegramBotUsername ?? $_('about.notConfigured')}`,
        `Svelte: ${svelteVersion}`,
        `svelte-i18n: ${svelteI18nVersion}`,
        `Vite: ${viteVersion}`,
        `Build Mode: ${buildMode}`,
      ] : []),
      `DID: ${session.did}`,
      `Handle: ${session.handle}`,
      `Account Status: ${session.accountKind}`,
      `Admin: ${session.isAdmin ? $_('about.yes') : $_('about.no')}`,
      `User Agent: ${userAgent}`,
      `Locale: ${browserLocale}`,
      `Screen: ${screenSize}`,
    ]
    try {
      await navigator.clipboard.writeText(lines.join('\n'))
      toast.success($_('about.copied'))
    } catch {
      toast.error($_('about.copyFailed'))
    }
  }
</script>

<div class="about-page">
  {#if loading}
    <div class="loading">{$_('common.loading')}</div>
  {:else}
    <section class="about-section">
      <h3>{$_('about.serverSection')}</h3>
      <div class="about-meta">
        <dl>
          <dt>{$_('about.serverUrl')}</dt>
          <dd class="mono">{serverUrl}</dd>
          <dt>{$_('about.pdsVersion')}</dt>
          <dd>{serverInfo?.version ?? $_('about.unknown')}</dd>
          <dt>{$_('about.serverDid')}</dt>
          <dd class="mono">{serverInfo?.did ?? $_('about.unknown')}</dd>
          <dt>{$_('about.availableDomains')}</dt>
          <dd>{serverInfo?.availableUserDomains?.join(', ') ?? $_('about.unknown')}</dd>
          <dt>{$_('about.inviteCodeRequired')}</dt>
          <dd>{serverInfo?.inviteCodeRequired ? $_('about.yes') : $_('about.no')}</dd>
          <dt>{$_('about.selfHostedDidWeb')}</dt>
          <dd>{serverInfo?.selfHostedDidWebEnabled ? $_('about.enabled') : $_('about.disabled')}</dd>
          {#if serverStats}
            <dt>{$_('about.userCount')}</dt>
            <dd>{serverStats.userCount.toLocaleString()}</dd>
          {/if}
        </dl>
      </div>
    </section>

    <section class="about-section">
      <h3>{$_('about.contactSection')}</h3>
      <div class="about-meta">
        <dl>
          <dt>{$_('about.contactEmail')}</dt>
          <dd>{serverInfo?.contact?.email ?? $_('about.notConfigured')}</dd>
          <dt>{$_('about.privacyPolicy')}</dt>
          <dd>
            {#if serverInfo?.links?.privacyPolicy}
              <a href={serverInfo.links.privacyPolicy} target="_blank" rel="noopener noreferrer">{serverInfo.links.privacyPolicy}</a>
            {:else}
              {$_('about.notConfigured')}
            {/if}
          </dd>
          <dt>{$_('about.termsOfService')}</dt>
          <dd>
            {#if serverInfo?.links?.termsOfService}
              <a href={serverInfo.links.termsOfService} target="_blank" rel="noopener noreferrer">{serverInfo.links.termsOfService}</a>
            {:else}
              {$_('about.notConfigured')}
            {/if}
          </dd>
        </dl>
      </div>
    </section>

    {#if session.isAdmin}
      <section class="about-section">
        <h3>{$_('about.communicationSection')}</h3>
        <div class="about-meta">
          <dl>
            <dt>{$_('about.availableChannels')}</dt>
            <dd>{serverInfo?.availableCommsChannels?.join(', ') ?? $_('about.unknown')}</dd>
            <dt>{$_('about.discordBot')}</dt>
            <dd>{serverInfo?.discordBotUsername ?? $_('about.notConfigured')}</dd>
            <dt>{$_('about.discordAppId')}</dt>
            <dd>{serverInfo?.discordAppId ?? $_('about.notConfigured')}</dd>
            <dt>{$_('about.telegramBot')}</dt>
            <dd>{serverInfo?.telegramBotUsername ?? $_('about.notConfigured')}</dd>
          </dl>
        </div>
      </section>
    {/if}

    {#if session.isAdmin}
      <section class="about-section">
        <h3>{$_('about.frontendSection')}</h3>
        <div class="about-meta">
          <dl>
            <dt>{$_('about.svelteVersion')}</dt>
            <dd>{svelteVersion}</dd>
            <dt>{$_('about.svelteI18nVersion')}</dt>
            <dd>{svelteI18nVersion}</dd>
            <dt>{$_('about.viteVersion')}</dt>
            <dd>{viteVersion}</dd>
            <dt>{$_('about.buildMode')}</dt>
            <dd>{buildMode}</dd>
          </dl>
        </div>
      </section>
    {/if}

    <section class="about-section">
      <h3>{$_('about.accountSection')}</h3>
      <div class="about-meta">
        <dl>
          <dt>{$_('about.did')}</dt>
          <dd class="mono">{session.did}</dd>
          <dt>{$_('about.handle')}</dt>
          <dd>{session.handle}</dd>
          <dt>{$_('about.accountStatus')}</dt>
          <dd>{session.accountKind}</dd>
          <dt>{$_('about.adminStatus')}</dt>
          <dd>{session.isAdmin ? $_('about.yes') : $_('about.no')}</dd>
        </dl>
      </div>
    </section>

    <section class="about-section">
      <h3>{$_('about.environmentSection')}</h3>
      <div class="about-meta">
        <dl>
          <dt>{$_('about.userAgent')}</dt>
          <dd>{userAgent}</dd>
          <dt>{$_('about.locale')}</dt>
          <dd>{browserLocale}</dd>
          <dt>{$_('about.screenSize')}</dt>
          <dd>{screenSize}</dd>
        </dl>
      </div>
    </section>

    <div class="actions">
      <button type="button" onclick={copyDebugInfo}>
        {$_('about.copyDebugInfo')}
      </button>
    </div>
  {/if}
</div>

<style>
  .about-page {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }

  .about-section h3 {
    margin: 0 0 var(--space-3) 0;
    font-size: var(--text-lg);
  }

  .about-meta {
    background: var(--bg-secondary);
    padding: var(--space-4);
  }

  .about-meta dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: var(--space-2) var(--space-4);
    margin: 0;
  }

  .about-meta dt {
    font-weight: var(--font-medium);
    color: var(--text-secondary);
  }

  .about-meta dd {
    margin: 0;
    word-break: break-all;
  }
</style>
