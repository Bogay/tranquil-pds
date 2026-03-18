<script lang="ts">
  import {
    getAuthState,
    logout,
    switchAccount,
    type SavedAccount,
  } from '../lib/auth.svelte'
  import { navigate, routes, getCurrentPath } from '../lib/router.svelte'
  import { _ } from '../lib/i18n'
  import { api } from '../lib/api'
  import { isOk } from '../lib/types/result'
  import { unsafeAsDid, type Did } from '../lib/types/branded'
  import type { Session } from '../lib/types/api'
  import { onMount } from 'svelte'
  import { getServerConfigState } from '../lib/serverConfig.svelte'

  import SettingsContent from '../components/dashboard/SettingsContent.svelte'
  import SecurityContent from '../components/dashboard/SecurityContent.svelte'
  import SessionsContent from '../components/dashboard/SessionsContent.svelte'
  import AppPasswordsContent from '../components/dashboard/AppPasswordsContent.svelte'
  import CommsContent from '../components/dashboard/CommsContent.svelte'
  import RepoContent from '../components/dashboard/RepoContent.svelte'
  import ControllersContent from '../components/dashboard/ControllersContent.svelte'
  import InviteCodesContent from '../components/dashboard/InviteCodesContent.svelte'
  import DidDocumentContent from '../components/dashboard/DidDocumentContent.svelte'
  import AdminContent from '../components/dashboard/AdminContent.svelte'

  type Section = 'settings' | 'security' | 'sessions' | 'app-passwords' | 'comms' | 'repo' | 'controllers' | 'invite-codes' | 'did-document' | 'admin'

  const auth = $derived(getAuthState())
  let dropdownOpen = $state(false)
  let switching = $state(false)
  let inviteCodesEnabled = $state(false)

  function getSession(): Session | null {
    return auth.kind === 'authenticated' ? auth.session : null
  }

  function getSavedAccounts(): readonly SavedAccount[] {
    return auth.savedAccounts
  }

  function isLoading(): boolean {
    return auth.kind === 'loading'
  }

  const session = $derived(getSession())
  const savedAccounts = $derived(getSavedAccounts())
  const loading = $derived(isLoading())
  const isPdsHostedDidWeb = $derived.by(() => {
    if (!session?.did?.startsWith('did:web:')) return false
    const didParts = session.did.split(':')
    if (didParts.length < 3) return false
    const didDomain = didParts[2]
    const hostname = globalThis.location?.hostname
    if (!hostname) return false
    return didDomain === hostname || didDomain.endsWith(`.${hostname}`)
  })
  const otherAccounts = $derived(savedAccounts.filter(a => a.did !== session?.did))
  let isMobile = $state(true)
  const serverConfig = $derived(getServerConfigState())

  const currentPath = $derived(getCurrentPath())
  const currentSection = $derived.by<Section | null>(() => {
    const path = currentPath.split('?')[0]
    const sectionMap: Record<string, Section> = {
      '/settings': 'settings',
      '/security': 'security',
      '/sessions': 'sessions',
      '/app-passwords': 'app-passwords',
      '/comms': 'comms',
      '/repo': 'repo',
      '/controllers': 'controllers',

      '/invite-codes': 'invite-codes',
      '/did-document': 'did-document',
      '/admin': 'admin',
    }
    return sectionMap[path] ?? null
  })

  onMount(async () => {
    isMobile = window.matchMedia('(max-width: 768px)').matches
    try {
      const serverInfo = await api.describeServer()
      inviteCodesEnabled = serverInfo.inviteCodeRequired
    } catch {
      inviteCodesEnabled = false
    }
  })

  $effect(() => {
    if (!loading && !session) {
      navigate(routes.login)
    }
  })

  $effect(() => {
    if (session && currentSection === null && !isMobile) {
      navigate('/settings' as typeof routes.dashboard)
    }
  })

  async function handleLogout() {
    await logout()
    navigate(routes.login)
  }

  async function handleSwitchAccount(did: Did) {
    switching = true
    dropdownOpen = false
    const result = await switchAccount(did)
    if (!isOk(result)) {
      navigate(routes.login)
    }
    switching = false
  }

  function toggleDropdown() {
    dropdownOpen = !dropdownOpen
  }

  function closeDropdown(e: MouseEvent) {
    const target = e.target as HTMLElement
    if (!target.closest('.account-dropdown')) {
      dropdownOpen = false
    }
  }

  $effect(() => {
    if (dropdownOpen) {
      document.addEventListener('click', closeDropdown)
    }
    return () => {
      if (dropdownOpen) {
        document.removeEventListener('click', closeDropdown)
      }
    }
  })

  const sectionRoutes: Record<Section, string> = {
    'settings': '/settings',
    'security': '/security',
    'sessions': '/sessions',
    'app-passwords': '/app-passwords',
    'comms': '/comms',
    'repo': '/repo',
    'controllers': '/controllers',

    'invite-codes': '/invite-codes',
    'did-document': '/did-document',
    'admin': '/admin',
  }

  function selectSection(section: Section) {
    navigate(sectionRoutes[section] as typeof routes.dashboard)
  }

  function goBack() {
    navigate(routes.dashboard)
  }

  interface NavItem {
    id: Section
    label: string
    show: boolean
    highlight?: 'admin' | 'migrated' | 'did-web'
  }

  const navItems = $derived<NavItem[]>([
    { id: 'settings', label: $_('dashboard.navSettings'), show: session?.accountKind !== 'migrated' },
    { id: 'security', label: $_('dashboard.navSecurity'), show: true },
    { id: 'sessions', label: $_('dashboard.navSessions'), show: true },
    { id: 'app-passwords', label: $_('dashboard.navAppPasswords'), show: session?.accountKind !== 'migrated' },
    { id: 'comms', label: $_('dashboard.navComms'), show: session?.accountKind !== 'migrated' },
    { id: 'repo', label: $_('dashboard.navRepo'), show: session?.accountKind !== 'migrated' },
    { id: 'controllers', label: $_('dashboard.navDelegation'), show: session?.accountKind !== 'migrated' },

    { id: 'invite-codes', label: $_('dashboard.navInviteCodes'), show: inviteCodesEnabled && (session?.isAdmin ?? false) && session?.accountKind !== 'migrated' },
    { id: 'did-document', label: $_('dashboard.navDidDocument'), show: isPdsHostedDidWeb || session?.accountKind === 'migrated', highlight: session?.accountKind === 'migrated' ? 'migrated' : 'did-web' },
    { id: 'admin', label: $_('dashboard.navAdmin'), show: session?.isAdmin ?? false, highlight: 'admin' },
  ])

  const visibleNavItems = $derived(navItems.filter(item => item.show))

  function getSectionTitle(section: Section): string {
    const item = navItems.find(i => i.id === section)
    return item?.label ?? ''
  }
</script>

{#if session}
  <div class="dashboard" class:section-open={currentSection !== null}>
    <aside class="sidebar" class:hidden-mobile={currentSection !== null}>
      <header class="sidebar-header">
        <h1>{serverConfig.serverName || $_('dashboard.title')}</h1>
        <p class="sidebar-subtitle">{$_('dashboard.accountManager')}</p>
        <div class="account-section">
          <div class="account-dropdown">
            <button class="account-trigger" onclick={toggleDropdown} disabled={switching}>
              <span class="account-handle">@{session.handle}</span>
              <span class="dropdown-arrow">{dropdownOpen ? '▲' : '▼'}</span>
            </button>
            {#if dropdownOpen}
              <div class="dropdown-menu">
                {#if otherAccounts.length > 0}
                  <div class="dropdown-section">
                    <span class="dropdown-label">{$_('dashboard.switchAccount')}</span>
                    {#each otherAccounts as account}
                      <button type="button" class="dropdown-item" onclick={() => handleSwitchAccount(account.did)}>
                        @{account.handle}
                      </button>
                    {/each}
                  </div>
                  <div class="dropdown-divider"></div>
                {/if}
                <button type="button" class="dropdown-item" onclick={() => { dropdownOpen = false; navigate(routes.login) }}>
                  {$_('dashboard.addAnotherAccount')}
                </button>
                <div class="dropdown-divider"></div>
                <button type="button" class="dropdown-item logout-item" onclick={handleLogout}>
                  {$_('dashboard.signOut', { values: { handle: session.handle } })}
                </button>
              </div>
            {/if}
          </div>
          <div class="account-details">
            <span class="account-did">{session.did}</span>
            <div class="account-status">
              {#if session.isAdmin}
                <span class="badge admin">{$_('dashboard.admin')}</span>
              {/if}
              {#if session.contactKind === 'channel'}
                {#if session.preferredChannelVerified}
                  <span class="badge success">{$_('dashboard.verified')}</span>
                {:else}
                  <span class="badge warning">{$_('dashboard.unverified')}</span>
                {/if}
              {:else if session.contactKind === 'email'}
                {#if session.emailConfirmed}
                  <span class="badge success">{$_('dashboard.verified')}</span>
                {:else}
                  <span class="badge warning">{$_('dashboard.unverified')}</span>
                {/if}
              {/if}
            </div>
          </div>
        </div>
      </header>

      {#if session.accountKind === 'migrated'}
        <div class="status-banner migrated">
          <strong>{$_('dashboard.migratedTitle')}</strong>
          <p>{$_('dashboard.migratedMessage', { values: { pds: session.migratedToPds || 'another PDS' } })}</p>
        </div>
      {:else if session.accountKind === 'deactivated'}
        <div class="status-banner deactivated">
          <strong>{$_('dashboard.deactivatedTitle')}</strong>
          <p>{$_('dashboard.deactivatedMessage')}</p>
        </div>
      {/if}

      <nav class="nav-list">
        {#each visibleNavItems as item}
          <button
            type="button"
            class="nav-item"
            class:active={currentSection === item.id}
            class:highlight-admin={item.highlight === 'admin'}
            class:highlight-migrated={item.highlight === 'migrated'}
            class:highlight-did-web={item.highlight === 'did-web'}
            onclick={() => selectSection(item.id)}
          >
            <span class="nav-label">{item.label}</span>
            <span class="nav-chevron">›</span>
          </button>
        {/each}
      </nav>
    </aside>

    <main class="content" class:hidden-mobile={currentSection === null}>
      <header class="content-header">
        <button type="button" class="back-button" onclick={goBack}>
          <span class="back-arrow">‹</span>
          <span class="back-text">{serverConfig.serverName || $_('dashboard.title')}</span>
        </button>
        <h2>{currentSection ? getSectionTitle(currentSection) : ''}</h2>
      </header>

      <div class="content-body">
        {#if currentSection === 'settings'}
          <SettingsContent {session} />
        {:else if currentSection === 'security'}
          <SecurityContent {session} />
        {:else if currentSection === 'sessions'}
          <SessionsContent {session} />
        {:else if currentSection === 'app-passwords'}
          <AppPasswordsContent {session} />
        {:else if currentSection === 'comms'}
          <CommsContent {session} />
        {:else if currentSection === 'repo'}
          <RepoContent {session} />
        {:else if currentSection === 'controllers'}
          <ControllersContent {session} />

        {:else if currentSection === 'invite-codes'}
          <InviteCodesContent {session} />
        {:else if currentSection === 'did-document'}
          <DidDocumentContent {session} />
        {:else if currentSection === 'admin'}
          <AdminContent {session} />
        {/if}
      </div>
    </main>
  </div>
{:else if loading}
  <div class="dashboard loading-state">
    <aside class="sidebar">
      <div class="skeleton-header"></div>
      <nav class="nav-list">
        {#each Array(8) as _}
          <div class="skeleton-nav-item"></div>
        {/each}
      </nav>
    </aside>
    <main class="content">
      <div class="skeleton-content"></div>
    </main>
  </div>
{/if}
