<script lang="ts">
  import { getCurrentPath } from './lib/router.svelte'
  import { initAuth, getAuthState } from './lib/auth.svelte'
  import Login from './routes/Login.svelte'
  import Register from './routes/Register.svelte'
  import ResetPassword from './routes/ResetPassword.svelte'
  import Dashboard from './routes/Dashboard.svelte'
  import AppPasswords from './routes/AppPasswords.svelte'
  import InviteCodes from './routes/InviteCodes.svelte'
  import Settings from './routes/Settings.svelte'
  import Sessions from './routes/Sessions.svelte'
  import Notifications from './routes/Notifications.svelte'
  import RepoExplorer from './routes/RepoExplorer.svelte'
  import Admin from './routes/Admin.svelte'

  const auth = getAuthState()

  $effect(() => {
    initAuth()
  })

  function getComponent(path: string) {
    switch (path) {
      case '/login':
        return Login
      case '/register':
        return Register
      case '/reset-password':
        return ResetPassword
      case '/dashboard':
        return Dashboard
      case '/app-passwords':
        return AppPasswords
      case '/invite-codes':
        return InviteCodes
      case '/settings':
        return Settings
      case '/sessions':
        return Sessions
      case '/notifications':
        return Notifications
      case '/repo':
        return RepoExplorer
      case '/admin':
        return Admin
      default:
        return auth.session ? Dashboard : Login
    }
  }

  let currentPath = $derived(getCurrentPath())
  let CurrentComponent = $derived(getComponent(currentPath))
</script>

<main>
  {#if auth.loading}
    <div class="loading">
      <p>Loading...</p>
    </div>
  {:else}
    <CurrentComponent />
  {/if}
</main>

<style>
  :global(:root) {
    --bg-primary: #fafafa;
    --bg-secondary: #f9f9f9;
    --bg-card: #ffffff;
    --bg-input: #ffffff;
    --bg-input-disabled: #f5f5f5;
    --text-primary: #333333;
    --text-secondary: #666666;
    --text-muted: #999999;
    --border-color: #dddddd;
    --border-color-light: #cccccc;
    --accent: #0066cc;
    --accent-hover: #0052a3;
    --success-bg: #dfd;
    --success-border: #8c8;
    --success-text: #060;
    --error-bg: #fee;
    --error-border: #fcc;
    --error-text: #c00;
    --warning-bg: #ffd;
    --warning-text: #660;
  }

  @media (prefers-color-scheme: dark) {
    :global(:root) {
      --bg-primary: #1a1a1a;
      --bg-secondary: #242424;
      --bg-card: #2a2a2a;
      --bg-input: #333333;
      --bg-input-disabled: #2a2a2a;
      --text-primary: #e0e0e0;
      --text-secondary: #a0a0a0;
      --text-muted: #707070;
      --border-color: #404040;
      --border-color-light: #505050;
      --accent: #4da6ff;
      --accent-hover: #7abbff;
      --success-bg: #1a3d1a;
      --success-border: #2d5a2d;
      --success-text: #7bc67b;
      --error-bg: #3d1a1a;
      --error-border: #5a2d2d;
      --error-text: #ff7b7b;
      --warning-bg: #3d3d1a;
      --warning-text: #c6c67b;
    }
  }

  :global(body) {
    margin: 0;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.5;
    color: var(--text-primary);
    background: var(--bg-primary);
  }

  :global(*) {
    box-sizing: border-box;
  }

  main {
    min-height: 100vh;
    background: var(--bg-primary);
  }

  .loading {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    color: var(--text-secondary);
  }
</style>
