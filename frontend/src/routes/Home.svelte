<script lang="ts">
  import { _ } from '../lib/i18n'
  import { getAuthState } from '../lib/auth.svelte'
  const auth = getAuthState()
</script>
<div class="home">
  <header class="hero">
    <h1>Tranquil PDS</h1>
    <p class="tagline">A Personal Data Server for the AT Protocol</p>
  </header>
  <section>
    <h2>What is a PDS?</h2>
    <p>
      Bluesky runs on a federated protocol called AT Protocol. Your account lives on a PDS,
      a server that stores your posts, profile, follows, and cryptographic keys. Bluesky hosts
      one for you at bsky.social, but you can run your own. Self-hosting means you control your
      data; you're not dependent on any company's servers, and your account + data is actually yours.
    </p>
  </section>
  <section>
    <h2>What's different about Tranquil?</h2>
    <p>
      This software isn't an afterthought by a company with limited resources.
      It is a superset of the reference PDS, including:
    </p>
    <ul>
      <li>Passkeys and 2FA (WebAuthn/FIDO2, TOTP, backup codes, trusted devices)</li>
      <li>did:web support (PDS-hosted subdomains or bring-your-own)</li>
      <li>Multi-channel notifications (email, discord, telegram, signal)</li>
      <li>Granular OAuth scopes with a consent UI</li>
      <li>Built-in web UI for account management, repo browsing, and admin</li>
    </ul>
    <p>
      Full compatibility with Bluesky's reference PDS: same endpoints, same behavior,
      same client compatibility. Everything works.
    </p>
  </section>
  <div class="cta">
    {#if auth.session}
      <a href="#/dashboard" class="btn">@{auth.session.handle}</a>
    {:else}
      <a href="#/login" class="btn">{$_('login.button')}</a>
      <a href="#/register" class="btn secondary">{$_('login.createAccount')}</a>
    {/if}
  </div>
  <footer>
    <a href="https://tangled.org/lewis.moe/bspds-sandbox" target="_blank" rel="noopener">Source code</a>
  </footer>
</div>
<style>
  .home {
    max-width: var(--width-md);
    margin: 0 auto;
    padding: var(--space-7);
  }

  .hero {
    text-align: center;
    margin-bottom: var(--space-8);
    padding-top: var(--space-7);
  }

  .hero h1 {
    font-size: var(--text-4xl);
    margin-bottom: var(--space-3);
  }

  .tagline {
    color: var(--text-secondary);
    font-size: var(--text-xl);
  }

  section {
    margin-bottom: var(--space-7);
  }

  h2 {
    margin-bottom: var(--space-4);
  }

  p {
    color: var(--text-secondary);
    margin-bottom: var(--space-4);
  }

  ul {
    color: var(--text-secondary);
    margin: 0 0 var(--space-4) 0;
    padding-left: var(--space-6);
    line-height: var(--leading-relaxed);
  }

  li {
    margin-bottom: var(--space-2);
  }

  .cta {
    display: flex;
    gap: var(--space-4);
    justify-content: center;
    margin: var(--space-8) 0;
  }

  .btn {
    display: inline-block;
    padding: var(--space-4) var(--space-7);
    border-radius: var(--radius-md);
    font-size: var(--text-base);
    font-weight: var(--font-medium);
    text-decoration: none;
    transition: background var(--transition-normal), border-color var(--transition-normal);
    background: var(--accent);
    color: var(--text-inverse);
  }

  .btn:hover {
    background: var(--accent-hover);
    text-decoration: none;
  }

  .btn.secondary {
    background: transparent;
    color: var(--accent);
    border: 1px solid var(--accent);
  }

  .btn.secondary:hover {
    background: var(--accent);
    color: var(--text-inverse);
  }

  footer {
    text-align: center;
    padding-top: var(--space-7);
    border-top: 1px solid var(--border-color);
  }

  footer a {
    color: var(--text-muted);
    font-size: var(--text-sm);
  }

  footer a:hover {
    color: var(--accent);
  }
</style>
