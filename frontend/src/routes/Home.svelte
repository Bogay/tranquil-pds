<script lang="ts">
  import { onMount } from 'svelte'
  import { _ } from '../lib/i18n'
  import { getAuthState } from '../lib/auth.svelte'
  import { getServerConfigState } from '../lib/serverConfig.svelte'
  import { api } from '../lib/api'

  const auth = getAuthState()
  const serverConfig = getServerConfigState()
  const sourceUrl = 'https://tangled.org/lewis.moe/bspds-sandbox'

  let pdsHostname = $state<string | null>(null)
  let pdsVersion = $state<string | null>(null)
  let userCount = $state<number | null>(null)

  const heroWords = ['Bluesky', 'Tangled', 'Leaflet', 'ATProto']
  const wordSpacing: Record<string, string> = {
    'Bluesky': '0.01em',
    'Tangled': '0.02em',
    'Leaflet': '0.05em',
    'ATProto': '0',
  }
  let currentWordIndex = $state(0)
  let isTransitioning = $state(false)
  let currentWord = $derived(heroWords[currentWordIndex])
  let currentSpacing = $derived(wordSpacing[currentWord] || '0')

  onMount(() => {
    api.describeServer().then(info => {
      if (info.availableUserDomains?.length) {
        pdsHostname = info.availableUserDomains[0]
      }
      if (info.version) {
        pdsVersion = info.version
      }
    }).catch(() => {})

    const baseDuration = 2000
    let wordTimeout: ReturnType<typeof setTimeout>

    function cycleWord() {
      isTransitioning = true
      setTimeout(() => {
        currentWordIndex = (currentWordIndex + 1) % heroWords.length
        isTransitioning = false
        const duration = heroWords[currentWordIndex] === 'ATProto' ? baseDuration * 2 : baseDuration
        wordTimeout = setTimeout(cycleWord, duration)
      }, 100)
    }

    wordTimeout = setTimeout(cycleWord, baseDuration)

    api.listRepos(1000).then(data => {
      userCount = data.repos.length
    }).catch(() => {})

    const pattern = document.getElementById('dotPattern')
    if (!pattern) return

    const spacing = 32
    const cols = Math.ceil((window.innerWidth + 600) / spacing)
    const rows = Math.ceil((window.innerHeight + 100) / spacing)
    const dots: { el: HTMLElement; x: number; y: number }[] = []

    for (let y = 0; y < rows; y++) {
      for (let x = 0; x < cols; x++) {
        const dot = document.createElement('div')
        dot.className = 'dot'
        dot.style.left = (x * spacing) + 'px'
        dot.style.top = (y * spacing) + 'px'
        pattern.appendChild(dot)
        dots.push({ el: dot, x: x * spacing, y: y * spacing })
      }
    }

    let mouseX = -1000
    let mouseY = -1000

    const handleMouseMove = (e: MouseEvent) => {
      mouseX = e.clientX
      mouseY = e.clientY
    }

    document.addEventListener('mousemove', handleMouseMove)

    let animationId: number

    function updateDots() {
      const patternRect = pattern.getBoundingClientRect()
      dots.forEach(dot => {
        const dotX = patternRect.left + dot.x + 5
        const dotY = patternRect.top + dot.y + 5
        const dist = Math.hypot(mouseX - dotX, mouseY - dotY)
        const maxDist = 120
        const scale = Math.min(1, Math.max(0.1, dist / maxDist))
        dot.el.style.transform = `scale(${scale})`
      })
      animationId = requestAnimationFrame(updateDots)
    }
    updateDots()

    return () => {
      document.removeEventListener('mousemove', handleMouseMove)
      cancelAnimationFrame(animationId)
      clearTimeout(wordTimeout)
    }
  })
</script>

<div class="pattern-container">
  <div class="pattern" id="dotPattern"></div>
</div>
<div class="pattern-fade"></div>

<nav>
  <div class="nav-left">
    {#if serverConfig.hasLogo}
      <img src="/logo" alt="Logo" class="nav-logo" />
    {/if}
    {#if pdsHostname}
      <span class="hostname">{pdsHostname}</span>
      {#if userCount !== null}
        <span class="user-count">{userCount} {userCount === 1 ? 'user' : 'users'}</span>
      {/if}
    {:else}
      <span class="hostname placeholder">loading...</span>
    {/if}
  </div>
  <span class="nav-meta">{pdsVersion || ''}</span>
</nav>

<div class="home">
  <section class="hero">
    <h1>A home for your <span class="cycling-word-container"><span class="cycling-word" class:transitioning={isTransitioning} style="letter-spacing: {currentSpacing}">{currentWord}</span></span> account</h1>

    <p class="lede">Tranquil PDS is a Personal Data Server, the thing that stores your posts, profile, and keys. Bluesky runs one for you, but you can run your own.</p>

    <div class="actions">
      {#if auth.session}
        <a href="#/dashboard" class="btn primary">@{auth.session.handle}</a>
      {:else}
        <a href="#/register" class="btn primary">Join This Server</a>
        <a href={sourceUrl} class="btn secondary" target="_blank" rel="noopener">Run Your Own</a>
      {/if}
    </div>

    <blockquote>
      <p>"Nature does not hurry, yet everything is accomplished."</p>
      <cite>Lao Tzu</cite>
    </blockquote>
  </section>

  <section class="content">
    <h2>What you get</h2>

    <div class="features">
      <div class="feature">
        <h3>Real security</h3>
        <p>Sign in with passkeys, add two-factor authentication, set up backup codes, and mark devices you trust. Your account stays yours.</p>
      </div>

      <div class="feature">
        <h3>Your own identity</h3>
        <p>Use your own domain as your handle, or get a subdomain on ours. Either way, your identity moves with you if you ever leave.</p>
      </div>

      <div class="feature">
        <h3>Stay in the loop</h3>
        <p>Get important alerts where you actually see them: email, Discord, Telegram, or Signal.</p>
      </div>

      <div class="feature">
        <h3>You decide what apps can do</h3>
        <p>When an app asks for access, you'll see exactly what it wants in plain language. Grant what makes sense, deny what doesn't.</p>
      </div>
    </div>

    <h2>Everything in one place</h2>

    <p>Manage your profile, security settings, connected apps, and more from a clean dashboard. No command line or 3rd party apps required.</p>

    <h2>Works with everything</h2>

    <p>Use any ATProto app you already like. Tranquil PDS speaks the same language as Bluesky's servers, so all your favorite clients and tools just work.</p>

    <h2>Ready to try it?</h2>

    <p>Join this server, or grab the source and run your own. Either way, you can migrate an existing account over and your followers, posts, and identity come with you.</p>

    <div class="actions">
      {#if auth.session}
        <a href="#/dashboard" class="btn primary">@{auth.session.handle}</a>
      {:else}
        <a href="#/register" class="btn primary">Join This Server</a>
        <a href={sourceUrl} class="btn secondary" target="_blank" rel="noopener">View Source</a>
      {/if}
    </div>
  </section>

  <footer class="site-footer">
    <span>Made by people who don't take themselves too seriously</span>
    <span>Open Source: issues & PRs welcome</span>
  </footer>
</div>

<style>
  .pattern-container {
    position: fixed;
    top: -32px;
    left: -32px;
    right: -32px;
    bottom: -32px;
    pointer-events: none;
    z-index: 1;
    overflow: hidden;
  }

  .pattern {
    position: absolute;
    top: 0;
    left: 0;
    width: calc(100% + 500px);
    height: 100%;
    animation: drift 80s linear infinite;
  }

  .pattern :global(.dot) {
    position: absolute;
    width: 10px;
    height: 10px;
    background: rgba(0, 0, 0, 0.06);
    border-radius: 50%;
    transition: transform 0.04s linear;
  }

  @media (prefers-color-scheme: dark) {
    .pattern :global(.dot) {
      background: rgba(255, 255, 255, 0.1);
    }
  }

  .pattern-fade {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(135deg, transparent 50%, var(--bg-primary) 75%);
    pointer-events: none;
    z-index: 2;
  }

  @keyframes drift {
    0% { transform: translateX(-500px); }
    100% { transform: translateX(0); }
  }

  nav {
    position: fixed;
    top: 12px;
    left: 32px;
    right: 32px;
    background: var(--accent);
    padding: 10px 18px;
    z-index: 100;
    border-radius: var(--radius-xl);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .nav-left {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .nav-logo {
    height: 28px;
    width: auto;
    object-fit: contain;
    border-radius: var(--radius-sm);
  }

  .hostname {
    font-weight: var(--font-semibold);
    font-size: var(--text-base);
    letter-spacing: 0.08em;
    color: var(--text-inverse);
    text-transform: uppercase;
  }

  .hostname.placeholder {
    opacity: 0.4;
  }

  .user-count {
    font-size: var(--text-sm);
    color: var(--text-inverse);
    opacity: 0.85;
    padding: 4px 10px;
    background: rgba(255, 255, 255, 0.15);
    border-radius: var(--radius-md);
    white-space: nowrap;
  }

  @media (prefers-color-scheme: dark) {
    .user-count {
      background: rgba(0, 0, 0, 0.15);
    }
  }

  .nav-meta {
    font-size: var(--text-sm);
    color: var(--text-inverse);
    opacity: 0.6;
    letter-spacing: 0.05em;
  }

  .home {
    position: relative;
    z-index: 10;
    max-width: var(--width-xl);
    margin: 0 auto;
    padding: 72px 32px 32px;
  }

  .hero {
    padding: var(--space-7) 0 var(--space-8);
    border-bottom: 1px solid var(--border-color);
    margin-bottom: var(--space-8);
  }

  h1 {
    font-size: var(--text-4xl);
    font-weight: var(--font-semibold);
    line-height: var(--leading-tight);
    margin-bottom: var(--space-6);
    letter-spacing: -0.02em;
  }

  .cycling-word-container {
    display: inline-block;
    width: 3.9em;
    text-align: left;
  }

  .cycling-word {
    display: inline-block;
    transition: opacity 0.1s ease, transform 0.1s ease;
  }

  .cycling-word.transitioning {
    opacity: 0;
    transform: scale(0.95);
  }

  .lede {
    font-size: var(--text-xl);
    font-weight: var(--font-medium);
    color: var(--text-primary);
    line-height: var(--leading-relaxed);
    margin-bottom: 0;
  }

  .actions {
    display: flex;
    gap: var(--space-4);
    margin-top: var(--space-7);
  }

  .btn {
    font-size: var(--text-sm);
    font-weight: var(--font-medium);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding: var(--space-4) var(--space-6);
    border-radius: var(--radius-lg);
    text-decoration: none;
    transition: all var(--transition-normal);
    border: 1px solid transparent;
  }

  .btn.primary {
    background: var(--secondary);
    color: var(--text-inverse);
    border-color: var(--secondary);
  }

  .btn.primary:hover {
    background: var(--secondary-hover);
    border-color: var(--secondary-hover);
  }

  .btn.secondary {
    background: transparent;
    color: var(--text-primary);
    border-color: var(--border-color);
  }

  .btn.secondary:hover {
    background: var(--secondary-muted);
    border-color: var(--secondary);
    color: var(--secondary);
  }

  blockquote {
    margin: var(--space-8) 0 0 0;
    padding: var(--space-6);
    background: var(--accent-muted);
    border-left: 3px solid var(--accent);
    border-radius: 0 var(--radius-xl) var(--radius-xl) 0;
  }

  blockquote p {
    font-size: var(--text-lg);
    color: var(--text-primary);
    font-style: italic;
    margin-bottom: var(--space-3);
  }

  blockquote cite {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    font-style: normal;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .content h2 {
    font-size: var(--text-sm);
    font-weight: var(--font-bold);
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--accent-light);
    margin: var(--space-8) 0 var(--space-5);
  }

  .content h2:first-child {
    margin-top: 0;
  }

  .content > p {
    font-size: var(--text-base);
    color: var(--text-secondary);
    margin-bottom: var(--space-5);
    line-height: var(--leading-relaxed);
  }

  .features {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: var(--space-6);
    margin: var(--space-6) 0 var(--space-8);
  }

  .feature {
    padding: var(--space-5);
    background: var(--bg-secondary);
    border-radius: var(--radius-xl);
    border: 1px solid var(--border-color);
  }

  .feature h3 {
    font-size: var(--text-base);
    font-weight: var(--font-semibold);
    color: var(--text-primary);
    margin-bottom: var(--space-3);
  }

  .feature p {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin: 0;
    line-height: var(--leading-relaxed);
  }

  @media (max-width: 700px) {
    .features {
      grid-template-columns: 1fr;
    }

    h1 {
      font-size: var(--text-3xl);
    }

    .actions {
      flex-direction: column;
    }

    .btn {
      text-align: center;
    }

    .user-count,
    .nav-meta {
      display: none;
    }
  }

  .site-footer {
    margin-top: var(--space-9);
    padding-top: var(--space-7);
    display: flex;
    justify-content: space-between;
    font-size: var(--text-sm);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border-top: 1px solid var(--border-color);
  }
</style>
