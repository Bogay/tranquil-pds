<script lang="ts">
  import { Button, Card, Input, Message, Page, Section } from '../components/ui'
  import Skeleton from '../components/Skeleton.svelte'
  import { toast } from '../lib/toast.svelte'
  import { getServerConfigState } from '../lib/serverConfig.svelte'
  import { _, locale, getSupportedLocales, localeNames, type SupportedLocale } from '../lib/i18n'

  let inputValue = $state('')
  let inputError = $state('')
  let inputDisabled = $state(false)

  const serverConfig = getServerConfigState()

  const LIGHT_ACCENT_DEFAULT = '#1a1d1d'
  const DARK_ACCENT_DEFAULT = '#e6e8e8'
  const LIGHT_SECONDARY_DEFAULT = '#1a1d1d'
  const DARK_SECONDARY_DEFAULT = '#e6e8e8'

  let accentLight = $state(LIGHT_ACCENT_DEFAULT)
  let accentDark = $state(DARK_ACCENT_DEFAULT)
  let secondaryLight = $state(LIGHT_SECONDARY_DEFAULT)
  let secondaryDark = $state(DARK_SECONDARY_DEFAULT)

  $effect(() => {
    accentLight = serverConfig.primaryColor || LIGHT_ACCENT_DEFAULT
    accentDark = serverConfig.primaryColorDark || DARK_ACCENT_DEFAULT
    secondaryLight = serverConfig.secondaryColor || LIGHT_SECONDARY_DEFAULT
    secondaryDark = serverConfig.secondaryColorDark || DARK_SECONDARY_DEFAULT
  })

  const isDark = $derived(
    typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches
  )

  function applyColor(prop: string, value: string): void {
    document.documentElement.style.setProperty(prop, value)
  }

  $effect(() => {
    applyColor('--accent', isDark ? accentDark : accentLight)
  })

  $effect(() => {
    applyColor('--secondary', isDark ? secondaryDark : secondaryLight)
  })
</script>

<Page title="UI Test" size="lg">
  <Section title="Theme">
    <div class="form-row">
      <div class="field">
        <label for="accent-light">Accent (light)</label>
        <div class="color-pair">
          <input type="color" bind:value={accentLight} />
          <input id="accent-light" type="text" class="mono" bind:value={accentLight} />
        </div>
      </div>
      <div class="field">
        <label for="accent-dark">Accent (dark)</label>
        <div class="color-pair">
          <input type="color" bind:value={accentDark} />
          <input id="accent-dark" type="text" class="mono" bind:value={accentDark} />
        </div>
      </div>
      <div class="field">
        <label for="secondary-light">Secondary (light)</label>
        <div class="color-pair">
          <input type="color" bind:value={secondaryLight} />
          <input id="secondary-light" type="text" class="mono" bind:value={secondaryLight} />
        </div>
      </div>
      <div class="field">
        <label for="secondary-dark">Secondary (dark)</label>
        <div class="color-pair">
          <input type="color" bind:value={secondaryDark} />
          <input id="secondary-dark" type="text" class="mono" bind:value={secondaryDark} />
        </div>
      </div>
      <div class="field">
        <label for="locale-picker">Locale</label>
        <select id="locale-picker" value={$locale} onchange={(e) => locale.set(e.currentTarget.value)}>
          {#each getSupportedLocales() as loc}
            <option value={loc}>{localeNames[loc]} ({loc})</option>
          {/each}
        </select>
      </div>
    </div>
  </Section>

  <Section title="Typography">
    <p style="font-size: var(--text-4xl)">4xl (2.5rem)</p>
    <p style="font-size: var(--text-3xl)">3xl (2rem)</p>
    <p style="font-size: var(--text-2xl)">2xl (1.5rem)</p>
    <p style="font-size: var(--text-xl)">xl (1.25rem)</p>
    <p style="font-size: var(--text-lg)">lg (1.125rem)</p>
    <p style="font-size: var(--text-base)">base (1rem)</p>
    <p style="font-size: var(--text-sm)">sm (0.875rem)</p>
    <p style="font-size: var(--text-xs)">xs (0.75rem)</p>
    <hr />
    <p style="font-weight: var(--font-normal)">Normal (400)</p>
    <p style="font-weight: var(--font-medium)">Medium (500)</p>
    <p style="font-weight: var(--font-semibold)">Semibold (600)</p>
    <p style="font-weight: var(--font-bold)">Bold (700)</p>
    <hr />
    <code>Monospace text</code>
    <pre>Pre block
  indented</pre>
  </Section>

  <Section title="Colors">
    <div class="form-row">
      <div>
        <h4>Backgrounds</h4>
        <div class="swatch" style="background: var(--bg-primary)">bg-primary</div>
        <div class="swatch" style="background: var(--bg-secondary)">bg-secondary</div>
        <div class="swatch" style="background: var(--bg-tertiary)">bg-tertiary</div>
        <div class="swatch" style="background: var(--bg-card)">bg-card</div>
        <div class="swatch" style="background: var(--bg-input)">bg-input</div>
      </div>
      <div>
        <h4>Text</h4>
        <p style="color: var(--text-primary)">text-primary</p>
        <p style="color: var(--text-secondary)">text-secondary</p>
        <p style="color: var(--text-muted)">text-muted</p>
        <div class="swatch" style="background: var(--accent); color: var(--text-inverse)">text-inverse</div>
      </div>
      <div>
        <h4>Accent</h4>
        <div class="swatch" style="background: var(--accent); color: var(--text-inverse)">accent</div>
        <div class="swatch" style="background: var(--accent-hover); color: var(--text-inverse)">accent-hover</div>
        <div class="swatch" style="background: var(--accent-muted)">accent-muted</div>
      </div>
      <div>
        <h4>Status</h4>
        <div class="swatch" style="background: var(--success-bg); color: var(--success-text)">success</div>
        <div class="swatch" style="background: var(--error-bg); color: var(--error-text)">error</div>
        <div class="swatch" style="background: var(--warning-bg); color: var(--warning-text)">warning</div>
      </div>
    </div>
  </Section>

  <Section title="Spacing">
    <div class="spacing-row">
      {#each [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] as i}
        <div class="spacing-item">
          <div class="spacing-box" style="width: var(--space-{i}); height: var(--space-{i})"></div>
          <span class="text-xs text-muted">--space-{i}</span>
        </div>
      {/each}
    </div>
  </Section>

  <Section title="Buttons">
    <p>
      <Button variant="primary">{$_('common.save')}</Button>
      <Button variant="secondary">{$_('common.cancel')}</Button>
      <Button variant="tertiary">{$_('common.back')}</Button>
      <Button variant="danger">{$_('common.delete')}</Button>
      <Button variant="ghost">{$_('common.refresh')}</Button>
    </p>
    <p class="mt-5">
      <Button size="sm">{$_('common.verify')}</Button>
      <Button size="md">{$_('common.continue')}</Button>
      <Button size="lg">{$_('common.signIn')}</Button>
    </p>
    <p class="mt-5">
      <Button disabled>{$_('common.save')}</Button>
      <Button loading>{$_('common.saving')}</Button>
      <Button variant="secondary" disabled>{$_('common.cancel')}</Button>
      <Button variant="danger" loading>{$_('common.delete')}</Button>
    </p>
    <p class="mt-5">
      <button class="danger-outline">{$_('common.revoke')}</button>
      <button class="link">{$_('login.forgotPassword')}</button>
      <button class="sm">{$_('common.done')}</button>
    </p>
    <div class="mt-5">
      <Button fullWidth>{$_('common.signIn')}</Button>
    </div>
  </Section>

  <Section title="Inputs">
    <div class="form-row">
      <div class="field">
        <Input label={$_('settings.newEmail')} placeholder={$_('settings.newEmailPlaceholder')} bind:value={inputValue} />
      </div>
      <div class="field">
        <Input label={$_('security.passkeyName')} placeholder={$_('security.passkeyNamePlaceholder')} hint={$_('appPasswords.createdMessage')} />
      </div>
    </div>
    <div class="form-row">
      <div class="field">
        <Input label={$_('verification.codeLabel')} placeholder={$_('verification.codePlaceholder')} error={$_('common.error')} bind:value={inputError} />
      </div>
      <div class="field">
        <Input label={$_('settings.yourDomain')} placeholder={$_('settings.yourDomainPlaceholder')} disabled bind:value={inputDisabled} />
      </div>
    </div>
    <div class="form-row mt-5">
      <div class="field">
        <label for="demo-select">{$_('settings.language')}</label>
        <select id="demo-select">
          {#each getSupportedLocales() as loc}
            <option>{localeNames[loc]}</option>
          {/each}
        </select>
      </div>
      <div class="field">
        <label for="demo-textarea">{$_('settings.exportData')}</label>
        <textarea id="demo-textarea" rows="3"></textarea>
      </div>
    </div>
  </Section>

  <Section title="Cards">
    <Card>
      <h4>{$_('settings.exportData')}</h4>
      <p class="text-secondary text-sm">{$_('settings.downloadRepo')}</p>
    </Card>
    <div class="mt-4">
      <Card variant="interactive">
        <h4>{$_('sessions.session')}</h4>
        <p class="text-secondary text-sm">{$_('sessions.current')}</p>
      </Card>
    </div>
    <div class="mt-4">
      <Card variant="danger">
        <h4>{$_('security.removePassword')}</h4>
        <p class="text-secondary text-sm">{$_('security.removePasswordWarning')}</p>
      </Card>
    </div>
  </Section>

  <Section title="Sections">
    <Section title="Default section" description="With a description">
      <p>Section content</p>
    </Section>
    <div class="mt-5">
      <Section title="Danger section" variant="danger">
        <p>Destructive operations</p>
      </Section>
    </div>
  </Section>

  <Section title="Messages">
    <Message variant="success">{$_('appPasswords.deleted')}</Message>
    <div class="mt-4"><Message variant="error">{$_('appPasswords.createFailed')}</Message></div>
    <div class="mt-4"><Message variant="warning">{$_('security.legacyLoginWarning')}</Message></div>
    <div class="mt-4"><Message variant="info">{$_('appPasswords.createdMessage')}</Message></div>
  </Section>

  <Section title="Badges">
    <p>
      <span class="badge success">{$_('inviteCodes.available')}</span>
      <span class="badge warning">{$_('inviteCodes.spent')}</span>
      <span class="badge error">{$_('inviteCodes.disabled')}</span>
      <span class="badge accent">{$_('sessions.current')}</span>
    </p>
  </Section>

  <Section title="Toasts">
    <p>
      <Button variant="secondary" onclick={() => toast.success($_('appPasswords.deleted'))}>{$_('appPasswords.deleted')}</Button>
      <Button variant="secondary" onclick={() => toast.error($_('appPasswords.createFailed'))}>{$_('appPasswords.createFailed')}</Button>
      <Button variant="secondary" onclick={() => toast.warning($_('security.disableTotpWarning'))}>{$_('security.disableTotpWarning')}</Button>
      <Button variant="secondary" onclick={() => toast.info($_('appPasswords.createdMessage'))}>{$_('appPasswords.createdMessage')}</Button>
    </p>
  </Section>

  <Section title="Skeleton loading">
    <Skeleton variant="line" size="full" />
    <Skeleton variant="line" size="medium" />
    <Skeleton variant="line" size="short" />
    <Skeleton variant="line" size="tiny" />
    <div class="mt-5">
      <Skeleton variant="line" lines={3} />
    </div>
    <div class="mt-5">
      <Skeleton variant="card" lines={2} />
    </div>
  </Section>

  <Section title="Fieldset">
    <fieldset>
      <legend>Account settings</legend>
      <div class="field">
        <label for="demo-display-name">Display name</label>
        <input id="demo-display-name" type="text" placeholder="Name" />
      </div>
    </fieldset>
  </Section>

  <Section title="Form layouts">
    <h4>Two column</h4>
    <div class="form-row">
      <div class="field">
        <label for="demo-fname">First name</label>
        <input id="demo-fname" type="text" />
      </div>
      <div class="field">
        <label for="demo-lname">Last name</label>
        <input id="demo-lname" type="text" />
      </div>
    </div>
    <h4 class="mt-5">Three column</h4>
    <div class="form-row thirds">
      <div class="field">
        <label for="demo-city">City</label>
        <input id="demo-city" type="text" />
      </div>
      <div class="field">
        <label for="demo-state">State</label>
        <input id="demo-state" type="text" />
      </div>
      <div class="field">
        <label for="demo-zip">ZIP</label>
        <input id="demo-zip" type="text" />
      </div>
    </div>
    <h4 class="mt-5">Full width in row</h4>
    <div class="form-row">
      <div class="field">
        <label for="demo-handle">Handle</label>
        <input id="demo-handle" type="text" />
      </div>
      <div class="field">
        <label for="demo-domain">Domain</label>
        <select id="demo-domain"><option>example.com</option></select>
      </div>
      <div class="field full-width">
        <label for="demo-bio">Bio</label>
        <textarea id="demo-bio" rows="2"></textarea>
      </div>
    </div>
  </Section>

  <Section title="Hints">
    <div class="field">
      <label for="demo-hint">With hints</label>
      <input id="demo-hint" type="text" />
      <span class="hint">Default hint</span>
    </div>
    <div class="field">
      <input type="text" />
      <span class="hint warning">Warning hint</span>
    </div>
    <div class="field">
      <input type="text" />
      <span class="hint error">Error hint</span>
    </div>
    <div class="field">
      <input type="text" />
      <span class="hint success">Success hint</span>
    </div>
  </Section>

  <Section title="Radio group">
    <div class="radio-group">
      <label class="radio-label">
        <input type="radio" name="demo-radio" checked />
        <div class="radio-content">
          <span>Option A</span>
          <span class="radio-hint">First choice</span>
        </div>
      </label>
      <label class="radio-label">
        <input type="radio" name="demo-radio" />
        <div class="radio-content">
          <span>Option B</span>
          <span class="radio-hint">Second choice</span>
        </div>
      </label>
      <label class="radio-label disabled">
        <input type="radio" name="demo-radio" disabled />
        <div class="radio-content">
          <span>Option C</span>
          <span class="radio-hint disabled-hint">Unavailable</span>
        </div>
      </label>
    </div>
  </Section>

  <Section title="Checkbox">
    <label class="checkbox-label">
      <input type="checkbox" />
      <span>{$_('appPasswords.acknowledgeLabel')}</span>
    </label>
  </Section>

  <Section title="Warning box">
    <div class="warning-box">
      <strong>{$_('appPasswords.saveWarningTitle')}</strong>
      <p>{$_('appPasswords.saveWarningMessage')}</p>
    </div>
  </Section>

  <Section title="Split layout">
    <div class="split-layout">
      <Card>
        <h4>Main content</h4>
        <p class="text-secondary">Primary area with a form or data</p>
        <div class="field mt-5">
          <label for="demo-example">Example field</label>
          <input id="demo-example" type="text" placeholder="Value" />
        </div>
      </Card>
      <div class="info-panel">
        <h3>Sidebar</h3>
        <p>Supplementary information placed alongside the main content area.</p>
        <ul class="info-list">
          <li>Supports DID methods: did:web, did:plc</li>
          <li>Maximum blob size: 10MB</li>
          <li>Rate limit: 100 requests per minute</li>
        </ul>
      </div>
    </div>
  </Section>

  <Section title="Composite: card with form">
    <Card>
      <h4>{$_('appPasswords.create')}</h4>
      <p class="text-secondary text-sm mb-5">{$_('appPasswords.permissions')}</p>
      <div class="field">
        <Input label={$_('appPasswords.name')} placeholder={$_('appPasswords.namePlaceholder')} />
      </div>
      <div class="mt-5" style="display: flex; gap: var(--space-3); justify-content: flex-end">
        <Button variant="tertiary">{$_('common.cancel')}</Button>
        <Button>{$_('appPasswords.create')}</Button>
      </div>
    </Card>
  </Section>

  <Section title="Composite: section with actions">
    <Section title={$_('security.passkeys')}>
      <div style="display: flex; justify-content: space-between; align-items: center">
        <div>
          <strong>{$_('security.totp')}</strong>
          <p class="text-sm text-secondary">{$_('security.totpEnabled')}</p>
        </div>
        <Button variant="secondary" size="sm">{$_('security.disableTotp')}</Button>
      </div>
      <hr />
      <div style="display: flex; justify-content: space-between; align-items: center">
        <div>
          <strong>{$_('security.passkeys')}</strong>
          <p class="text-sm text-secondary">{$_('security.noPasskeys')}</p>
        </div>
        <Button variant="secondary" size="sm">{$_('security.addPasskey')}</Button>
      </div>
    </Section>
  </Section>

  <Section title="Composite: error state">
    <div class="error-container">
      <div class="error-icon">!</div>
      <h2>Authorization failed</h2>
      <p>The requested scope exceeds the granted permissions.</p>
      <Button variant="secondary">Back</Button>
    </div>
  </Section>

  <Section title="Item list">
    <div class="item">
      <div class="item-info">
        <strong>Primary passkey</strong>
        <span class="text-sm text-secondary">Created 2024-01-15</span>
      </div>
      <div class="item-actions">
        <button class="sm">Rename</button>
        <button class="sm danger-outline">Revoke</button>
      </div>
    </div>
    <div class="item">
      <div class="item-info">
        <strong>Backup passkey</strong>
        <span class="text-sm text-secondary">Created 2024-03-20</span>
      </div>
      <div class="item-actions">
        <button class="sm">Rename</button>
        <button class="sm danger-outline">Revoke</button>
      </div>
    </div>
    <div class="item">
      <div class="item-info">
        <strong>Work laptop</strong>
        <span class="text-sm text-secondary">Created 2024-06-01</span>
      </div>
      <div class="item-actions">
        <button class="sm danger-outline">Revoke</button>
      </div>
    </div>
  </Section>

  <Section title="Definition list">
    <dl class="definition-list">
      <dt>Handle</dt>
      <dd>@alice.example.com</dd>
      <dt>DID</dt>
      <dd class="mono">did:web:alice.example.com</dd>
      <dt>Email</dt>
      <dd>alice@example.com</dd>
      <dt>Created</dt>
      <dd>2024-01-15</dd>
      <dt>Status</dt>
      <dd><span class="badge success">Verified</span></dd>
    </dl>
  </Section>

  <Section title="Tabs">
    <div class="tabs">
      <button class="tab active">PDS handle</button>
      <button class="tab">Custom domain</button>
    </div>
    <p class="text-secondary">Tab content appears here</p>
  </Section>

  <Section title="Inline form">
    <div class="inline-form">
      <h4>Change password</h4>
      <div class="field">
        <label for="demo-current-pw">Current password</label>
        <input id="demo-current-pw" type="password" />
      </div>
      <div class="field">
        <label for="demo-new-pw">New password</label>
        <input id="demo-new-pw" type="password" />
      </div>
      <div style="display: flex; gap: var(--space-3); justify-content: flex-end">
        <Button variant="secondary">Cancel</Button>
        <Button>Save</Button>
      </div>
    </div>
  </Section>
</Page>
