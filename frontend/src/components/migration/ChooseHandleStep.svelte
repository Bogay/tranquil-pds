<script lang="ts">
  import type { AuthMethod, ServerDescription } from '../../lib/migration/types'
  import { _ } from '../../lib/i18n'

  interface Props {
    handleInput: string
    selectedDomain: string
    handleAvailable: boolean | null
    checkingHandle: boolean
    email: string
    password: string
    authMethod: AuthMethod
    inviteCode: string
    serverInfo: ServerDescription | null
    migratingFromLabel: string
    migratingFromValue: string
    loading?: boolean
    onHandleChange: (handle: string) => void
    onDomainChange: (domain: string) => void
    onCheckHandle: () => void
    onEmailChange: (email: string) => void
    onPasswordChange: (password: string) => void
    onAuthMethodChange: (method: AuthMethod) => void
    onInviteCodeChange: (code: string) => void
    onBack: () => void
    onContinue: () => void
  }

  let {
    handleInput,
    selectedDomain,
    handleAvailable,
    checkingHandle,
    email,
    password,
    authMethod,
    inviteCode,
    serverInfo,
    migratingFromLabel,
    migratingFromValue,
    loading = false,
    onHandleChange,
    onDomainChange,
    onCheckHandle,
    onEmailChange,
    onPasswordChange,
    onAuthMethodChange,
    onInviteCodeChange,
    onBack,
    onContinue,
  }: Props = $props()

  const canContinue = $derived(
    handleInput.trim() &&
    email &&
    (authMethod === 'passkey' || password) &&
    handleAvailable !== false
  )
</script>

<div class="step-content">
  <h2>{$_('migration.inbound.chooseHandle.title')}</h2>
  <p>{$_('migration.inbound.chooseHandle.desc')}</p>

  <div class="current-info">
    <span class="label">{migratingFromLabel}:</span>
    <span class="value">{migratingFromValue}</span>
  </div>

  <div class="field">
    <label for="new-handle">{$_('migration.inbound.chooseHandle.newHandle')}</label>
    <div class="handle-input-group">
      <input
        id="new-handle"
        type="text"
        placeholder="username"
        value={handleInput}
        oninput={(e) => onHandleChange((e.target as HTMLInputElement).value)}
        onblur={onCheckHandle}
      />
      {#if serverInfo && serverInfo.availableUserDomains.length > 0 && !handleInput.includes('.')}
        <select value={selectedDomain} onchange={(e) => onDomainChange((e.target as HTMLSelectElement).value)}>
          {#each serverInfo.availableUserDomains as domain}
            <option value={domain}>.{domain}</option>
          {/each}
        </select>
      {/if}
    </div>

    {#if checkingHandle}
      <p class="hint">{$_('migration.inbound.chooseHandle.checkingAvailability')}</p>
    {:else if handleAvailable === true}
      <p class="hint" style="color: var(--success-text)">{$_('migration.inbound.chooseHandle.handleAvailable')}</p>
    {:else if handleAvailable === false}
      <p class="hint error">{$_('migration.inbound.chooseHandle.handleTaken')}</p>
    {:else}
      <p class="hint">{$_('migration.inbound.chooseHandle.handleHint')}</p>
    {/if}
  </div>

  <div class="field">
    <label for="email">{$_('migration.inbound.chooseHandle.email')}</label>
    <input
      id="email"
      type="email"
      placeholder="you@example.com"
      value={email}
      oninput={(e) => onEmailChange((e.target as HTMLInputElement).value)}
      required
    />
  </div>

  <div class="field">
    <label>{$_('migration.inbound.chooseHandle.authMethod')}</label>
    <div class="auth-method-options">
      <label class="auth-option" class:selected={authMethod === 'password'}>
        <input
          type="radio"
          name="auth-method"
          value="password"
          checked={authMethod === 'password'}
          onchange={() => onAuthMethodChange('password')}
        />
        <div class="auth-option-content">
          <strong>{$_('migration.inbound.chooseHandle.authPassword')}</strong>
          <span>{$_('migration.inbound.chooseHandle.authPasswordDesc')}</span>
        </div>
      </label>
      <label class="auth-option" class:selected={authMethod === 'passkey'}>
        <input
          type="radio"
          name="auth-method"
          value="passkey"
          checked={authMethod === 'passkey'}
          onchange={() => onAuthMethodChange('passkey')}
        />
        <div class="auth-option-content">
          <strong>{$_('migration.inbound.chooseHandle.authPasskey')}</strong>
          <span>{$_('migration.inbound.chooseHandle.authPasskeyDesc')}</span>
        </div>
      </label>
    </div>
  </div>

  {#if authMethod === 'password'}
    <div class="field">
      <label for="new-password">{$_('migration.inbound.chooseHandle.password')}</label>
      <input
        id="new-password"
        type="password"
        placeholder="Password for your new account"
        value={password}
        oninput={(e) => onPasswordChange((e.target as HTMLInputElement).value)}
        required
        minlength={8}
      />
      <p class="hint">{$_('migration.inbound.chooseHandle.passwordHint')}</p>
    </div>
  {:else}
    <div class="info-box">
      <p>{$_('migration.inbound.chooseHandle.passkeyInfo')}</p>
    </div>
  {/if}

  {#if serverInfo?.inviteCodeRequired}
    <div class="field">
      <label for="invite">{$_('migration.inbound.chooseHandle.inviteCode')}</label>
      <input
        id="invite"
        type="text"
        placeholder="Enter invite code"
        value={inviteCode}
        oninput={(e) => onInviteCodeChange((e.target as HTMLInputElement).value)}
        required
      />
    </div>
  {/if}

  <div class="button-row">
    <button class="ghost" onclick={onBack} disabled={loading}>{$_('migration.inbound.common.back')}</button>
    <button disabled={!canContinue || loading} onclick={onContinue}>
      {$_('migration.inbound.common.continue')}
    </button>
  </div>
</div>
