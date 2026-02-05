<script lang="ts">
  import type { AuthMethod, HandlePreservation, ServerDescription } from '../../lib/migration/types'
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
    sourceHandle: string
    sourceDid: string
    handlePreservation: HandlePreservation
    existingHandleVerified: boolean
    verifyingExistingHandle?: boolean
    existingHandleError?: string | null
    onHandleChange: (handle: string) => void
    onDomainChange: (domain: string) => void
    onCheckHandle: () => void
    onEmailChange: (email: string) => void
    onPasswordChange: (password: string) => void
    onAuthMethodChange: (method: AuthMethod) => void
    onInviteCodeChange: (code: string) => void
    onHandlePreservationChange?: (preservation: HandlePreservation) => void
    onVerifyExistingHandle?: () => void
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
    sourceHandle,
    sourceDid,
    handlePreservation,
    existingHandleVerified,
    verifyingExistingHandle = false,
    existingHandleError = null,
    onHandleChange,
    onDomainChange,
    onCheckHandle,
    onEmailChange,
    onPasswordChange,
    onAuthMethodChange,
    onInviteCodeChange,
    onHandlePreservationChange,
    onVerifyExistingHandle,
    onBack,
    onContinue,
  }: Props = $props()

  const handleTooShort = $derived(handleInput.trim().length > 0 && handleInput.trim().length < 3)

  const isExternalHandle = $derived(
    serverInfo != null &&
    sourceHandle.includes('.') &&
    !serverInfo.availableUserDomains.some(d => sourceHandle.endsWith(`.${d}`))
  )

  const canContinue = $derived(
    email &&
    (authMethod === 'passkey' || password) &&
    (
      (handlePreservation === 'existing' && existingHandleVerified) ||
      (handlePreservation === 'new' && handleInput.trim().length >= 3 && handleAvailable !== false)
    )
  )
</script>

<div class="step-content">
  <h2>{$_('migration.inbound.chooseHandle.title')}</h2>
  <p>{$_('migration.inbound.chooseHandle.desc')}</p>

  <div class="current-info">
    <span class="label">{migratingFromLabel}:</span>
    <span class="value">{migratingFromValue}</span>
  </div>

  {#if isExternalHandle}
    <div class="field">
      <span class="field-label">{$_('migration.inbound.chooseHandle.handleChoice')}</span>
      <div class="handle-choice-options">
        <label class="handle-choice-option" class:selected={handlePreservation === 'existing'}>
          <input
            type="radio"
            name="handle-preservation"
            value="existing"
            checked={handlePreservation === 'existing'}
            onchange={() => onHandlePreservationChange?.('existing')}
          />
          <div class="handle-choice-content">
            <strong>{$_('migration.inbound.chooseHandle.keepExisting')}</strong>
            <span class="handle-preview">@{sourceHandle}</span>
          </div>
        </label>
        <label class="handle-choice-option" class:selected={handlePreservation === 'new'}>
          <input
            type="radio"
            name="handle-preservation"
            value="new"
            checked={handlePreservation === 'new'}
            onchange={() => onHandlePreservationChange?.('new')}
          />
          <div class="handle-choice-content">
            <strong>{$_('migration.inbound.chooseHandle.createNew')}</strong>
          </div>
        </label>
      </div>
    </div>
  {/if}

  {#if handlePreservation === 'existing' && isExternalHandle}
    <div class="field">
      <span class="field-label">{$_('migration.inbound.chooseHandle.existingHandle')}</span>
      <div class="existing-handle-display">
        <span class="handle-value">@{sourceHandle}</span>
        {#if existingHandleVerified}
          <span class="verified-badge">{$_('migration.inbound.chooseHandle.verified')}</span>
        {/if}
      </div>

      {#if !existingHandleVerified}
        <div class="verification-instructions">
          <p class="instruction-header">{$_('migration.inbound.chooseHandle.verifyInstructions')}</p>
          <div class="verification-record">
            <code>_atproto.{sourceHandle} TXT "did={sourceDid}"</code>
          </div>
          <p class="instruction-or">{$_('migration.inbound.chooseHandle.or')}</p>
          <div class="verification-record">
            <code>https://{sourceHandle}/.well-known/atproto-did</code>
            <span class="record-content">{$_('migration.inbound.chooseHandle.returning')} <code>{sourceDid}</code></span>
          </div>
        </div>

        <button
          class="verify-btn"
          onclick={() => onVerifyExistingHandle?.()}
          disabled={verifyingExistingHandle}
        >
          {#if verifyingExistingHandle}
            {$_('migration.inbound.chooseHandle.verifying')}
          {:else if existingHandleError}
            {$_('migration.inbound.chooseHandle.checkAgain')}
          {:else}
            {$_('migration.inbound.chooseHandle.verifyOwnership')}
          {/if}
        </button>

        {#if existingHandleError}
          <p class="hint error">{existingHandleError}</p>
        {/if}
      {/if}
    </div>
  {:else}
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

      {#if handleTooShort}
        <p class="hint error">{$_('migration.inbound.chooseHandle.handleTooShort')}</p>
      {:else if checkingHandle}
        <p class="hint">{$_('migration.inbound.chooseHandle.checkingAvailability')}</p>
      {:else if handleAvailable === true}
        <p class="hint" style="color: var(--success-text)">{$_('migration.inbound.chooseHandle.handleAvailable')}</p>
      {:else if handleAvailable === false}
        <p class="hint error">{$_('migration.inbound.chooseHandle.handleTaken')}</p>
      {:else}
        <p class="hint">{$_('migration.inbound.chooseHandle.handleHint')}</p>
      {/if}
    </div>
  {/if}

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
    <span class="field-label">{$_('migration.inbound.chooseHandle.authMethod')}</span>
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

<style>
  .handle-choice-options {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .handle-choice-option {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-4);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    cursor: pointer;
    transition: border-color var(--transition-normal), background var(--transition-normal);
  }

  .handle-choice-option:hover {
    border-color: var(--accent);
  }

  .handle-choice-option.selected {
    border-color: var(--accent);
    background: var(--accent-muted);
  }

  .handle-choice-option input[type="radio"] {
    flex-shrink: 0;
    width: 18px;
    height: 18px;
    margin: 0;
  }

  .handle-choice-content {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .handle-preview {
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .existing-handle-display {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    padding: var(--space-4);
    background: var(--bg-secondary);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-4);
  }

  .handle-value {
    font-family: var(--font-mono);
    font-size: var(--text-base);
  }

  .verified-badge {
    font-size: var(--text-xs);
    padding: var(--space-1) var(--space-3);
    background: var(--success-bg);
    color: var(--success-text);
    border-radius: var(--radius-md);
  }

  .verification-instructions {
    background: var(--bg-secondary);
    padding: var(--space-5);
    border-radius: var(--radius-lg);
    margin-bottom: var(--space-4);
  }

  .instruction-header {
    margin: 0 0 var(--space-4) 0;
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .instruction-or {
    margin: var(--space-3) 0;
    font-size: var(--text-xs);
    color: var(--text-muted);
    text-align: center;
  }

  .verification-record {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .verification-record code {
    font-size: var(--text-sm);
    padding: var(--space-3);
    background: var(--bg-tertiary);
    border-radius: var(--radius-md);
    overflow-x: auto;
    word-break: break-all;
  }

  .record-content {
    font-size: var(--text-xs);
    color: var(--text-secondary);
    padding-left: var(--space-3);
  }

  .record-content code {
    padding: var(--space-1) var(--space-2);
    font-size: var(--text-xs);
  }

  .verify-btn {
    width: 100%;
  }
</style>
