<script lang="ts">
  import { onMount } from 'svelte'
  import { api, ApiError } from '../../lib/api'
  import { _ } from '../../lib/i18n'
  import { toast } from '../../lib/toast.svelte'
  import type { Session } from '../../lib/types/api'
  import {
    type TotpSetupState,
    idleState,
    qrState,
    verifyState,
    backupState,
    goBackToQr,
    finish,
    type TotpQr,
  } from '../../lib/types/totp-state'

  interface Props {
    session: Session
    onStatusChanged?: (enabled: boolean, hasBackupCodes: boolean) => void
  }

  let { session, onStatusChanged }: Props = $props()

  let totpEnabled = $state(false)
  let hasBackupCodes = $state(false)
  let totpSetup = $state<TotpSetupState>(idleState)
  let verifyCodeRaw = $state('')
  let verifyCode = $derived(verifyCodeRaw.replace(/\s/g, ''))
  let verifyLoading = $state(false)

  let disablePassword = $state('')
  let disableCode = $state('')
  let disableLoading = $state(false)
  let showDisableForm = $state(false)

  let regenPassword = $state('')
  let regenCode = $state('')
  let regenLoading = $state(false)
  let showRegenForm = $state(false)

  onMount(async () => {
    await loadTotpStatus()
  })

  async function loadTotpStatus() {
    try {
      const status = await api.getTotpStatus(session.accessJwt)
      totpEnabled = status.enabled
      hasBackupCodes = status.hasBackupCodes
      onStatusChanged?.(totpEnabled, hasBackupCodes)
    } catch {
      toast.error($_('security.failedToLoadTotpStatus'))
    }
  }

  async function handleStartTotpSetup() {
    verifyLoading = true
    try {
      const result = await api.createTotpSecret(session.accessJwt)
      totpSetup = qrState(result.qrBase64, result.uri)
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Failed to generate TOTP secret')
    } finally {
      verifyLoading = false
    }
  }

  async function handleVerifyTotp(e: Event) {
    e.preventDefault()
    if (!verifyCode || totpSetup.step !== 'verify') return
    verifyLoading = true
    try {
      const result = await api.enableTotp(session.accessJwt, verifyCode)
      totpSetup = backupState(totpSetup, result.backupCodes)
      totpEnabled = true
      hasBackupCodes = true
      verifyCodeRaw = ''
      onStatusChanged?.(true, true)
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : 'Invalid code')
    } finally {
      verifyLoading = false
    }
  }

  function handleFinishSetup() {
    if (totpSetup.step !== 'backup') return
    totpSetup = finish(totpSetup)
    toast.success($_('security.totpEnabledSuccess'))
  }

  function copyBackupCodes() {
    if (totpSetup.step !== 'backup') return
    navigator.clipboard.writeText(totpSetup.backupCodes.join('\n'))
    toast.success($_('security.backupCodesCopied'))
  }

  async function handleDisableTotp(e: Event) {
    e.preventDefault()
    if (!disablePassword || !disableCode) return
    disableLoading = true
    try {
      await api.disableTotp(session.accessJwt, disablePassword, disableCode)
      totpEnabled = false
      hasBackupCodes = false
      showDisableForm = false
      disablePassword = ''
      disableCode = ''
      toast.success($_('security.totpDisabledSuccess'))
      onStatusChanged?.(false, false)
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('security.failedToDisableTotp'))
    } finally {
      disableLoading = false
    }
  }

  async function handleRegenerateBackupCodes(e: Event) {
    e.preventDefault()
    if (!regenPassword || !regenCode) return
    regenLoading = true
    try {
      const result = await api.regenerateBackupCodes(session.accessJwt, regenPassword, regenCode)
      const dummyVerify = verifyState(qrState('', ''))
      totpSetup = backupState(dummyVerify, result.backupCodes)
      showRegenForm = false
      regenPassword = ''
      regenCode = ''
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : $_('security.failedToRegenerateBackupCodes'))
    } finally {
      regenLoading = false
    }
  }
</script>

<section>
  <h3>{$_('security.totp')}</h3>

  {#if totpSetup.step === 'idle'}
    {#if totpEnabled}
      <div class="status success">{$_('security.totpEnabled')}</div>

      {#if !showDisableForm && !showRegenForm}
        <div class="totp-actions">
          <button type="button" class="secondary" onclick={() => showRegenForm = true}>
            {$_('security.regenerateBackupCodes')}
          </button>
          <button type="button" class="danger-outline" onclick={() => showDisableForm = true}>
            {$_('security.disableTotp')}
          </button>
        </div>
      {/if}

      {#if showRegenForm}
        <form class="inline-form" onsubmit={handleRegenerateBackupCodes}>
          <h4>{$_('security.regenerateBackupCodes')}</h4>
          <p class="warning-text">{$_('security.regenerateConfirm')}</p>
          <div>
            <label for="regen-password">{$_('security.password')}</label>
            <input
              id="regen-password"
              type="password"
              bind:value={regenPassword}
              placeholder={$_('security.enterPassword')}
              disabled={regenLoading}
              required
            />
          </div>
          <div>
            <label for="regen-code">{$_('security.totpCode')}</label>
            <input
              id="regen-code"
              type="text"
              bind:value={regenCode}
              placeholder={$_('security.totpCodePlaceholder')}
              disabled={regenLoading}
              required
              maxlength="6"
              inputmode="numeric"
            />
          </div>
          <div class="actions">
            <button type="button" class="secondary" onclick={() => { showRegenForm = false; regenPassword = ''; regenCode = '' }}>
              {$_('common.cancel')}
            </button>
            <button type="submit" disabled={regenLoading || !regenPassword || regenCode.length !== 6}>
              {regenLoading ? $_('security.regenerating') : $_('security.regenerateBackupCodes')}
            </button>
          </div>
        </form>
      {/if}

      {#if showDisableForm}
        <form class="inline-form danger-form" onsubmit={handleDisableTotp}>
          <h4>{$_('security.disableTotp')}</h4>
          <p class="warning-text">{$_('security.disableTotpWarning')}</p>
          <div>
            <label for="disable-password">{$_('security.password')}</label>
            <input
              id="disable-password"
              type="password"
              bind:value={disablePassword}
              placeholder={$_('security.enterPassword')}
              disabled={disableLoading}
              required
            />
          </div>
          <div>
            <label for="disable-code">{$_('security.totpCode')}</label>
            <input
              id="disable-code"
              type="text"
              bind:value={disableCode}
              placeholder={$_('security.totpCodePlaceholder')}
              disabled={disableLoading}
              required
              maxlength="6"
              inputmode="numeric"
            />
          </div>
          <div class="actions">
            <button type="button" class="secondary" onclick={() => { showDisableForm = false; disablePassword = ''; disableCode = '' }}>
              {$_('common.cancel')}
            </button>
            <button type="submit" class="danger" disabled={disableLoading || !disablePassword || disableCode.length !== 6}>
              {disableLoading ? $_('security.disabling') : $_('security.disableTotp')}
            </button>
          </div>
        </form>
      {/if}
    {:else}
      <div class="status warning">{$_('security.totpDisabled')}</div>
      <button onclick={handleStartTotpSetup} disabled={verifyLoading}>
        {$_('security.enableTotp')}
      </button>
    {/if}
  {:else if totpSetup.step === 'qr'}
    {@const qrData = totpSetup as TotpQr}
    <div class="setup-step">
      <p>{$_('security.totpSetupInstructions')}</p>
      <div class="qr-container">
        <img src="data:image/png;base64,{qrData.qrBase64}" alt="TOTP QR Code" class="qr-code" />
      </div>
      <details class="manual-entry">
        <summary>{$_('security.cantScan')}</summary>
        <code class="secret-code">{qrData.totpUri.split('secret=')[1]?.split('&')[0] || ''}</code>
      </details>
      <button onclick={() => totpSetup = verifyState(qrData)}>{$_('security.next')}</button>
    </div>
  {:else if totpSetup.step === 'verify'}
    {@const verifyData = totpSetup}
    <div class="setup-step">
      <p>{$_('security.totpCodePlaceholder')}</p>
      <form onsubmit={handleVerifyTotp}>
        <input type="text" bind:value={verifyCodeRaw} placeholder="000000" class="code-input" inputmode="numeric" disabled={verifyLoading} />
        <div class="actions">
          <button type="button" class="secondary" onclick={() => totpSetup = goBackToQr(verifyData)}>{$_('common.back')}</button>
          <button type="submit" disabled={verifyLoading || verifyCode.length !== 6}>{$_('security.verifyAndEnable')}</button>
        </div>
      </form>
    </div>
  {:else if totpSetup.step === 'backup'}
    <div class="setup-step">
      <h4>{$_('security.backupCodes')}</h4>
      <p class="warning-text">{$_('security.backupCodesDescription')}</p>
      <div class="backup-codes">
        {#each totpSetup.backupCodes as code}
          <code class="backup-code">{code}</code>
        {/each}
      </div>
      <div class="actions">
        <button type="button" class="secondary" onclick={copyBackupCodes}>{$_('security.copyToClipboard')}</button>
        <button onclick={handleFinishSetup}>{$_('security.savedMyCodes')}</button>
      </div>
    </div>
  {/if}
</section>
