<script lang="ts">
  import { onMount } from 'svelte'
  import { getValidToken } from '../../lib/auth.svelte'
  import { api, ApiError } from '../../lib/api'
  import { _ } from '../../lib/i18n'
  import { toast } from '../../lib/toast.svelte'
  import type { Session } from '../../lib/types/api'

  interface Props {
    session: Session
    passkeyCount: number
    onPasswordChanged?: (hasPassword: boolean) => void
    onReauthRequired: (methods: string[], retryAction: () => Promise<void>) => void
  }

  let { session, passkeyCount, onPasswordChanged, onReauthRequired }: Props = $props()

  let hasPassword = $state(true)
  let loading = $state(true)

  let showChangePasswordForm = $state(false)
  let currentPassword = $state('')
  let newPassword = $state('')
  let confirmNewPassword = $state('')
  let changePasswordLoading = $state(false)

  let showSetPasswordForm = $state(false)
  let setNewPassword = $state('')
  let setConfirmPassword = $state('')
  let setPasswordLoading = $state(false)

  let showRemovePasswordForm = $state(false)
  let removePasswordLoading = $state(false)

  onMount(async () => {
    await loadPasswordStatus()
  })

  async function loadPasswordStatus() {
    loading = true
    try {
      const status = await api.getPasswordStatus(session.accessJwt)
      hasPassword = status.hasPassword
      onPasswordChanged?.(hasPassword)
    } catch {
      hasPassword = true
    } finally {
      loading = false
    }
  }

  function handleReauthError(e: unknown, fallback: string, retryAction: () => Promise<void>) {
    if (e instanceof ApiError) {
      if (e.error === 'ReauthRequired') {
        onReauthRequired(e.reauthMethods || ['password'], retryAction)
      } else {
        toast.error(e.message)
      }
    } else {
      toast.error(fallback)
    }
  }

  async function handleChangePassword(e: Event) {
    e.preventDefault()
    if (!currentPassword || !newPassword || !confirmNewPassword) return
    if (newPassword !== confirmNewPassword) {
      toast.error($_('security.passwordsDoNotMatch'))
      return
    }
    if (newPassword.length < 8) {
      toast.error($_('security.passwordTooShort'))
      return
    }
    changePasswordLoading = true
    try {
      await api.changePassword(session.accessJwt, currentPassword, newPassword)
      toast.success($_('security.passwordChanged'))
      currentPassword = ''
      newPassword = ''
      confirmNewPassword = ''
      showChangePasswordForm = false
    } catch (e) {
      handleReauthError(e, $_('security.failedToChangePassword'), () => handleChangePassword(new Event('submit')))
    } finally {
      changePasswordLoading = false
    }
  }

  async function handleSetPassword(e: Event) {
    e.preventDefault()
    if (!setNewPassword || !setConfirmPassword) return
    if (setNewPassword !== setConfirmPassword) {
      toast.error($_('security.passwordsDoNotMatch'))
      return
    }
    if (setNewPassword.length < 8) {
      toast.error($_('security.passwordTooShort'))
      return
    }
    setPasswordLoading = true
    try {
      await api.setPassword(session.accessJwt, setNewPassword)
      hasPassword = true
      toast.success($_('security.passwordSet'))
      setNewPassword = ''
      setConfirmPassword = ''
      showSetPasswordForm = false
      onPasswordChanged?.(true)
    } catch (e) {
      handleReauthError(e, $_('security.failedToSetPassword'), () => handleSetPassword(new Event('submit')))
    } finally {
      setPasswordLoading = false
    }
  }

  async function handleRemovePassword() {
    removePasswordLoading = true
    try {
      const token = await getValidToken()
      if (!token) {
        toast.error($_('security.sessionExpired'))
        return
      }
      await api.removePassword(token)
      hasPassword = false
      showRemovePasswordForm = false
      toast.success($_('security.passwordRemoved'))
      onPasswordChanged?.(false)
    } catch (e) {
      handleReauthError(e, $_('security.failedToRemovePassword'), handleRemovePassword)
    } finally {
      removePasswordLoading = false
    }
  }
</script>

<section>
  <h3>{$_('security.password')}</h3>
  {#if !loading}
    {#if hasPassword}
      <div class="status success">{$_('security.passwordStatus')}</div>

      {#if !showChangePasswordForm && !showRemovePasswordForm}
        <div class="password-actions">
          <button type="button" onclick={() => showChangePasswordForm = true}>
            {$_('security.changePassword')}
          </button>
          {#if passkeyCount > 0}
            <button type="button" class="danger-outline" onclick={() => showRemovePasswordForm = true}>
              {$_('security.removePassword')}
            </button>
          {/if}
        </div>
      {/if}

      {#if showChangePasswordForm}
        <form class="inline-form" onsubmit={handleChangePassword}>
          <h4>{$_('security.changePassword')}</h4>
          <div>
            <label for="current-password">{$_('security.currentPassword')}</label>
            <input
              id="current-password"
              type="password"
              bind:value={currentPassword}
              placeholder={$_('security.currentPasswordPlaceholder')}
              disabled={changePasswordLoading}
              required
            />
          </div>
          <div>
            <label for="new-password">{$_('security.newPassword')}</label>
            <input
              id="new-password"
              type="password"
              bind:value={newPassword}
              placeholder={$_('security.newPasswordPlaceholder')}
              disabled={changePasswordLoading}
              required
              minlength="8"
            />
          </div>
          <div>
            <label for="confirm-password">{$_('security.confirmPassword')}</label>
            <input
              id="confirm-password"
              type="password"
              bind:value={confirmNewPassword}
              placeholder={$_('security.confirmPasswordPlaceholder')}
              disabled={changePasswordLoading}
              required
              minlength="8"
            />
          </div>
          <div class="actions">
            <button type="button" class="secondary" onclick={() => { showChangePasswordForm = false; currentPassword = ''; newPassword = ''; confirmNewPassword = '' }}>
              {$_('common.cancel')}
            </button>
            <button type="submit" disabled={changePasswordLoading || !currentPassword || !newPassword || !confirmNewPassword}>
              {changePasswordLoading ? $_('security.changing') : $_('security.changePassword')}
            </button>
          </div>
        </form>
      {/if}

      {#if showRemovePasswordForm}
        <div class="remove-password-form">
          <p class="warning-text">{$_('security.removePasswordWarning')}</p>
          <div class="actions">
            <button type="button" class="ghost sm" onclick={() => showRemovePasswordForm = false}>
              {$_('common.cancel')}
            </button>
            <button type="button" class="danger sm" onclick={handleRemovePassword} disabled={removePasswordLoading}>
              {removePasswordLoading ? $_('security.removing') : $_('security.removePassword')}
            </button>
          </div>
        </div>
      {/if}
    {:else}
      <div class="status info">{$_('security.noPassword')}</div>

      {#if !showSetPasswordForm}
        <button type="button" onclick={() => showSetPasswordForm = true}>
          {$_('security.setPassword')}
        </button>
      {:else}
        <form class="inline-form" onsubmit={handleSetPassword}>
          <h4>{$_('security.setPassword')}</h4>
          <div>
            <label for="set-new-password">{$_('security.newPassword')}</label>
            <input
              id="set-new-password"
              type="password"
              bind:value={setNewPassword}
              placeholder={$_('security.newPasswordPlaceholder')}
              disabled={setPasswordLoading}
              required
              minlength="8"
            />
          </div>
          <div>
            <label for="set-confirm-password">{$_('security.confirmPassword')}</label>
            <input
              id="set-confirm-password"
              type="password"
              bind:value={setConfirmPassword}
              placeholder={$_('security.confirmPasswordPlaceholder')}
              disabled={setPasswordLoading}
              required
              minlength="8"
            />
          </div>
          <div class="actions">
            <button type="button" class="secondary" onclick={() => { showSetPasswordForm = false; setNewPassword = ''; setConfirmPassword = '' }}>
              {$_('common.cancel')}
            </button>
            <button type="submit" disabled={setPasswordLoading || !setNewPassword || !setConfirmPassword}>
              {setPasswordLoading ? $_('security.setting') : $_('security.setPassword')}
            </button>
          </div>
        </form>
      {/if}
    {/if}
  {/if}
</section>
