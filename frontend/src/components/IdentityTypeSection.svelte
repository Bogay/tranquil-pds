<script lang="ts">
  import { _ } from '../lib/i18n'

  interface Props {
    didType: 'plc' | 'web' | 'web-external'
    externalDid: string
    disabled: boolean
    selfHostedDidWebEnabled: boolean
    defaultDomain: string
    onDidTypeChange: (value: 'plc' | 'web' | 'web-external') => void
    onExternalDidChange: (value: string) => void
  }

  let {
    didType,
    externalDid,
    disabled,
    selfHostedDidWebEnabled,
    defaultDomain,
    onDidTypeChange,
    onExternalDidChange,
  }: Props = $props()

  function extractDomain(did: string): string {
    return did.replace(/^did:web:/, '').split(':')[0] || 'yourdomain.com'
  }
</script>

<fieldset class="identity-section">
  <legend>{$_('registerPasskey.identityType')}</legend>
  <div class="radio-group">
    <label class="radio-label">
      <input type="radio" name="didType" value="plc" checked={didType === 'plc'} onchange={() => onDidTypeChange('plc')} {disabled} />
      <span class="radio-content">
        <strong>{$_('registerPasskey.didPlcRecommended')}</strong>
        <span class="radio-hint">{$_('registerPasskey.didPlcHint')}</span>
      </span>
    </label>
    <label class="radio-label" class:disabled={!selfHostedDidWebEnabled}>
      <input type="radio" name="didType" value="web" checked={didType === 'web'} onchange={() => onDidTypeChange('web')} disabled={disabled || !selfHostedDidWebEnabled} />
      <span class="radio-content">
        <strong>{$_('registerPasskey.didWeb')}</strong>
        {#if !selfHostedDidWebEnabled}
          <span class="radio-hint disabled-hint">{$_('registerPasskey.didWebDisabledHint')}</span>
        {:else}
          <span class="radio-hint">{$_('registerPasskey.didWebHint')}</span>
        {/if}
      </span>
    </label>
    <label class="radio-label">
      <input type="radio" name="didType" value="web-external" checked={didType === 'web-external'} onchange={() => onDidTypeChange('web-external')} {disabled} />
      <span class="radio-content">
        <strong>{$_('registerPasskey.didWebBYOD')}</strong>
        <span class="radio-hint">{$_('registerPasskey.didWebBYODHint')}</span>
      </span>
    </label>
  </div>
</fieldset>

{#if didType === 'web'}
  <div class="warning-box">
    <strong>{$_('registerPasskey.didWebWarningTitle')}</strong>
    <ul>
      <li><strong>{$_('registerPasskey.didWebWarning1')}</strong> {@html $_('registerPasskey.didWebWarning1Detail', { values: { did: `<code>did:web:yourhandle.${defaultDomain}</code>` } })}</li>
      <li><strong>{$_('registerPasskey.didWebWarning2')}</strong> {$_('registerPasskey.didWebWarning2Detail')}</li>
      <li><strong>{$_('registerPasskey.didWebWarning3')}</strong> {$_('registerPasskey.didWebWarning3Detail')}</li>
      <li><strong>{$_('registerPasskey.didWebWarning4')}</strong> {$_('registerPasskey.didWebWarning4Detail')}</li>
    </ul>
  </div>
{/if}

{#if didType === 'web-external'}
  <div>
    <label for="external-did">{$_('registerPasskey.externalDid')}</label>
    <input id="external-did" type="text" value={externalDid} oninput={(e) => onExternalDidChange(e.currentTarget.value)} placeholder={$_('registerPasskey.externalDidPlaceholder')} {disabled} required />
    <p class="hint">{$_('registerPasskey.externalDidHint')} <code>https://{externalDid ? extractDomain(externalDid) : 'yourdomain.com'}/.well-known/did.json</code></p>
  </div>
{/if}
