<script lang="ts">
  import { _ } from '../../lib/i18n'

  interface Props {
    error: string | null
    onStartOver: () => void
  }

  let { error, onStartOver }: Props = $props()
</script>

<div class="step-content">
  <h2>{$_('migration.inbound.error.title')}</h2>
  <p>{$_('migration.inbound.error.desc')}</p>

  <div class="message error">
    {error || $_('migration.inbound.error.unknown')}
  </div>

  <div class="button-row">
    <button class="ghost" onclick={onStartOver}>{$_('migration.inbound.error.startOver')}</button>
  </div>
</div>
