<script lang="ts">
  interface Props {
    value: string
    domains: string[]
    selectedDomain: string
    disabled?: boolean
    placeholder?: string
    id?: string
    autocomplete?: HTMLInputElement['autocomplete']
    onInput: (value: string) => void
    onDomainChange: (domain: string) => void
  }

  let {
    value,
    domains,
    selectedDomain,
    disabled = false,
    placeholder = 'username',
    id = 'handle',
    autocomplete = 'off',
    onInput,
    onDomainChange,
  }: Props = $props()

  const showDomainSelect = $derived(domains.length > 1 && !value.includes('.'))
</script>

<div class="handle-input-group">
  <input
    {id}
    type="text"
    value={value}
    {placeholder}
    {disabled}
    autocomplete={autocomplete}
    required
    oninput={(e) => onInput((e.target as HTMLInputElement).value)}
  />
  {#if showDomainSelect}
    <select value={selectedDomain} onchange={(e) => onDomainChange((e.target as HTMLSelectElement).value)}>
      {#each domains as domain}
        <option value={domain}>.{domain}</option>
      {/each}
    </select>
  {:else if domains.length === 1 && !value.includes('.')}
    <span class="domain-suffix">.{domains[0]}</span>
  {/if}
</div>

<style>
  .handle-input-group {
    display: flex;
    gap: var(--space-2);
    align-items: center;
  }

  .handle-input-group input {
    flex: 1;
  }

  .handle-input-group select {
    width: auto;
  }

  .domain-suffix {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    white-space: nowrap;
  }
</style>
