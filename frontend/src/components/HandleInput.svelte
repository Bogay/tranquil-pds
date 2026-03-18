<script lang="ts">
  interface Props {
    value: string
    domains: string[]
    selectedDomain: string
    disabled?: boolean
    placeholder?: string
    id?: string
    autocomplete?: HTMLInputElement['autocomplete']
    checkAvailability?: (fullHandle: string) => Promise<boolean>
    available?: boolean | null
    checking?: boolean
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
    checkAvailability,
    available = $bindable<boolean | null>(null),
    checking = $bindable(false),
    onInput,
    onDomainChange,
  }: Props = $props()

  const showDomainSelect = $derived(domains.length > 1 && !value.includes('.'))

  let checkTimeout: ReturnType<typeof setTimeout> | null = null

  $effect(() => {
    void value
    void selectedDomain
    if (!checkAvailability) return
    if (checkTimeout) clearTimeout(checkTimeout)
    available = null
    if (value.trim().length >= 3 && !value.includes('.')) {
      checkTimeout = setTimeout(() => runCheck(), 400)
    }
  })

  async function runCheck() {
    if (!checkAvailability) return
    const fullHandle = value.includes('.')
      ? value.trim()
      : `${value.trim()}.${selectedDomain}`
    checking = true
    try {
      available = await checkAvailability(fullHandle)
    } catch {
      available = null
    } finally {
      checking = false
    }
  }
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
