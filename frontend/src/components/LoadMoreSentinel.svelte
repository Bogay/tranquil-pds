<script lang="ts">
  import { _ } from '../lib/i18n'

  interface Props {
    hasMore: boolean
    loading: boolean
    onLoadMore: () => void
    rootMargin?: string
  }

  let { hasMore, loading, onLoadMore, rootMargin = '200px' }: Props = $props()
  let sentinel = $state<HTMLDivElement | null>(null)

  $effect(() => {
    if (!sentinel || !hasMore) return
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && hasMore && !loading) {
          onLoadMore()
        }
      },
      { rootMargin }
    )
    observer.observe(sentinel)
    return () => observer.disconnect()
  })
</script>

{#if hasMore}
  <div bind:this={sentinel} class="load-more-sentinel">
    {#if loading}
      <span class="loading-indicator">{$_('common.loading')}</span>
    {/if}
  </div>
{/if}
