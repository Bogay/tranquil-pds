<script lang="ts">
  import type { Snippet } from 'svelte'

  interface ProgressItem {
    label: string
    completed: boolean
    active?: boolean
  }

  interface Props {
    title: string
    description: string
    items: ProgressItem[]
    statusText: string
    progressBar?: { current: number; total: number }
    children?: Snippet
  }

  let { title, description, items, statusText, progressBar, children }: Props = $props()
</script>

<div class="step-content">
  <h2>{title}</h2>
  <p>{description}</p>

  <div class="progress-section">
    {#each items as item}
      <div class="progress-item" class:completed={item.completed} class:active={item.active}>
        <span class="icon">{item.completed ? '✓' : '○'}</span>
        <span>{item.label}</span>
      </div>
    {/each}
  </div>

  {#if progressBar && progressBar.total > 0}
    <div class="progress-bar">
      <div class="progress-fill" style="width: {(progressBar.current / progressBar.total) * 100}%"></div>
    </div>
  {/if}

  <p class="status-text">{statusText}</p>

  {#if children}
    {@render children()}
  {/if}
</div>
