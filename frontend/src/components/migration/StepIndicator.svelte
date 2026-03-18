<script lang="ts">
  interface Props {
    steps: string[]
    currentIndex: number
  }

  let { steps, currentIndex }: Props = $props()
</script>

<div class="step-indicator">
  {#each steps as _, i}
    <div class="step" class:active={i === currentIndex} class:completed={i < currentIndex}>
      <div class="step-dot">{i < currentIndex ? '✓' : i + 1}</div>
    </div>
    {#if i < steps.length - 1}
      <div class="step-line" class:completed={i < currentIndex}></div>
    {/if}
  {/each}
</div>
<div class="current-step-label">
  <strong>{steps[currentIndex]}</strong> · Step {currentIndex + 1} of {steps.length}
</div>
