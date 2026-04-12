<script lang="ts" module>
  const EXAMPLE_HANDLES = [
    "nel.pet",
    "oyster.cafe",
    "llaama.bsky.social",
    "debugman.wizardry.systems",
    "nonbinary.computer",
    "mary.my.id",
    "olaren.dev",
  ] as const;

  export function getRandomHandle(): string {
    return EXAMPLE_HANDLES[Math.floor(Math.random() * EXAMPLE_HANDLES.length)];
  }
</script>

<script lang="ts">
  let handle = $state(getRandomHandle());
</script>

@{handle}
