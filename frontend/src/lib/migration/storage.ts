import type {
  MigrationDirection,
  MigrationState,
  StoredMigrationState,
} from "./types";

const STORAGE_KEY = "tranquil_migration_state";
const MAX_AGE_MS = 24 * 60 * 60 * 1000;

export function saveMigrationState(state: MigrationState): void {
  const storedState: StoredMigrationState = {
    version: 1,
    direction: state.direction,
    step: state.direction === "inbound" ? state.step : state.step,
    startedAt: new Date().toISOString(),
    sourcePdsUrl: state.direction === "inbound"
      ? state.sourcePdsUrl
      : window.location.origin,
    targetPdsUrl: state.direction === "inbound"
      ? window.location.origin
      : state.targetPdsUrl,
    sourceDid: state.direction === "inbound" ? state.sourceDid : "",
    sourceHandle: state.direction === "inbound" ? state.sourceHandle : "",
    targetHandle: state.targetHandle,
    targetEmail: state.targetEmail,
    progress: {
      repoExported: state.progress.repoExported,
      repoImported: state.progress.repoImported,
      blobsTotal: state.progress.blobsTotal,
      blobsMigrated: state.progress.blobsMigrated,
      prefsMigrated: state.progress.prefsMigrated,
      plcSigned: state.progress.plcSigned,
    },
    lastError: state.error ?? undefined,
    lastErrorStep: state.error ? state.step : undefined,
  };

  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(storedState));
  } catch {
  }
}

export function loadMigrationState(): StoredMigrationState | null {
  try {
    const stored = sessionStorage.getItem(STORAGE_KEY);
    if (!stored) return null;

    const state = JSON.parse(stored) as StoredMigrationState;

    if (state.version !== 1) return null;

    const startedAt = new Date(state.startedAt).getTime();
    if (Date.now() - startedAt > MAX_AGE_MS) {
      clearMigrationState();
      return null;
    }

    return state;
  } catch {
    return null;
  }
}

export function clearMigrationState(): void {
  try {
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
  }
}

export function hasPendingMigration(): boolean {
  return loadMigrationState() !== null;
}

export function getResumeInfo(): {
  direction: MigrationDirection;
  sourceHandle: string;
  targetHandle: string;
  sourcePdsUrl: string;
  targetPdsUrl: string;
  progressSummary: string;
  step: string;
} | null {
  const state = loadMigrationState();
  if (!state) return null;

  const progressParts: string[] = [];
  if (state.progress.repoExported) progressParts.push("repo exported");
  if (state.progress.repoImported) progressParts.push("repo imported");
  if (state.progress.blobsMigrated > 0) {
    progressParts.push(
      `${state.progress.blobsMigrated}/${state.progress.blobsTotal} blobs`,
    );
  }
  if (state.progress.prefsMigrated) progressParts.push("preferences migrated");
  if (state.progress.plcSigned) progressParts.push("PLC signed");

  return {
    direction: state.direction,
    sourceHandle: state.sourceHandle,
    targetHandle: state.targetHandle,
    sourcePdsUrl: state.sourcePdsUrl,
    targetPdsUrl: state.targetPdsUrl,
    progressSummary: progressParts.length > 0
      ? progressParts.join(", ")
      : "just started",
    step: state.step,
  };
}

export function updateProgress(
  updates: Partial<StoredMigrationState["progress"]>,
): void {
  const state = loadMigrationState();
  if (!state) return;

  state.progress = { ...state.progress, ...updates };
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
  }
}

export function updateStep(step: string): void {
  const state = loadMigrationState();
  if (!state) return;

  state.step = step;
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
  }
}

export function setError(error: string, step: string): void {
  const state = loadMigrationState();
  if (!state) return;

  state.lastError = error;
  state.lastErrorStep = step;
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
  }
}
