import { beforeEach, describe, expect, it } from "vitest";
import {
  clearMigrationState,
  getResumeInfo,
  hasPendingMigration,
  loadMigrationState,
  saveMigrationState,
  setError,
  updateProgress,
  updateStep,
} from "../../lib/migration/storage.ts";
import type {
  InboundMigrationState,
  MigrationState,
} from "../../lib/migration/types.ts";

interface OutboundMigrationState {
  direction: "outbound";
  step: string;
  localDid: string;
  localHandle: string;
  targetPdsUrl: string;
  targetPdsDid: string;
  targetHandle: string;
  targetEmail: string;
  targetPassword: string;
  inviteCode: string;
  targetAccessToken: string | null;
  targetRefreshToken: string | null;
  serviceAuthToken: string | null;
  plcToken: string;
  progress: {
    repoExported: boolean;
    repoImported: boolean;
    blobsTotal: number;
    blobsMigrated: number;
    blobsFailed: string[];
    prefsMigrated: boolean;
    plcSigned: boolean;
    activated: boolean;
    deactivated: boolean;
    currentOperation: string;
  };
  error: string | null;
  targetServerInfo: unknown;
}

const STORAGE_KEY = "tranquil_migration_state";
const DPOP_KEY_STORAGE = "migration_dpop_key";

function createInboundState(
  overrides?: Partial<InboundMigrationState>,
): InboundMigrationState {
  return {
    direction: "inbound",
    step: "welcome",
    sourcePdsUrl: "https://bsky.social",
    sourceDid: "did:plc:abc123",
    sourceHandle: "alice.bsky.social",
    targetHandle: "alice.example.com",
    targetEmail: "alice@example.com",
    targetPassword: "password123",
    inviteCode: "",
    sourceAccessToken: null,
    sourceRefreshToken: null,
    serviceAuthToken: null,
    emailVerifyToken: "",
    plcToken: "",
    progress: {
      repoExported: false,
      repoImported: false,
      blobsTotal: 0,
      blobsMigrated: 0,
      blobsFailed: [],
      prefsMigrated: false,
      plcSigned: false,
      activated: false,
      deactivated: false,
      currentOperation: "",
    },
    error: null,
    targetVerificationMethod: null,
    authMethod: "password",
    passkeySetupToken: null,
    oauthCodeVerifier: null,
    localAccessToken: null,
    generatedAppPassword: null,
    generatedAppPasswordName: null,
    ...overrides,
  };
}

function createOutboundState(
  overrides?: Partial<OutboundMigrationState>,
): OutboundMigrationState {
  return {
    direction: "outbound",
    step: "welcome",
    localDid: "did:plc:xyz789",
    localHandle: "bob.example.com",
    targetPdsUrl: "https://new-pds.com",
    targetPdsDid: "did:web:new-pds.com",
    targetHandle: "bob.new-pds.com",
    targetEmail: "bob@new-pds.com",
    targetPassword: "password456",
    inviteCode: "",
    targetAccessToken: null,
    targetRefreshToken: null,
    serviceAuthToken: null,
    plcToken: "",
    progress: {
      repoExported: false,
      repoImported: false,
      blobsTotal: 0,
      blobsMigrated: 0,
      blobsFailed: [],
      prefsMigrated: false,
      plcSigned: false,
      activated: false,
      deactivated: false,
      currentOperation: "",
    },
    error: null,
    targetServerInfo: null,
    ...overrides,
  };
}

describe("migration/storage", () => {
  beforeEach(() => {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(DPOP_KEY_STORAGE);
  });

  describe("saveMigrationState", () => {
    it("saves inbound migration state to localStorage", () => {
      const state = createInboundState({
        step: "migrating",
        progress: {
          repoExported: true,
          repoImported: false,
          blobsTotal: 10,
          blobsMigrated: 5,
          blobsFailed: [],
          prefsMigrated: false,
          plcSigned: false,
          activated: false,
          deactivated: false,
          currentOperation: "Migrating blobs...",
        },
      });

      saveMigrationState(state);

      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
      expect(stored.version).toBe(1);
      expect(stored.direction).toBe("inbound");
      expect(stored.step).toBe("migrating");
      expect(stored.sourcePdsUrl).toBe("https://bsky.social");
      expect(stored.sourceDid).toBe("did:plc:abc123");
      expect(stored.sourceHandle).toBe("alice.bsky.social");
      expect(stored.targetHandle).toBe("alice.example.com");
      expect(stored.targetEmail).toBe("alice@example.com");
      expect(stored.progress.repoExported).toBe(true);
      expect(stored.progress.blobsMigrated).toBe(5);
      expect(stored.startedAt).toBeDefined();
      expect(new Date(stored.startedAt).getTime()).not.toBeNaN();
    });

    it("saves outbound migration state to localStorage", () => {
      const state = createOutboundState({
        step: "review",
      });

      saveMigrationState(state as unknown as MigrationState);

      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
      expect(stored.version).toBe(1);
      expect(stored.direction).toBe("outbound");
      expect(stored.step).toBe("review");
      expect(stored.targetHandle).toBe("bob.new-pds.com");
      expect(stored.targetEmail).toBe("bob@new-pds.com");
    });

    it("saves authMethod for inbound migrations", () => {
      const state = createInboundState({ authMethod: "passkey" });

      saveMigrationState(state);

      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
      expect(stored.authMethod).toBe("passkey");
    });

    it("saves passkeySetupToken when present", () => {
      const state = createInboundState({
        authMethod: "passkey",
        passkeySetupToken: "setup-token-123",
      });

      saveMigrationState(state);

      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
      expect(stored.passkeySetupToken).toBe("setup-token-123");
    });

    it("saves error information", () => {
      const state = createInboundState({
        step: "error",
        error: "Connection failed",
      });

      saveMigrationState(state);

      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
      expect(stored.lastError).toBe("Connection failed");
      expect(stored.lastErrorStep).toBe("error");
    });
  });

  describe("loadMigrationState", () => {
    it("returns null when no state is stored", () => {
      expect(loadMigrationState()).toBeNull();
    });

    it("loads valid migration state", () => {
      const state = createInboundState({ step: "migrating" });
      saveMigrationState(state);

      const loaded = loadMigrationState();

      expect(loaded).not.toBeNull();
      expect(loaded!.direction).toBe("inbound");
      expect(loaded!.step).toBe("migrating");
      expect(loaded!.sourceHandle).toBe("alice.bsky.social");
    });

    it("clears and returns null for incompatible version", () => {
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({
          version: 999,
          direction: "inbound",
          step: "welcome",
        }),
      );

      const loaded = loadMigrationState();

      expect(loaded).toBeNull();
      expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
    });

    it("clears and returns null for expired state (> 24 hours)", () => {
      const expiredState = {
        version: 1,
        direction: "inbound",
        step: "welcome",
        startedAt: new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString(),
        sourcePdsUrl: "https://bsky.social",
        targetPdsUrl: "http://localhost:3000",
        sourceDid: "did:plc:abc123",
        sourceHandle: "alice.bsky.social",
        targetHandle: "alice.example.com",
        targetEmail: "alice@example.com",
        progress: {
          repoExported: false,
          repoImported: false,
          blobsTotal: 0,
          blobsMigrated: 0,
          prefsMigrated: false,
          plcSigned: false,
        },
      };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(expiredState));

      const loaded = loadMigrationState();

      expect(loaded).toBeNull();
      expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
    });

    it("returns state that is not yet expired (< 24 hours)", () => {
      const recentState = {
        version: 1,
        direction: "inbound",
        step: "review",
        startedAt: new Date(Date.now() - 23 * 60 * 60 * 1000).toISOString(),
        sourcePdsUrl: "https://bsky.social",
        targetPdsUrl: "http://localhost:3000",
        sourceDid: "did:plc:abc123",
        sourceHandle: "alice.bsky.social",
        targetHandle: "alice.example.com",
        targetEmail: "alice@example.com",
        progress: {
          repoExported: false,
          repoImported: false,
          blobsTotal: 0,
          blobsMigrated: 0,
          prefsMigrated: false,
          plcSigned: false,
        },
      };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(recentState));

      const loaded = loadMigrationState();

      expect(loaded).not.toBeNull();
      expect(loaded!.step).toBe("review");
    });

    it("clears and returns null for invalid JSON", () => {
      localStorage.setItem(STORAGE_KEY, "not-valid-json");

      const loaded = loadMigrationState();

      expect(loaded).toBeNull();
      expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
    });
  });

  describe("clearMigrationState", () => {
    it("removes migration state from localStorage", () => {
      const state = createInboundState();
      saveMigrationState(state);
      expect(localStorage.getItem(STORAGE_KEY)).not.toBeNull();

      clearMigrationState();

      expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
    });

    it("also removes DPoP key", () => {
      localStorage.setItem(DPOP_KEY_STORAGE, "some-dpop-key");
      const state = createInboundState();
      saveMigrationState(state);

      clearMigrationState();

      expect(localStorage.getItem(DPOP_KEY_STORAGE)).toBeNull();
    });

    it("does not throw when nothing to clear", () => {
      expect(() => clearMigrationState()).not.toThrow();
    });
  });

  describe("hasPendingMigration", () => {
    it("returns false when no migration state exists", () => {
      expect(hasPendingMigration()).toBe(false);
    });

    it("returns true when valid migration state exists", () => {
      const state = createInboundState();
      saveMigrationState(state);

      expect(hasPendingMigration()).toBe(true);
    });

    it("returns false when state is expired", () => {
      const expiredState = {
        version: 1,
        direction: "inbound",
        step: "welcome",
        startedAt: new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString(),
        sourcePdsUrl: "https://bsky.social",
        targetPdsUrl: "http://localhost:3000",
        sourceDid: "did:plc:abc123",
        sourceHandle: "alice.bsky.social",
        targetHandle: "alice.example.com",
        targetEmail: "alice@example.com",
        progress: {
          repoExported: false,
          repoImported: false,
          blobsTotal: 0,
          blobsMigrated: 0,
          prefsMigrated: false,
          plcSigned: false,
        },
      };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(expiredState));

      expect(hasPendingMigration()).toBe(false);
    });
  });

  describe("getResumeInfo", () => {
    it("returns null when no migration state exists", () => {
      expect(getResumeInfo()).toBeNull();
    });

    it("returns resume info for inbound migration", () => {
      const state = createInboundState({
        step: "migrating",
        progress: {
          repoExported: true,
          repoImported: true,
          blobsTotal: 10,
          blobsMigrated: 5,
          blobsFailed: [],
          prefsMigrated: false,
          plcSigned: false,
          activated: false,
          deactivated: false,
          currentOperation: "",
        },
      });
      saveMigrationState(state);

      const info = getResumeInfo();

      expect(info).not.toBeNull();
      expect(info!.direction).toBe("inbound");
      expect(info!.sourceHandle).toBe("alice.bsky.social");
      expect(info!.targetHandle).toBe("alice.example.com");
      expect(info!.progressSummary).toContain("repo exported");
      expect(info!.progressSummary).toContain("repo imported");
      expect(info!.progressSummary).toContain("5/10 blobs");
    });

    it("returns 'just started' when no progress made", () => {
      const state = createInboundState({ step: "welcome" });
      saveMigrationState(state);

      const info = getResumeInfo();

      expect(info!.progressSummary).toBe("just started");
    });

    it("includes authMethod for inbound migrations", () => {
      const state = createInboundState({ authMethod: "passkey" });
      saveMigrationState(state);

      const info = getResumeInfo();

      expect(info!.authMethod).toBe("passkey");
    });

    it("includes all completed progress items", () => {
      const state = createInboundState({
        step: "finalizing",
        progress: {
          repoExported: true,
          repoImported: true,
          blobsTotal: 10,
          blobsMigrated: 10,
          blobsFailed: [],
          prefsMigrated: true,
          plcSigned: true,
          activated: false,
          deactivated: false,
          currentOperation: "",
        },
      });
      saveMigrationState(state);

      const info = getResumeInfo();

      expect(info!.progressSummary).toContain("repo exported");
      expect(info!.progressSummary).toContain("repo imported");
      expect(info!.progressSummary).toContain("preferences migrated");
      expect(info!.progressSummary).toContain("PLC signed");
    });
  });

  describe("updateProgress", () => {
    it("updates progress fields in stored state", () => {
      const state = createInboundState();
      saveMigrationState(state);

      updateProgress({ repoExported: true, blobsTotal: 50 });

      const loaded = loadMigrationState();
      expect(loaded!.progress.repoExported).toBe(true);
      expect(loaded!.progress.blobsTotal).toBe(50);
    });

    it("preserves other progress fields", () => {
      const state = createInboundState({
        progress: {
          repoExported: true,
          repoImported: false,
          blobsTotal: 10,
          blobsMigrated: 0,
          blobsFailed: [],
          prefsMigrated: false,
          plcSigned: false,
          activated: false,
          deactivated: false,
          currentOperation: "",
        },
      });
      saveMigrationState(state);

      updateProgress({ repoImported: true });

      const loaded = loadMigrationState();
      expect(loaded!.progress.repoExported).toBe(true);
      expect(loaded!.progress.repoImported).toBe(true);
    });

    it("does nothing when no state exists", () => {
      expect(() => updateProgress({ repoExported: true })).not.toThrow();
      expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
    });
  });

  describe("updateStep", () => {
    it("updates step in stored state", () => {
      const state = createInboundState({ step: "welcome" });
      saveMigrationState(state);

      updateStep("migrating");

      const loaded = loadMigrationState();
      expect(loaded!.step).toBe("migrating");
    });

    it("does nothing when no state exists", () => {
      expect(() => updateStep("migrating")).not.toThrow();
      expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
    });
  });

  describe("setError", () => {
    it("sets error and errorStep in stored state", () => {
      const state = createInboundState({ step: "migrating" });
      saveMigrationState(state);

      setError("Connection timeout", "migrating");

      const loaded = loadMigrationState();
      expect(loaded!.lastError).toBe("Connection timeout");
      expect(loaded!.lastErrorStep).toBe("migrating");
    });

    it("does nothing when no state exists", () => {
      expect(() => setError("Error message", "welcome")).not.toThrow();
      expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
    });
  });
});
