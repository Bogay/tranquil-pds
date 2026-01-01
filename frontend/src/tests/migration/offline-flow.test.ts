import { beforeEach, describe, expect, it, vi } from "vitest";
import { createOfflineInboundMigrationFlow } from "../../lib/migration/offline-flow.svelte";

const OFFLINE_STORAGE_KEY = "tranquil_offline_migration_state";

describe("migration/offline-flow", () => {
  beforeEach(() => {
    localStorage.removeItem(OFFLINE_STORAGE_KEY);
    vi.restoreAllMocks();
  });

  describe("createOfflineInboundMigrationFlow", () => {
    it("creates flow with initial state", () => {
      const flow = createOfflineInboundMigrationFlow();

      expect(flow.state.direction).toBe("offline-inbound");
      expect(flow.state.step).toBe("welcome");
      expect(flow.state.userDid).toBe("");
      expect(flow.state.carFile).toBeNull();
      expect(flow.state.carFileName).toBe("");
      expect(flow.state.carSizeBytes).toBe(0);
      expect(flow.state.rotationKey).toBe("");
      expect(flow.state.rotationKeyDidKey).toBe("");
      expect(flow.state.targetHandle).toBe("");
      expect(flow.state.targetEmail).toBe("");
      expect(flow.state.targetPassword).toBe("");
      expect(flow.state.inviteCode).toBe("");
      expect(flow.state.localAccessToken).toBeNull();
      expect(flow.state.localRefreshToken).toBeNull();
      expect(flow.state.error).toBeNull();
    });

    it("initializes progress correctly", () => {
      const flow = createOfflineInboundMigrationFlow();

      expect(flow.state.progress.repoExported).toBe(false);
      expect(flow.state.progress.repoImported).toBe(false);
      expect(flow.state.progress.blobsTotal).toBe(0);
      expect(flow.state.progress.blobsMigrated).toBe(0);
      expect(flow.state.progress.blobsFailed).toEqual([]);
      expect(flow.state.progress.prefsMigrated).toBe(false);
      expect(flow.state.progress.plcSigned).toBe(false);
      expect(flow.state.progress.activated).toBe(false);
      expect(flow.state.progress.deactivated).toBe(false);
      expect(flow.state.progress.currentOperation).toBe("");
    });
  });

  describe("setUserDid", () => {
    it("sets the user DID", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setUserDid("did:plc:abc123");

      expect(flow.state.userDid).toBe("did:plc:abc123");
    });

    it("saves state to localStorage", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setUserDid("did:plc:xyz789");

      const stored = JSON.parse(localStorage.getItem(OFFLINE_STORAGE_KEY)!);
      expect(stored.userDid).toBe("did:plc:xyz789");
    });
  });

  describe("setCarFile", () => {
    it("sets CAR file data", () => {
      const flow = createOfflineInboundMigrationFlow();
      const carData = new Uint8Array([1, 2, 3, 4, 5]);

      flow.setCarFile(carData, "repo.car");

      expect(flow.state.carFile).toEqual(carData);
      expect(flow.state.carFileName).toBe("repo.car");
      expect(flow.state.carSizeBytes).toBe(5);
    });

    it("saves file metadata to localStorage (not file content)", () => {
      const flow = createOfflineInboundMigrationFlow();
      const carData = new Uint8Array([1, 2, 3, 4, 5]);

      flow.setCarFile(carData, "backup.car");

      const stored = JSON.parse(localStorage.getItem(OFFLINE_STORAGE_KEY)!);
      expect(stored.carFileName).toBe("backup.car");
      expect(stored.carSizeBytes).toBe(5);
    });
  });

  describe("setRotationKey", () => {
    it("sets the rotation key", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setRotationKey("abc123privatekey");

      expect(flow.state.rotationKey).toBe("abc123privatekey");
    });

    it("does not save rotation key to localStorage (security)", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setRotationKey("supersecretkey");

      const stored = localStorage.getItem(OFFLINE_STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        expect(parsed.rotationKey).toBeUndefined();
      }
    });
  });

  describe("setTargetHandle", () => {
    it("sets the target handle", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setTargetHandle("alice.example.com");

      expect(flow.state.targetHandle).toBe("alice.example.com");
    });

    it("saves to localStorage", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setTargetHandle("bob.example.com");

      const stored = JSON.parse(localStorage.getItem(OFFLINE_STORAGE_KEY)!);
      expect(stored.targetHandle).toBe("bob.example.com");
    });
  });

  describe("setTargetEmail", () => {
    it("sets the target email", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setTargetEmail("alice@example.com");

      expect(flow.state.targetEmail).toBe("alice@example.com");
    });

    it("saves to localStorage", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setTargetEmail("bob@example.com");

      const stored = JSON.parse(localStorage.getItem(OFFLINE_STORAGE_KEY)!);
      expect(stored.targetEmail).toBe("bob@example.com");
    });
  });

  describe("setTargetPassword", () => {
    it("sets the target password", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setTargetPassword("securepassword123");

      expect(flow.state.targetPassword).toBe("securepassword123");
    });

    it("does not save password to localStorage (security)", () => {
      const flow = createOfflineInboundMigrationFlow();
      flow.setUserDid("did:plc:test");

      flow.setTargetPassword("mypassword");

      const stored = localStorage.getItem(OFFLINE_STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        expect(parsed.targetPassword).toBeUndefined();
      }
    });
  });

  describe("setInviteCode", () => {
    it("sets the invite code", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setInviteCode("invite-abc123");

      expect(flow.state.inviteCode).toBe("invite-abc123");
    });
  });

  describe("setStep", () => {
    it("changes the current step", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setStep("provide-did");

      expect(flow.state.step).toBe("provide-did");
    });

    it("clears error when changing step", () => {
      const flow = createOfflineInboundMigrationFlow();
      flow.setError("Previous error");

      flow.setStep("upload-car");

      expect(flow.state.error).toBeNull();
    });

    it("saves step to localStorage", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setStep("provide-rotation-key");

      const stored = JSON.parse(localStorage.getItem(OFFLINE_STORAGE_KEY)!);
      expect(stored.step).toBe("provide-rotation-key");
    });
  });

  describe("setError", () => {
    it("sets the error message", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setError("Something went wrong");

      expect(flow.state.error).toBe("Something went wrong");
    });

    it("saves error to localStorage", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setError("Connection failed");

      const stored = JSON.parse(localStorage.getItem(OFFLINE_STORAGE_KEY)!);
      expect(stored.lastError).toBe("Connection failed");
    });
  });

  describe("setProgress", () => {
    it("updates progress fields", () => {
      const flow = createOfflineInboundMigrationFlow();

      flow.setProgress({
        repoImported: true,
        currentOperation: "Importing...",
      });

      expect(flow.state.progress.repoImported).toBe(true);
      expect(flow.state.progress.currentOperation).toBe("Importing...");
    });

    it("preserves other progress fields", () => {
      const flow = createOfflineInboundMigrationFlow();
      flow.setProgress({ repoExported: true });

      flow.setProgress({ repoImported: true });

      expect(flow.state.progress.repoExported).toBe(true);
      expect(flow.state.progress.repoImported).toBe(true);
    });
  });

  describe("reset", () => {
    it("resets state to initial values", () => {
      const flow = createOfflineInboundMigrationFlow();
      flow.setUserDid("did:plc:abc123");
      flow.setTargetHandle("alice.example.com");
      flow.setStep("review");

      flow.reset();

      expect(flow.state.step).toBe("welcome");
      expect(flow.state.userDid).toBe("");
      expect(flow.state.targetHandle).toBe("");
    });

    it("clears localStorage", () => {
      const flow = createOfflineInboundMigrationFlow();
      flow.setUserDid("did:plc:abc123");
      expect(localStorage.getItem(OFFLINE_STORAGE_KEY)).not.toBeNull();

      flow.reset();

      expect(localStorage.getItem(OFFLINE_STORAGE_KEY)).toBeNull();
    });
  });

  describe("clearOfflineState", () => {
    it("removes state from localStorage", () => {
      const flow = createOfflineInboundMigrationFlow();
      flow.setUserDid("did:plc:abc123");
      expect(localStorage.getItem(OFFLINE_STORAGE_KEY)).not.toBeNull();

      flow.clearOfflineState();

      expect(localStorage.getItem(OFFLINE_STORAGE_KEY)).toBeNull();
    });
  });

  describe("tryResume", () => {
    it("returns false when no stored state", () => {
      const flow = createOfflineInboundMigrationFlow();

      const result = flow.tryResume();

      expect(result).toBe(false);
    });

    it("restores state from localStorage", () => {
      const storedState = {
        version: 1,
        step: "choose-handle",
        startedAt: new Date().toISOString(),
        userDid: "did:plc:restored123",
        carFileName: "backup.car",
        carSizeBytes: 12345,
        rotationKeyDidKey: "did:key:z123abc",
        targetHandle: "restored.example.com",
        targetEmail: "restored@example.com",
        progress: {
          accountCreated: true,
          repoImported: false,
          plcSigned: false,
          activated: false,
        },
      };
      localStorage.setItem(OFFLINE_STORAGE_KEY, JSON.stringify(storedState));

      const flow = createOfflineInboundMigrationFlow();
      const result = flow.tryResume();

      expect(result).toBe(true);
      expect(flow.state.step).toBe("choose-handle");
      expect(flow.state.userDid).toBe("did:plc:restored123");
      expect(flow.state.carFileName).toBe("backup.car");
      expect(flow.state.carSizeBytes).toBe(12345);
      expect(flow.state.rotationKeyDidKey).toBe("did:key:z123abc");
      expect(flow.state.targetHandle).toBe("restored.example.com");
      expect(flow.state.targetEmail).toBe("restored@example.com");
      expect(flow.state.progress.repoExported).toBe(true);
    });

    it("restores error from stored state", () => {
      const storedState = {
        version: 1,
        step: "error",
        startedAt: new Date().toISOString(),
        userDid: "did:plc:abc",
        carFileName: "",
        carSizeBytes: 0,
        rotationKeyDidKey: "",
        targetHandle: "",
        targetEmail: "",
        progress: {
          accountCreated: false,
          repoImported: false,
          plcSigned: false,
          activated: false,
        },
        lastError: "Previous migration failed",
      };
      localStorage.setItem(OFFLINE_STORAGE_KEY, JSON.stringify(storedState));

      const flow = createOfflineInboundMigrationFlow();
      flow.tryResume();

      expect(flow.state.error).toBe("Previous migration failed");
    });

    it("returns false and clears for incompatible version", () => {
      const storedState = {
        version: 999,
        step: "review",
        userDid: "did:plc:abc",
      };
      localStorage.setItem(OFFLINE_STORAGE_KEY, JSON.stringify(storedState));

      const flow = createOfflineInboundMigrationFlow();
      const result = flow.tryResume();

      expect(result).toBe(false);
      expect(localStorage.getItem(OFFLINE_STORAGE_KEY)).toBeNull();
    });

    it("returns false and clears for expired state (> 24 hours)", () => {
      const expiredState = {
        version: 1,
        step: "review",
        startedAt: new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString(),
        userDid: "did:plc:expired",
        carFileName: "old.car",
        carSizeBytes: 100,
        rotationKeyDidKey: "",
        targetHandle: "old.example.com",
        targetEmail: "old@example.com",
        progress: {
          accountCreated: false,
          repoImported: false,
          plcSigned: false,
          activated: false,
        },
      };
      localStorage.setItem(OFFLINE_STORAGE_KEY, JSON.stringify(expiredState));

      const flow = createOfflineInboundMigrationFlow();
      const result = flow.tryResume();

      expect(result).toBe(false);
      expect(localStorage.getItem(OFFLINE_STORAGE_KEY)).toBeNull();
    });

    it("returns false and clears for invalid JSON", () => {
      localStorage.setItem(OFFLINE_STORAGE_KEY, "not-valid-json");

      const flow = createOfflineInboundMigrationFlow();
      const result = flow.tryResume();

      expect(result).toBe(false);
      expect(localStorage.getItem(OFFLINE_STORAGE_KEY)).toBeNull();
    });

    it("accepts state within 24 hours", () => {
      const recentState = {
        version: 1,
        step: "review",
        startedAt: new Date(Date.now() - 23 * 60 * 60 * 1000).toISOString(),
        userDid: "did:plc:recent",
        carFileName: "recent.car",
        carSizeBytes: 500,
        rotationKeyDidKey: "did:key:zRecent",
        targetHandle: "recent.example.com",
        targetEmail: "recent@example.com",
        progress: {
          accountCreated: true,
          repoImported: true,
          plcSigned: false,
          activated: false,
        },
      };
      localStorage.setItem(OFFLINE_STORAGE_KEY, JSON.stringify(recentState));

      const flow = createOfflineInboundMigrationFlow();
      const result = flow.tryResume();

      expect(result).toBe(true);
      expect(flow.state.userDid).toBe("did:plc:recent");
    });
  });

  describe("loadLocalServerInfo", () => {
    function createMockResponse(data: unknown) {
      const jsonStr = JSON.stringify(data);
      return new Response(jsonStr, {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    it("fetches server description", async () => {
      const mockServerInfo = {
        did: "did:web:example.com",
        availableUserDomains: ["example.com"],
        inviteCodeRequired: false,
      };

      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockResponse(mockServerInfo),
      );

      const flow = createOfflineInboundMigrationFlow();
      const result = await flow.loadLocalServerInfo();

      expect(result).toEqual(mockServerInfo);
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining("com.atproto.server.describeServer"),
        expect.any(Object),
      );
    });

    it("caches server info", async () => {
      const mockServerInfo = {
        did: "did:web:example.com",
        availableUserDomains: ["example.com"],
        inviteCodeRequired: false,
      };

      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockResponse(mockServerInfo),
      );

      const flow = createOfflineInboundMigrationFlow();
      await flow.loadLocalServerInfo();
      await flow.loadLocalServerInfo();

      expect(fetch).toHaveBeenCalledTimes(1);
    });
  });
});
