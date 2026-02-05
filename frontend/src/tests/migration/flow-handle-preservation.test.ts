import { beforeEach, describe, expect, it, vi } from "vitest";
import { createInboundMigrationFlow } from "../../lib/migration/flow.svelte.ts";

const STORAGE_KEY = "tranquil_migration_state";

function createMockJsonResponse(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("migration/flow handle preservation", () => {
  beforeEach(() => {
    localStorage.removeItem(STORAGE_KEY);
    vi.restoreAllMocks();
  });

  describe("initial state", () => {
    it("defaults handlePreservation to 'new'", () => {
      const flow = createInboundMigrationFlow();
      expect(flow.state.handlePreservation).toBe("new");
    });

    it("defaults existingHandleVerified to false", () => {
      const flow = createInboundMigrationFlow();
      expect(flow.state.existingHandleVerified).toBe(false);
    });
  });

  describe("updateField for handle preservation", () => {
    it("sets handlePreservation to 'existing'", () => {
      const flow = createInboundMigrationFlow();
      flow.updateField("handlePreservation", "existing");
      expect(flow.state.handlePreservation).toBe("existing");
    });

    it("sets handlePreservation back to 'new'", () => {
      const flow = createInboundMigrationFlow();
      flow.updateField("handlePreservation", "existing");
      flow.updateField("handlePreservation", "new");
      expect(flow.state.handlePreservation).toBe("new");
    });

    it("sets existingHandleVerified", () => {
      const flow = createInboundMigrationFlow();
      flow.updateField("existingHandleVerified", true);
      expect(flow.state.existingHandleVerified).toBe(true);
    });
  });

  describe("verifyExistingHandle", () => {
    it("sets existingHandleVerified and targetHandle on success", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockJsonResponse({ verified: true, method: "dns" }),
      );

      const flow = createInboundMigrationFlow();
      flow.updateField("sourceHandle", "alice.custom.com");
      flow.updateField("sourceDid", "did:plc:abc123");

      const result = await flow.verifyExistingHandle();

      expect(result.verified).toBe(true);
      expect(result.method).toBe("dns");
      expect(flow.state.existingHandleVerified).toBe(true);
      expect(flow.state.targetHandle).toBe("alice.custom.com");
    });

    it("does not set existingHandleVerified on failure", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockJsonResponse({
          verified: false,
          error: "Handle resolution failed",
        }),
      );

      const flow = createInboundMigrationFlow();
      flow.updateField("sourceHandle", "alice.custom.com");
      flow.updateField("sourceDid", "did:plc:abc123");

      const result = await flow.verifyExistingHandle();

      expect(result.verified).toBe(false);
      expect(result.error).toBe("Handle resolution failed");
      expect(flow.state.existingHandleVerified).toBe(false);
    });

    it("sends correct handle and did to endpoint", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockJsonResponse({ verified: true, method: "http" }),
      );

      const flow = createInboundMigrationFlow();
      flow.updateField("sourceHandle", "bob.example.org");
      flow.updateField("sourceDid", "did:plc:xyz789");

      await flow.verifyExistingHandle();

      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining("_identity.verifyHandleOwnership"),
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            handle: "bob.example.org",
            did: "did:plc:xyz789",
          }),
        }),
      );
    });

    it("handles http verification method", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockJsonResponse({ verified: true, method: "http" }),
      );

      const flow = createInboundMigrationFlow();
      flow.updateField("sourceHandle", "alice.custom.com");
      flow.updateField("sourceDid", "did:plc:abc123");

      const result = await flow.verifyExistingHandle();

      expect(result.method).toBe("http");
    });

    it("propagates xrpc errors as thrown exceptions", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockJsonResponse(
          { error: "InvalidHandle", message: "Invalid handle format" },
          400,
        ),
      );

      const flow = createInboundMigrationFlow();
      flow.updateField("sourceHandle", "@#$!");
      flow.updateField("sourceDid", "did:plc:abc123");

      await expect(flow.verifyExistingHandle()).rejects.toThrow();
    });
  });

  describe("reset clears handle preservation state", () => {
    it("resets handlePreservation to 'new'", () => {
      const flow = createInboundMigrationFlow();
      flow.updateField("handlePreservation", "existing");
      flow.updateField("existingHandleVerified", true);

      flow.reset();

      expect(flow.state.handlePreservation).toBe("new");
      expect(flow.state.existingHandleVerified).toBe(false);
    });
  });

  describe("handle @ normalization", () => {
    it("resolveSourcePds strips leading @", async () => {
      globalThis.fetch = vi.fn()
        .mockResolvedValueOnce(
          createMockJsonResponse({
            Answer: [{ data: '"did=did:plc:test123"' }],
          }),
        )
        .mockResolvedValueOnce(
          createMockJsonResponse({
            id: "did:plc:test123",
            service: [
              {
                type: "AtprotoPersonalDataServer",
                serviceEndpoint: "https://pds.example.com",
              },
            ],
          }),
        );

      const flow = createInboundMigrationFlow();
      await flow.resolveSourcePds("@alice.example.com");

      expect(flow.state.sourceHandle).toBe("alice.example.com");
    });

    it("resolveSourcePds preserves handle without @", async () => {
      globalThis.fetch = vi.fn()
        .mockResolvedValueOnce(
          createMockJsonResponse({
            Answer: [{ data: '"did=did:plc:test456"' }],
          }),
        )
        .mockResolvedValueOnce(
          createMockJsonResponse({
            id: "did:plc:test456",
            service: [
              {
                type: "AtprotoPersonalDataServer",
                serviceEndpoint: "https://pds.example.com",
              },
            ],
          }),
        );

      const flow = createInboundMigrationFlow();
      await flow.resolveSourcePds("bob.example.com");

      expect(flow.state.sourceHandle).toBe("bob.example.com");
    });
  });
});
