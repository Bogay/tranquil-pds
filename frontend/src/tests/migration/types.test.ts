import { describe, expect, it } from "vitest";
import { MigrationError } from "../../lib/migration/types";

describe("migration/types", () => {
  describe("MigrationError", () => {
    it("creates error with message and code", () => {
      const error = new MigrationError("Something went wrong", "ERR_NETWORK");

      expect(error.message).toBe("Something went wrong");
      expect(error.code).toBe("ERR_NETWORK");
      expect(error.name).toBe("MigrationError");
    });

    it("defaults recoverable to false", () => {
      const error = new MigrationError("Error", "ERR_CODE");

      expect(error.recoverable).toBe(false);
    });

    it("accepts recoverable flag", () => {
      const error = new MigrationError("Temporary error", "ERR_TIMEOUT", true);

      expect(error.recoverable).toBe(true);
    });

    it("accepts details object", () => {
      const details = { status: 500, endpoint: "/api/test" };
      const error = new MigrationError(
        "Server error",
        "ERR_SERVER",
        false,
        details,
      );

      expect(error.details).toEqual(details);
    });

    it("is instanceof Error", () => {
      const error = new MigrationError("Test", "ERR_TEST");

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(MigrationError);
    });

    it("has proper stack trace", () => {
      const error = new MigrationError("Test", "ERR_TEST");

      expect(error.stack).toBeDefined();
      expect(error.stack).toContain("MigrationError");
    });

    it("can be caught as Error", () => {
      let caught: Error | null = null;

      try {
        throw new MigrationError("Test error", "ERR_TEST");
      } catch (e) {
        caught = e as Error;
      }

      expect(caught).not.toBeNull();
      expect(caught!.message).toBe("Test error");
    });

    it("can check if error is MigrationError", () => {
      const error = new MigrationError("Test", "ERR_TEST", true, { foo: "bar" });

      if (error instanceof MigrationError) {
        expect(error.code).toBe("ERR_TEST");
        expect(error.recoverable).toBe(true);
        expect(error.details).toEqual({ foo: "bar" });
      }
    });
  });
});
