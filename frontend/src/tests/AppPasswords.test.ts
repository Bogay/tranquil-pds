import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import AppPasswords from "../routes/AppPasswords.svelte";
import {
  clearMocks,
  errorResponse,
  getErrorToasts,
  jsonResponse,
  mockData,
  mockEndpoint,
  setupAuthenticatedUser,
  setupFetchMock,
  setupUnauthenticatedUser,
} from "./mocks.ts";
import { unsafeAsISODateString } from "../lib/types/branded.ts";
describe("AppPasswords", () => {
  beforeEach(() => {
    clearMocks();
    setupFetchMock();
    globalThis.confirm = vi.fn(() => true);
  });
  describe("authentication guard", () => {
    it("redirects to login when not authenticated", async () => {
      setupUnauthenticatedUser();
      render(AppPasswords);
      await waitFor(() => {
        expect(globalThis.location.pathname).toBe("/app/login");
      });
    });
  });
  describe("page structure", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
      mockEndpoint(
        "com.atproto.server.listAppPasswords",
        () => jsonResponse({ passwords: [] }),
      );
    });
    it("displays all page elements", async () => {
      render(AppPasswords);
      await waitFor(() => {
        expect(
          screen.getByRole("heading", { name: /app passwords/i, level: 1 }),
        ).toBeInTheDocument();
        expect(screen.getByRole("link", { name: /dashboard/i }))
          .toHaveAttribute("href", "/app/dashboard");
        expect(screen.getByText(/third-party apps/i)).toBeInTheDocument();
      });
    });
  });
  describe("loading state", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
    });
    it("shows loading skeleton while fetching passwords", () => {
      mockEndpoint(
        "com.atproto.server.listAppPasswords",
        () =>
          new Promise((resolve) =>
            setTimeout(() => resolve(jsonResponse({ passwords: [] })), 100)
          ),
      );
      const { container } = render(AppPasswords);
      expect(container.querySelectorAll(".skeleton-item").length)
        .toBeGreaterThan(0);
    });
  });
  describe("empty state", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
      mockEndpoint(
        "com.atproto.server.listAppPasswords",
        () => jsonResponse({ passwords: [] }),
      );
    });
    it("shows empty message when no passwords exist", async () => {
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByText(/no app passwords yet/i)).toBeInTheDocument();
      });
    });
  });
  describe("password list", () => {
    const testPasswords = [
      mockData.appPassword({
        name: "Graysky",
        createdAt: unsafeAsISODateString("2024-01-15T10:00:00Z"),
      }),
      mockData.appPassword({
        name: "Skeets",
        createdAt: unsafeAsISODateString("2024-02-20T15:30:00Z"),
      }),
    ];
    beforeEach(() => {
      setupAuthenticatedUser();
      mockEndpoint(
        "com.atproto.server.listAppPasswords",
        () => jsonResponse({ passwords: testPasswords }),
      );
    });
    it("displays all app passwords with dates and revoke buttons", async () => {
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByText("Graysky")).toBeInTheDocument();
        expect(screen.getByText("Skeets")).toBeInTheDocument();
        expect(screen.getByText(/created.*2024-01-15/i)).toBeInTheDocument();
        expect(screen.getByText(/created.*2024-02-20/i)).toBeInTheDocument();
        expect(screen.getAllByRole("button", { name: /revoke/i })).toHaveLength(
          2,
        );
      });
    });
  });
  describe("create app password", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
      mockEndpoint(
        "com.atproto.server.listAppPasswords",
        () => jsonResponse({ passwords: [] }),
      );
    });
    it("displays create form with input and button", async () => {
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByPlaceholderText(/app name/i)).toBeInTheDocument();
        expect(screen.getByRole("button", { name: /create/i }))
          .toBeInTheDocument();
      });
    });
    it("disables create button when input is empty", async () => {
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByRole("button", { name: /create/i })).toBeDisabled();
      });
    });
    it("enables create button when input has value", async () => {
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByPlaceholderText(/app name/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByPlaceholderText(/app name/i), {
        target: { value: "My New App" },
      });
      expect(screen.getByRole("button", { name: /create/i })).not
        .toBeDisabled();
    });
    it("calls createAppPassword with correct name", async () => {
      let capturedName: string | null = null;
      mockEndpoint("com.atproto.server.createAppPassword", (_url, options) => {
        const body = JSON.parse((options?.body as string) || "{}");
        capturedName = body.name;
        return jsonResponse({
          name: body.name,
          password: "xxxx-xxxx-xxxx-xxxx",
          createdAt: new Date().toISOString(),
        });
      });
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByPlaceholderText(/app name/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByPlaceholderText(/app name/i), {
        target: { value: "Graysky" },
      });
      await fireEvent.click(screen.getByRole("button", { name: /create/i }));
      await waitFor(() => {
        expect(capturedName).toBe("Graysky");
      });
    });
    it("shows loading state while creating", async () => {
      mockEndpoint("com.atproto.server.createAppPassword", async () => {
        await new Promise((resolve) => setTimeout(resolve, 100));
        return jsonResponse({
          name: "Test",
          password: "xxxx-xxxx-xxxx-xxxx",
          createdAt: new Date().toISOString(),
        });
      });
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByPlaceholderText(/app name/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByPlaceholderText(/app name/i), {
        target: { value: "Test" },
      });
      await fireEvent.click(screen.getByRole("button", { name: /create/i }));
      expect(screen.getByRole("button", { name: /creating/i }))
        .toBeInTheDocument();
      expect(screen.getByRole("button", { name: /creating/i })).toBeDisabled();
    });
    it("displays created password in success box and clears input", async () => {
      mockEndpoint("com.atproto.server.createAppPassword", () =>
        jsonResponse({
          name: "MyApp",
          password: "abcd-efgh-ijkl-mnop",
          createdAt: new Date().toISOString(),
        }));
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByPlaceholderText(/app name/i)).toBeInTheDocument();
      });
      const input = screen.getByPlaceholderText(
        /app name/i,
      ) as HTMLInputElement;
      await fireEvent.input(input, { target: { value: "MyApp" } });
      await fireEvent.click(screen.getByRole("button", { name: /create/i }));
      await waitFor(() => {
        expect(screen.getByText(/save this app password/i)).toBeInTheDocument();
        expect(screen.getByText("abcd-efgh-ijkl-mnop")).toBeInTheDocument();
        expect(screen.getByText("MyApp")).toBeInTheDocument();
        expect(input.value).toBe("");
      });
    });
    it("dismisses created password box when clicking Done", async () => {
      mockEndpoint("com.atproto.server.createAppPassword", () =>
        jsonResponse({
          name: "Test",
          password: "xxxx-xxxx-xxxx-xxxx",
          createdAt: new Date().toISOString(),
        }));
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByPlaceholderText(/app name/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByPlaceholderText(/app name/i), {
        target: { value: "Test" },
      });
      await fireEvent.click(screen.getByRole("button", { name: /create/i }));
      await waitFor(() => {
        expect(screen.getByText(/save this app password/i)).toBeInTheDocument();
      });
      await fireEvent.click(
        screen.getByLabelText(/i have saved my app password/i),
      );
      await fireEvent.click(screen.getByRole("button", { name: /done/i }));
      await waitFor(() => {
        expect(screen.queryByText(/save this app password/i)).not
          .toBeInTheDocument();
      });
    });
    it("shows error toast when creation fails", async () => {
      mockEndpoint(
        "com.atproto.server.createAppPassword",
        () => errorResponse("InvalidRequest", "Name already exists", 400),
      );
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByPlaceholderText(/app name/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByPlaceholderText(/app name/i), {
        target: { value: "Duplicate" },
      });
      await fireEvent.click(screen.getByRole("button", { name: /create/i }));
      await waitFor(() => {
        const errors = getErrorToasts();
        expect(errors.some((e) => /name already exists/i.test(e))).toBe(true);
      });
    });
  });
  describe("revoke app password", () => {
    const testPassword = mockData.appPassword({ name: "TestApp" });
    beforeEach(() => {
      setupAuthenticatedUser();
    });
    it("shows confirmation dialog before revoking", async () => {
      const confirmSpy = vi.fn(() => false);
      globalThis.confirm = confirmSpy;
      mockEndpoint(
        "com.atproto.server.listAppPasswords",
        () => jsonResponse({ passwords: [testPassword] }),
      );
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByText("TestApp")).toBeInTheDocument();
      });
      await fireEvent.click(screen.getByRole("button", { name: /revoke/i }));
      expect(confirmSpy).toHaveBeenCalledWith(
        expect.stringContaining("TestApp"),
      );
    });
    it("does not revoke when confirmation is cancelled", async () => {
      globalThis.confirm = vi.fn(() => false);
      let revokeCalled = false;
      mockEndpoint(
        "com.atproto.server.listAppPasswords",
        () => jsonResponse({ passwords: [testPassword] }),
      );
      mockEndpoint("com.atproto.server.revokeAppPassword", () => {
        revokeCalled = true;
        return jsonResponse({});
      });
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByText("TestApp")).toBeInTheDocument();
      });
      await fireEvent.click(screen.getByRole("button", { name: /revoke/i }));
      expect(revokeCalled).toBe(false);
    });
    it("calls revokeAppPassword with correct name", async () => {
      globalThis.confirm = vi.fn(() => true);
      let capturedName: string | null = null;
      mockEndpoint(
        "com.atproto.server.listAppPasswords",
        () => jsonResponse({ passwords: [testPassword] }),
      );
      mockEndpoint("com.atproto.server.revokeAppPassword", (_url, options) => {
        const body = JSON.parse((options?.body as string) || "{}");
        capturedName = body.name;
        return jsonResponse({});
      });
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByText("TestApp")).toBeInTheDocument();
      });
      await fireEvent.click(screen.getByRole("button", { name: /revoke/i }));
      await waitFor(() => {
        expect(capturedName).toBe("TestApp");
      });
    });
    it("shows loading state while revoking", async () => {
      globalThis.confirm = vi.fn(() => true);
      mockEndpoint(
        "com.atproto.server.listAppPasswords",
        () => jsonResponse({ passwords: [testPassword] }),
      );
      mockEndpoint("com.atproto.server.revokeAppPassword", async () => {
        await new Promise((resolve) => setTimeout(resolve, 100));
        return jsonResponse({});
      });
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByText("TestApp")).toBeInTheDocument();
      });
      await fireEvent.click(screen.getByRole("button", { name: /revoke/i }));
      expect(screen.getByRole("button", { name: /revoking/i }))
        .toBeInTheDocument();
      expect(screen.getByRole("button", { name: /revoking/i })).toBeDisabled();
    });
    it("reloads password list after successful revocation", async () => {
      globalThis.confirm = vi.fn(() => true);
      let listCallCount = 0;
      mockEndpoint("com.atproto.server.listAppPasswords", () => {
        listCallCount++;
        if (listCallCount === 1) {
          return jsonResponse({ passwords: [testPassword] });
        }
        return jsonResponse({ passwords: [] });
      });
      mockEndpoint(
        "com.atproto.server.revokeAppPassword",
        () => jsonResponse({}),
      );
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByText("TestApp")).toBeInTheDocument();
      });
      await fireEvent.click(screen.getByRole("button", { name: /revoke/i }));
      await waitFor(() => {
        expect(screen.queryByText("TestApp")).not.toBeInTheDocument();
        expect(screen.getByText(/no app passwords yet/i)).toBeInTheDocument();
      });
    });
    it("shows error toast when revocation fails", async () => {
      globalThis.confirm = vi.fn(() => true);
      mockEndpoint(
        "com.atproto.server.listAppPasswords",
        () => jsonResponse({ passwords: [testPassword] }),
      );
      mockEndpoint(
        "com.atproto.server.revokeAppPassword",
        () => errorResponse("InternalError", "Server error", 500),
      );
      render(AppPasswords);
      await waitFor(() => {
        expect(screen.getByText("TestApp")).toBeInTheDocument();
      });
      await fireEvent.click(screen.getByRole("button", { name: /revoke/i }));
      await waitFor(() => {
        const errors = getErrorToasts();
        expect(errors.some((e) => /server error/i.test(e))).toBe(true);
      });
    });
  });
  describe("error handling", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
    });
    it("shows error toast when loading passwords fails", async () => {
      mockEndpoint(
        "com.atproto.server.listAppPasswords",
        () => errorResponse("InternalError", "Database connection failed", 500),
      );
      render(AppPasswords);
      await waitFor(() => {
        const errors = getErrorToasts();
        expect(errors.some((e) => /database connection failed/i.test(e))).toBe(
          true,
        );
      });
    });
  });
});
