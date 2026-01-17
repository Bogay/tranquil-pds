import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import Settings from "../routes/Settings.svelte";
import {
  clearMocks,
  errorResponse,
  getErrorToasts,
  getToasts,
  jsonResponse,
  mockData,
  mockEndpoint,
  setupAuthenticatedUser,
  setupDefaultMocks,
  setupUnauthenticatedUser,
} from "./mocks.ts";
describe("Settings", () => {
  beforeEach(() => {
    clearMocks();
    setupDefaultMocks();
    globalThis.confirm = vi.fn(() => true);
  });
  describe("authentication guard", () => {
    it("redirects to login when not authenticated", async () => {
      setupUnauthenticatedUser();
      render(Settings);
      await waitFor(() => {
        expect(globalThis.location.pathname).toBe("/app/login");
      });
    });
  });
  describe("page structure", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
    });
    it("displays all page elements and sections", async () => {
      render(Settings);
      await waitFor(() => {
        expect(
          screen.getByRole("heading", { name: /account settings/i, level: 1 }),
        ).toBeInTheDocument();
        expect(screen.getByRole("link", { name: /dashboard/i }))
          .toHaveAttribute("href", "/app/dashboard");
        expect(screen.getByRole("heading", { name: /change email/i }))
          .toBeInTheDocument();
        expect(screen.getByRole("heading", { name: /change handle/i }))
          .toBeInTheDocument();
        expect(screen.getByRole("heading", { name: /delete account/i }))
          .toBeInTheDocument();
      });
    });
  });
  describe("email change", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
    });
    it("displays current email and change button", async () => {
      render(Settings);
      await waitFor(() => {
        expect(screen.getByText(/current.*test@example.com/i))
          .toBeInTheDocument();
        expect(screen.getByRole("button", { name: /change email/i }))
          .toBeInTheDocument();
      });
    });
    it("calls requestEmailUpdate when clicking change email button", async () => {
      let requestCalled = false;
      mockEndpoint("com.atproto.server.requestEmailUpdate", () => {
        requestCalled = true;
        return jsonResponse({ tokenRequired: true });
      });
      mockEndpoint(
        "_account.checkEmailUpdateStatus",
        () => jsonResponse({ pending: false, authorized: false }),
      );
      render(Settings);
      await waitFor(() => {
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByLabelText(/new email/i), {
        target: { value: "newemail@example.com" },
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /change email/i }),
      );
      await waitFor(() => {
        expect(requestCalled).toBe(true);
      });
    });
    it("shows verification code and new email inputs when token is required", async () => {
      mockEndpoint(
        "com.atproto.server.requestEmailUpdate",
        () => jsonResponse({ tokenRequired: true }),
      );
      mockEndpoint(
        "_account.checkEmailUpdateStatus",
        () => jsonResponse({ pending: false, authorized: false }),
      );
      render(Settings);
      await waitFor(() => {
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByLabelText(/new email/i), {
        target: { value: "newemail@example.com" },
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /change email/i }),
      );
      await waitFor(() => {
        expect(screen.getByLabelText(/verification code/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument();
        expect(screen.getByRole("button", { name: /confirm email change/i }))
          .toBeInTheDocument();
      });
    });
    it("calls updateEmail with token when confirming", async () => {
      let updateCalled = false;
      let capturedBody: Record<string, string> | null = null;
      mockEndpoint(
        "com.atproto.server.requestEmailUpdate",
        () => jsonResponse({ tokenRequired: true }),
      );
      mockEndpoint(
        "_account.checkEmailUpdateStatus",
        () => jsonResponse({ pending: false, authorized: false }),
      );
      mockEndpoint("com.atproto.server.updateEmail", (_url, options) => {
        updateCalled = true;
        capturedBody = JSON.parse((options?.body as string) || "{}");
        return jsonResponse({});
      });
      mockEndpoint(
        "com.atproto.server.getSession",
        () => jsonResponse(mockData.session()),
      );
      render(Settings);
      await waitFor(() => {
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByLabelText(/new email/i), {
        target: { value: "newemail@example.com" },
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /change email/i }),
      );
      await waitFor(() => {
        expect(screen.getByLabelText(/verification code/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByLabelText(/verification code/i), {
        target: { value: "123456" },
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /confirm email change/i }),
      );
      await waitFor(() => {
        expect(updateCalled).toBe(true);
        expect(capturedBody?.email).toBe("newemail@example.com");
        expect(capturedBody?.token).toBe("123456");
      });
    });
    it("shows success toast after email update", async () => {
      mockEndpoint(
        "com.atproto.server.requestEmailUpdate",
        () => jsonResponse({ tokenRequired: true }),
      );
      mockEndpoint(
        "_account.checkEmailUpdateStatus",
        () => jsonResponse({ pending: false, authorized: false }),
      );
      mockEndpoint("com.atproto.server.updateEmail", () => jsonResponse({}));
      mockEndpoint(
        "com.atproto.server.getSession",
        () => jsonResponse(mockData.session()),
      );
      render(Settings);
      await waitFor(() => {
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByLabelText(/new email/i), {
        target: { value: "new@test.com" },
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /change email/i }),
      );
      await waitFor(() => {
        expect(screen.getByLabelText(/verification code/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByLabelText(/verification code/i), {
        target: { value: "123456" },
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /confirm email change/i }),
      );
      await waitFor(() => {
        const toasts = getToasts();
        expect(
          toasts.some((t) =>
            t.type === "success" && /email.*updated/i.test(t.message)
          ),
        ).toBe(true);
      });
    });
    it("shows cancel button to return to initial state", async () => {
      mockEndpoint(
        "com.atproto.server.requestEmailUpdate",
        () => jsonResponse({ tokenRequired: true }),
      );
      mockEndpoint(
        "_account.checkEmailUpdateStatus",
        () => jsonResponse({ pending: false, authorized: false }),
      );
      render(Settings);
      await waitFor(() => {
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByLabelText(/new email/i), {
        target: { value: "newemail@example.com" },
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /change email/i }),
      );
      await waitFor(() => {
        expect(screen.getByRole("button", { name: /cancel/i }))
          .toBeInTheDocument();
      });
      const emailSection = screen.getByRole("heading", {
        name: /change email/i,
      })
        .closest("section");
      const cancelButton = emailSection?.querySelector("button.secondary");
      if (cancelButton) {
        await fireEvent.click(cancelButton);
      }
      await waitFor(() => {
        expect(screen.queryByLabelText(/verification code/i)).not
          .toBeInTheDocument();
      });
    });
    it("shows error toast when request fails", async () => {
      mockEndpoint(
        "com.atproto.server.requestEmailUpdate",
        () => errorResponse("InvalidEmail", "Invalid email format", 400),
      );
      render(Settings);
      await waitFor(() => {
        expect(screen.getByLabelText(/new email/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByLabelText(/new email/i), {
        target: { value: "invalid@email.com" },
      });
      const button = screen.getByRole("button", { name: /change email/i });
      await fireEvent.submit(button.closest("form")!);
      await waitFor(() => {
        const errors = getErrorToasts();
        expect(errors.some((e) => /invalid email format/i.test(e))).toBe(true);
      });
    });
  });
  describe("handle change", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
      mockEndpoint(
        "com.atproto.server.describeServer",
        () => jsonResponse(mockData.describeServer()),
      );
    });
    it("displays current handle", async () => {
      render(Settings);
      await waitFor(() => {
        expect(screen.getByText(/current.*@testuser\.test\.tranquil\.dev/i))
          .toBeInTheDocument();
      });
    });
    it("shows PDS handle and custom domain tabs", async () => {
      render(Settings);
      await waitFor(() => {
        expect(screen.getByRole("button", { name: /pds handle/i }))
          .toBeInTheDocument();
        expect(screen.getByRole("button", { name: /custom domain/i }))
          .toBeInTheDocument();
      });
    });
    it("allows entering handle and shows domain suffix", async () => {
      render(Settings);
      await waitFor(() => {
        expect(screen.getByLabelText(/new handle/i)).toBeInTheDocument();
        expect(screen.getByText(/\.test\.tranquil\.dev/i)).toBeInTheDocument();
      });
      const input = screen.getByLabelText(/new handle/i) as HTMLInputElement;
      await fireEvent.input(input, {
        target: { value: "newhandle" },
      });
      expect(input.value).toBe("newhandle");
      expect(screen.getByRole("button", { name: /change handle/i }))
        .toBeInTheDocument();
    });
    it("shows success toast after handle change", async () => {
      mockEndpoint("com.atproto.identity.updateHandle", () => jsonResponse({}));
      mockEndpoint(
        "com.atproto.server.getSession",
        () => jsonResponse(mockData.session()),
      );
      render(Settings);
      await waitFor(() => {
        expect(screen.getByLabelText(/new handle/i)).toBeInTheDocument();
        expect(screen.getByText(/\.test\.tranquil\.dev/i)).toBeInTheDocument();
      });
      const input = screen.getByLabelText(/new handle/i) as HTMLInputElement;
      await fireEvent.input(input, {
        target: { value: "newhandle" },
      });
      const button = screen.getByRole("button", { name: /change handle/i });
      await fireEvent.submit(button.closest("form")!);
      await waitFor(() => {
        const toasts = getToasts();
        expect(
          toasts.some((t) =>
            t.type === "success" && /handle.*updated/i.test(t.message)
          ),
        ).toBe(true);
      });
    });
    it("shows error toast when handle change fails", async () => {
      mockEndpoint(
        "com.atproto.identity.updateHandle",
        () =>
          errorResponse("HandleNotAvailable", "Handle is already taken", 400),
      );
      render(Settings);
      await waitFor(() => {
        expect(screen.getByLabelText(/new handle/i)).toBeInTheDocument();
        expect(screen.getByText(/\.test\.tranquil\.dev/i)).toBeInTheDocument();
      });
      const input = screen.getByLabelText(/new handle/i) as HTMLInputElement;
      await fireEvent.input(input, {
        target: { value: "taken" },
      });
      expect(input.value).toBe("taken");
      const button = screen.getByRole("button", { name: /change handle/i });
      await fireEvent.submit(button.closest("form")!);
      await waitFor(() => {
        const errors = getErrorToasts();
        expect(errors.some((e) => /handle is already taken/i.test(e))).toBe(
          true,
        );
      });
    });
  });
  describe("account deletion", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
      mockEndpoint("com.atproto.server.deleteSession", () => jsonResponse({}));
    });
    it("displays delete section with warning and request button", async () => {
      render(Settings);
      await waitFor(() => {
        expect(screen.getByText(/this action is irreversible/i))
          .toBeInTheDocument();
        expect(
          screen.getByRole("button", { name: /request account deletion/i }),
        ).toBeInTheDocument();
      });
    });
    it("calls requestAccountDelete when clicking request", async () => {
      let requestCalled = false;
      mockEndpoint("com.atproto.server.requestAccountDelete", () => {
        requestCalled = true;
        return jsonResponse({});
      });
      render(Settings);
      await waitFor(() => {
        expect(
          screen.getByRole("button", { name: /request account deletion/i }),
        ).toBeInTheDocument();
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /request account deletion/i }),
      );
      await waitFor(() => {
        expect(requestCalled).toBe(true);
      });
    });
    it("shows confirmation form after requesting deletion", async () => {
      mockEndpoint(
        "com.atproto.server.requestAccountDelete",
        () => jsonResponse({}),
      );
      render(Settings);
      await waitFor(() => {
        expect(
          screen.getByRole("button", { name: /request account deletion/i }),
        ).toBeInTheDocument();
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /request account deletion/i }),
      );
      await waitFor(() => {
        expect(screen.getByLabelText(/confirmation code/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/your password/i)).toBeInTheDocument();
        expect(
          screen.getByRole("button", { name: /permanently delete account/i }),
        ).toBeInTheDocument();
      });
    });
    it("shows confirmation dialog before final deletion", async () => {
      const confirmSpy = vi.fn(() => false);
      globalThis.confirm = confirmSpy;
      mockEndpoint(
        "com.atproto.server.requestAccountDelete",
        () => jsonResponse({}),
      );
      render(Settings);
      await waitFor(() => {
        expect(
          screen.getByRole("button", { name: /request account deletion/i }),
        ).toBeInTheDocument();
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /request account deletion/i }),
      );
      await waitFor(() => {
        expect(screen.getByLabelText(/confirmation code/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByLabelText(/confirmation code/i), {
        target: { value: "ABC123" },
      });
      await fireEvent.input(screen.getByLabelText(/your password/i), {
        target: { value: "password" },
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /permanently delete account/i }),
      );
      expect(confirmSpy).toHaveBeenCalledWith(
        expect.stringContaining("absolutely sure"),
      );
    });
    it("calls deleteAccount with correct parameters", async () => {
      globalThis.confirm = vi.fn(() => true);
      let capturedBody: Record<string, string> | null = null;
      mockEndpoint(
        "com.atproto.server.requestAccountDelete",
        () => jsonResponse({}),
      );
      mockEndpoint("com.atproto.server.deleteAccount", (_url, options) => {
        capturedBody = JSON.parse((options?.body as string) || "{}");
        return jsonResponse({});
      });
      render(Settings);
      await waitFor(() => {
        expect(
          screen.getByRole("button", { name: /request account deletion/i }),
        ).toBeInTheDocument();
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /request account deletion/i }),
      );
      await waitFor(() => {
        expect(screen.getByLabelText(/confirmation code/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByLabelText(/confirmation code/i), {
        target: { value: "DEL123" },
      });
      await fireEvent.input(screen.getByLabelText(/your password/i), {
        target: { value: "mypassword" },
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /permanently delete account/i }),
      );
      await waitFor(() => {
        expect(capturedBody?.token).toBe("DEL123");
        expect(capturedBody?.password).toBe("mypassword");
        expect(capturedBody?.did).toBe("did:web:test.tranquil.dev:u:testuser");
      });
    });
    it("navigates to login after successful deletion", async () => {
      globalThis.confirm = vi.fn(() => true);
      mockEndpoint(
        "com.atproto.server.requestAccountDelete",
        () => jsonResponse({}),
      );
      mockEndpoint("com.atproto.server.deleteAccount", () => jsonResponse({}));
      render(Settings);
      await waitFor(() => {
        expect(
          screen.getByRole("button", { name: /request account deletion/i }),
        ).toBeInTheDocument();
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /request account deletion/i }),
      );
      await waitFor(() => {
        expect(screen.getByLabelText(/confirmation code/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByLabelText(/confirmation code/i), {
        target: { value: "DEL123" },
      });
      await fireEvent.input(screen.getByLabelText(/your password/i), {
        target: { value: "password" },
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /permanently delete account/i }),
      );
      await waitFor(() => {
        expect(globalThis.location.pathname).toBe("/app/login");
      });
    });
    it("shows cancel button to return to request state", async () => {
      mockEndpoint(
        "com.atproto.server.requestAccountDelete",
        () => jsonResponse({}),
      );
      render(Settings);
      await waitFor(() => {
        expect(
          screen.getByRole("button", { name: /request account deletion/i }),
        ).toBeInTheDocument();
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /request account deletion/i }),
      );
      await waitFor(() => {
        const cancelButtons = screen.getAllByRole("button", {
          name: /cancel/i,
        });
        expect(cancelButtons.length).toBeGreaterThan(0);
      });
      const deleteHeading = screen.getByRole("heading", {
        name: /delete account/i,
      });
      const deleteSection = deleteHeading.closest("section");
      const cancelButton = deleteSection?.querySelector("button.secondary");
      if (cancelButton) {
        await fireEvent.click(cancelButton);
      }
      await waitFor(() => {
        expect(
          screen.getByRole("button", { name: /request account deletion/i }),
        ).toBeInTheDocument();
      });
    });
    it("shows error toast when deletion fails", async () => {
      globalThis.confirm = vi.fn(() => true);
      mockEndpoint(
        "com.atproto.server.requestAccountDelete",
        () => jsonResponse({}),
      );
      mockEndpoint(
        "com.atproto.server.deleteAccount",
        () => errorResponse("InvalidToken", "Invalid confirmation code", 400),
      );
      render(Settings);
      await waitFor(() => {
        expect(
          screen.getByRole("button", { name: /request account deletion/i }),
        ).toBeInTheDocument();
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /request account deletion/i }),
      );
      await waitFor(() => {
        expect(screen.getByLabelText(/confirmation code/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByLabelText(/confirmation code/i), {
        target: { value: "WRONG" },
      });
      await fireEvent.input(screen.getByLabelText(/your password/i), {
        target: { value: "password" },
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /permanently delete account/i }),
      );
      await waitFor(() => {
        const errors = getErrorToasts();
        expect(errors.some((e) => /invalid confirmation code/i.test(e))).toBe(
          true,
        );
      });
    });
  });
});
