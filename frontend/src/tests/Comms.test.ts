import { beforeEach, describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import Comms from "../routes/Comms.svelte";
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
describe("Comms", () => {
  beforeEach(() => {
    clearMocks();
    setupDefaultMocks();
  });
  describe("authentication guard", () => {
    it("redirects to login when not authenticated", async () => {
      setupUnauthenticatedUser();
      render(Comms);
      await waitFor(() => {
        expect(globalThis.location.pathname).toBe("/app/login");
      });
    });
  });
  describe("page structure", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
      mockEndpoint(
        "_account.getNotificationPrefs",
        () => jsonResponse(mockData.notificationPrefs()),
      );
      mockEndpoint(
        "com.atproto.server.describeServer",
        () => jsonResponse(mockData.describeServer()),
      );
      mockEndpoint(
        "_account.getNotificationHistory",
        () => jsonResponse({ notifications: [] }),
      );
    });
    it("displays all page elements and sections", async () => {
      render(Comms);
      await waitFor(() => {
        expect(
          screen.getByRole("heading", {
            name: /communication preferences|notification preferences/i,
            level: 1,
          }),
        ).toBeInTheDocument();
        expect(screen.getByRole("link", { name: /dashboard/i }))
          .toHaveAttribute("href", "/app/dashboard");
        expect(screen.getByRole("heading", { name: /preferred channel/i }))
          .toBeInTheDocument();
        expect(screen.getByRole("heading", { name: /channel configuration/i }))
          .toBeInTheDocument();
      });
    });
  });
  describe("loading state", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
      mockEndpoint(
        "com.atproto.server.describeServer",
        () => jsonResponse(mockData.describeServer()),
      );
      mockEndpoint(
        "_account.getNotificationHistory",
        () => jsonResponse({ notifications: [] }),
      );
    });
    it("shows loading skeleton while fetching preferences", () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () =>
          new Promise((resolve) =>
            setTimeout(
              () => resolve(jsonResponse(mockData.notificationPrefs())),
              100,
            )
          ),
      );
      const { container } = render(Comms);
      expect(container.querySelectorAll(".skeleton-section").length)
        .toBeGreaterThan(0);
    });
  });
  describe("channel options", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
      mockEndpoint(
        "com.atproto.server.describeServer",
        () => jsonResponse(mockData.describeServer()),
      );
      mockEndpoint(
        "_account.getNotificationHistory",
        () => jsonResponse({ notifications: [] }),
      );
    });
    it("displays all four channel options", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () => jsonResponse(mockData.notificationPrefs()),
      );
      render(Comms);
      await waitFor(() => {
        expect(screen.getByRole("radio", { name: /email/i }))
          .toBeInTheDocument();
        expect(screen.getByRole("radio", { name: /discord/i }))
          .toBeInTheDocument();
        expect(screen.getByRole("radio", { name: /telegram/i }))
          .toBeInTheDocument();
        expect(screen.getByRole("radio", { name: /signal/i }))
          .toBeInTheDocument();
      });
    });
    it("email channel is always selectable", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () => jsonResponse(mockData.notificationPrefs()),
      );
      render(Comms);
      await waitFor(() => {
        const emailRadio = screen.getByRole("radio", { name: /email/i });
        expect(emailRadio).not.toBeDisabled();
      });
    });
    it("discord channel is disabled when not configured", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () => jsonResponse(mockData.notificationPrefs({ discordId: null })),
      );
      render(Comms);
      await waitFor(() => {
        const discordRadio = screen.getByRole("radio", { name: /discord/i });
        expect(discordRadio).toBeDisabled();
      });
    });
    it("discord channel is enabled when configured", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () =>
          jsonResponse(mockData.notificationPrefs({ discordId: "123456789" })),
      );
      render(Comms);
      await waitFor(() => {
        const discordRadio = screen.getByRole("radio", { name: /discord/i });
        expect(discordRadio).not.toBeDisabled();
      });
    });
    it("shows hint for disabled channels", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () => jsonResponse(mockData.notificationPrefs()),
      );
      render(Comms);
      await waitFor(() => {
        expect(screen.getAllByText(/configure.*to enable/i).length)
          .toBeGreaterThan(0);
      });
    });
    it("selects current preferred channel", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () =>
          jsonResponse(
            mockData.notificationPrefs({ preferredChannel: "email" }),
          ),
      );
      render(Comms);
      await waitFor(() => {
        const emailRadio = screen.getByRole("radio", {
          name: /email/i,
        }) as HTMLInputElement;
        expect(emailRadio.checked).toBe(true);
      });
    });
  });
  describe("channel configuration", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
      mockEndpoint(
        "com.atproto.server.describeServer",
        () => jsonResponse(mockData.describeServer()),
      );
      mockEndpoint(
        "_account.getNotificationHistory",
        () => jsonResponse({ notifications: [] }),
      );
    });
    it("displays email as readonly with current value", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () => jsonResponse(mockData.notificationPrefs()),
      );
      render(Comms);
      await waitFor(() => {
        const emailInput = screen.getByLabelText(
          /^email$/i,
        ) as HTMLInputElement;
        expect(emailInput).toBeDisabled();
        expect(emailInput.value).toBe("test@example.com");
      });
    });
    it("displays all channel inputs with current values", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () =>
          jsonResponse(mockData.notificationPrefs({
            discordId: "123456789",
            telegramUsername: "testuser",
            signalNumber: "+1234567890",
          })),
      );
      render(Comms);
      await waitFor(() => {
        expect(
          (screen.getByLabelText(/discord.*id/i) as HTMLInputElement).value,
        ).toBe("123456789");
        expect(
          (screen.getByLabelText(/telegram.*username/i) as HTMLInputElement)
            .value,
        ).toBe("testuser");
        expect(
          (screen.getByLabelText(/signal.*number/i) as HTMLInputElement)
            .value,
        ).toBe("+1234567890");
      });
    });
  });
  describe("verification status badges", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
      mockEndpoint(
        "com.atproto.server.describeServer",
        () => jsonResponse(mockData.describeServer()),
      );
      mockEndpoint(
        "_account.getNotificationHistory",
        () => jsonResponse({ notifications: [] }),
      );
    });
    it("shows Primary badge for email", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () => jsonResponse(mockData.notificationPrefs()),
      );
      render(Comms);
      await waitFor(() => {
        expect(screen.getByText("Primary")).toBeInTheDocument();
      });
    });
    it("shows Verified badge for verified discord", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () =>
          jsonResponse(mockData.notificationPrefs({
            discordId: "123456789",
            discordVerified: true,
          })),
      );
      render(Comms);
      await waitFor(() => {
        const verifiedBadges = screen.getAllByText("Verified");
        expect(verifiedBadges.length).toBeGreaterThan(0);
      });
    });
    it("shows Not verified badge for unverified discord", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () =>
          jsonResponse(mockData.notificationPrefs({
            discordId: "123456789",
            discordVerified: false,
          })),
      );
      render(Comms);
      await waitFor(() => {
        expect(screen.getByText("Not verified")).toBeInTheDocument();
      });
    });
    it("does not show badge when channel not configured", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () => jsonResponse(mockData.notificationPrefs()),
      );
      render(Comms);
      await waitFor(() => {
        expect(screen.getByText("Primary")).toBeInTheDocument();
        expect(screen.queryByText("Not verified")).not.toBeInTheDocument();
      });
    });
  });
  describe("save preferences", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
      mockEndpoint(
        "com.atproto.server.describeServer",
        () => jsonResponse(mockData.describeServer()),
      );
      mockEndpoint(
        "_account.getNotificationHistory",
        () => jsonResponse({ notifications: [] }),
      );
    });
    it("calls updateNotificationPrefs with correct data", async () => {
      let capturedBody: Record<string, unknown> | null = null;
      mockEndpoint(
        "_account.getNotificationPrefs",
        () => jsonResponse(mockData.notificationPrefs()),
      );
      mockEndpoint(
        "_account.updateNotificationPrefs",
        (_url, options) => {
          capturedBody = JSON.parse((options?.body as string) || "{}");
          return jsonResponse({ success: true });
        },
      );
      render(Comms);
      await waitFor(() => {
        expect(screen.getByLabelText(/discord.*id/i)).toBeInTheDocument();
      });
      await fireEvent.input(screen.getByLabelText(/discord.*id/i), {
        target: { value: "999888777" },
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /save preferences/i }),
      );
      await waitFor(() => {
        expect(capturedBody).not.toBeNull();
        expect(capturedBody?.discordId).toBe("999888777");
        expect(capturedBody?.preferredChannel).toBe("email");
      });
    });
    it("shows loading state while saving", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () => jsonResponse(mockData.notificationPrefs()),
      );
      mockEndpoint("_account.updateNotificationPrefs", async () => {
        await new Promise((resolve) => setTimeout(resolve, 100));
        return jsonResponse({ success: true });
      });
      render(Comms);
      await waitFor(() => {
        expect(screen.getByRole("button", { name: /save preferences/i }))
          .toBeInTheDocument();
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /save preferences/i }),
      );
      expect(screen.getByRole("button", { name: /saving/i }))
        .toBeInTheDocument();
      expect(screen.getByRole("button", { name: /saving/i })).toBeDisabled();
    });
    it("shows success toast after saving", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () => jsonResponse(mockData.notificationPrefs()),
      );
      mockEndpoint(
        "_account.updateNotificationPrefs",
        () => jsonResponse({ success: true }),
      );
      render(Comms);
      await waitFor(() => {
        expect(screen.getByRole("button", { name: /save preferences/i }))
          .toBeInTheDocument();
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /save preferences/i }),
      );
      await waitFor(() => {
        const toasts = getToasts();
        expect(
          toasts.some((t) => t.type === "success" && /saved/i.test(t.message)),
        ).toBe(true);
      });
    });
    it("shows error toast when save fails", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () => jsonResponse(mockData.notificationPrefs()),
      );
      mockEndpoint(
        "_account.updateNotificationPrefs",
        () =>
          errorResponse("InvalidRequest", "Invalid channel configuration", 400),
      );
      render(Comms);
      await waitFor(() => {
        expect(screen.getByRole("button", { name: /save preferences/i }))
          .toBeInTheDocument();
      });
      await fireEvent.click(
        screen.getByRole("button", { name: /save preferences/i }),
      );
      await waitFor(() => {
        const errors = getErrorToasts();
        expect(errors.some((e) => /invalid channel configuration/i.test(e)))
          .toBe(true);
      });
    });
    it("reloads preferences after successful save", async () => {
      let loadCount = 0;
      mockEndpoint("_account.getNotificationPrefs", () => {
        loadCount++;
        return jsonResponse(mockData.notificationPrefs());
      });
      mockEndpoint(
        "_account.updateNotificationPrefs",
        () => jsonResponse({ success: true }),
      );
      render(Comms);
      await waitFor(() => {
        expect(screen.getByRole("button", { name: /save preferences/i }))
          .toBeInTheDocument();
      });
      const initialLoadCount = loadCount;
      await fireEvent.click(
        screen.getByRole("button", { name: /save preferences/i }),
      );
      await waitFor(() => {
        expect(loadCount).toBeGreaterThan(initialLoadCount);
      });
    });
  });
  describe("channel selection interaction", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
      mockEndpoint(
        "com.atproto.server.describeServer",
        () => jsonResponse(mockData.describeServer()),
      );
      mockEndpoint(
        "_account.getNotificationHistory",
        () => jsonResponse({ notifications: [] }),
      );
    });
    it("enables discord channel after entering discord ID", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () => jsonResponse(mockData.notificationPrefs()),
      );
      render(Comms);
      await waitFor(() => {
        expect(screen.getByRole("radio", { name: /discord/i })).toBeDisabled();
      });
      await fireEvent.input(screen.getByLabelText(/discord.*id/i), {
        target: { value: "123456789" },
      });
      await waitFor(() => {
        expect(screen.getByRole("radio", { name: /discord/i })).not
          .toBeDisabled();
      });
    });
    it("allows selecting a configured channel", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () =>
          jsonResponse(mockData.notificationPrefs({
            discordId: "123456789",
            discordVerified: true,
          })),
      );
      render(Comms);
      await waitFor(() => {
        expect(screen.getByRole("radio", { name: /discord/i })).not
          .toBeDisabled();
      });
      await fireEvent.click(screen.getByRole("radio", { name: /discord/i }));
      const discordRadio = screen.getByRole("radio", {
        name: /discord/i,
      }) as HTMLInputElement;
      expect(discordRadio.checked).toBe(true);
    });
  });
  describe("error handling", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
      mockEndpoint(
        "com.atproto.server.describeServer",
        () => jsonResponse(mockData.describeServer()),
      );
      mockEndpoint(
        "_account.getNotificationHistory",
        () => jsonResponse({ notifications: [] }),
      );
    });
    it("shows error toast when loading preferences fails", async () => {
      mockEndpoint(
        "_account.getNotificationPrefs",
        () => errorResponse("InternalError", "Database connection failed", 500),
      );
      render(Comms);
      await waitFor(() => {
        const errors = getErrorToasts();
        expect(errors.some((e) => /database connection failed/i.test(e))).toBe(
          true,
        );
      });
    });
  });
});
