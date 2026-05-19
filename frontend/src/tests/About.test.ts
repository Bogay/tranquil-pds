import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import AboutContent from "../components/dashboard/AboutContent.svelte";
import {
  clearMocks,
  jsonResponse,
  mockData,
  mockEndpoint,
  setupAuthenticatedUser,
  setupFetchMock,
  setupIndexedDBMock,
} from "./mocks.ts";

describe("AboutContent", () => {
  let session: ReturnType<typeof setupAuthenticatedUser>;

  beforeEach(() => {
    clearMocks();
    setupFetchMock();
    setupIndexedDBMock();
    session = setupAuthenticatedUser();
    mockEndpoint("com.atproto.server.describeServer", () =>
      jsonResponse(
        mockData.describeServer({ version: "0.4.59" }),
      ),
    );
    mockEndpoint("_server.getConfig", () =>
      jsonResponse({
        serverName: "Test PDS",
        primaryColor: null,
        primaryColorDark: null,
        secondaryColor: null,
        secondaryColorDark: null,
        logoCid: null,
      }),
    );
  });

  it("displays account information from session", async () => {
    render(AboutContent, { props: { session } });
    await waitFor(() => {
      expect(
        screen.getByText("did:web:test.tranquil.dev:u:testuser"),
      ).toBeInTheDocument();
      expect(
        screen.getByText("testuser.test.tranquil.dev"),
      ).toBeInTheDocument();
    });
  });

  it("displays PDS version from server description", async () => {
    render(AboutContent, { props: { session } });
    await waitFor(() => {
      expect(screen.getByText("0.4.59")).toBeInTheDocument();
    });
  });

  it("displays environment information", async () => {
    render(AboutContent, { props: { session } });
    await waitFor(() => {
      expect(screen.getByText(/User Agent/i)).toBeInTheDocument();
      expect(screen.getByText(/Locale/i)).toBeInTheDocument();
      expect(screen.getByText(/Screen Size/i)).toBeInTheDocument();
    });
  });

  it("shows section headings", async () => {
    render(AboutContent, { props: { session } });
    await waitFor(() => {
      expect(screen.getByText("Server")).toBeInTheDocument();
      expect(screen.getByText("Contact & Policies")).toBeInTheDocument();
      expect(screen.getByText("Account")).toBeInTheDocument();
      expect(screen.getByText("Environment")).toBeInTheDocument();
    });
  });

  it("shows unknown when PDS version is not available", async () => {
    mockEndpoint("com.atproto.server.describeServer", () =>
      jsonResponse(mockData.describeServer()),
    );
    render(AboutContent, { props: { session } });
    await waitFor(() => {
      expect(screen.getByText("Unknown")).toBeInTheDocument();
    });
  });

  it("has a copy debug info button", async () => {
    render(AboutContent, { props: { session } });
    await waitFor(() => {
      expect(
        screen.getByRole("button", { name: /copy debug info/i }),
      ).toBeInTheDocument();
    });
  });

  it("copies debug info to clipboard on button click", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      writable: true,
      configurable: true,
    });

    render(AboutContent, { props: { session } });

    await waitFor(() => {
      expect(screen.getByText("0.4.59")).toBeInTheDocument();
    });

    await fireEvent.click(
      screen.getByRole("button", { name: /copy debug info/i }),
    );

    await waitFor(() => {
      expect(writeText).toHaveBeenCalledOnce();
      const copied = writeText.mock.calls[0][0] as string;
      expect(copied).toContain("Tranquil Debug Info");
      expect(copied).toContain("did:web:test.tranquil.dev:u:testuser");
      expect(copied).toContain("testuser.test.tranquil.dev");
      expect(copied).toContain("Server DID: did:web:test.tranquil.dev");
      expect(copied).toContain("Contact Email: admin@test.tranquil.dev");
      expect(copied).toContain("Privacy Policy: https://example.com/privacy");
      expect(copied).not.toContain("Discord Bot");
    });
  });

  it("displays admin status correctly for admin users", async () => {
    clearMocks();
    setupFetchMock();
    session = setupAuthenticatedUser({ isAdmin: true });
    mockEndpoint("com.atproto.server.describeServer", () =>
      jsonResponse(mockData.describeServer({ version: "0.4.59" })),
    );
    mockEndpoint("_admin.getServerStats", () =>
      jsonResponse(mockData.serverStats()),
    );

    render(AboutContent, { props: { session } });
    await waitFor(() => {
      expect(screen.getByText("Yes")).toBeInTheDocument();
    });
  });

  it("displays admin status correctly for non-admin users", async () => {
    render(AboutContent, { props: { session } });
    await waitFor(() => {
      const noElements = screen.getAllByText("No");
      expect(noElements.length).toBeGreaterThanOrEqual(1);
    });
  });

  it("displays server DID", async () => {
    render(AboutContent, { props: { session } });
    await waitFor(() => {
      expect(screen.getByText("did:web:test.tranquil.dev")).toBeInTheDocument();
    });
  });

  it("displays invite code and DID:web status", async () => {
    render(AboutContent, { props: { session } });
    await waitFor(() => {
      const noElements = screen.getAllByText("No");
      expect(noElements.length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText("Enabled")).toBeInTheDocument();
    });
  });

  it("displays contact email and policy links", async () => {
    render(AboutContent, { props: { session } });
    await waitFor(() => {
      expect(screen.getByText("admin@test.tranquil.dev")).toBeInTheDocument();
      const privacyLink = screen.getByRole("link", { name: "https://example.com/privacy" });
      expect(privacyLink).toHaveAttribute("href", "https://example.com/privacy");
      expect(privacyLink).toHaveAttribute("target", "_blank");
      const tosLink = screen.getByRole("link", { name: "https://example.com/tos" });
      expect(tosLink).toHaveAttribute("href", "https://example.com/tos");
      expect(tosLink).toHaveAttribute("target", "_blank");
    });
  });

  it("displays communication channels and bot info for admins", async () => {
    clearMocks();
    setupFetchMock();
    const adminSession = setupAuthenticatedUser({ isAdmin: true });
    mockEndpoint("com.atproto.server.describeServer", () =>
      jsonResponse(mockData.describeServer({ version: "0.4.59" })),
    );
    mockEndpoint("_admin.getServerStats", () =>
      jsonResponse(mockData.serverStats()),
    );

    render(AboutContent, { props: { session: adminSession } });
    await waitFor(() => {
      expect(screen.getByText("Communication")).toBeInTheDocument();
      expect(screen.getByText("email, discord, telegram, signal")).toBeInTheDocument();
      expect(screen.getByText("test-bot")).toBeInTheDocument();
      expect(screen.getByText("123456789")).toBeInTheDocument();
      expect(screen.getByText("test_tg_bot")).toBeInTheDocument();
      expect(screen.getByText("42")).toBeInTheDocument();
    });
  });

  it("hides admin-only sections for non-admins", async () => {
    render(AboutContent, { props: { session } });
    await waitFor(() => {
      expect(screen.getByText("Server")).toBeInTheDocument();
    });
    expect(screen.queryByText("Communication")).not.toBeInTheDocument();
    expect(screen.queryByText("Frontend")).not.toBeInTheDocument();
  });

  it("shows 'Not configured' for missing optional fields", async () => {
    mockEndpoint("com.atproto.server.describeServer", () =>
      jsonResponse(
        mockData.describeServer({
          contact: {},
          links: {},
          discordBotUsername: undefined,
          discordAppId: undefined,
          telegramBotUsername: undefined,
        }),
      ),
    );
    render(AboutContent, { props: { session } });
    await waitFor(() => {
      const notConfigured = screen.getAllByText("Not configured");
      expect(notConfigured.length).toBe(3);
    });
  });
});
