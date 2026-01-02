import { beforeEach, describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import Dashboard from "../routes/Dashboard.svelte";
import {
  clearMocks,
  jsonResponse,
  mockData,
  mockEndpoint,
  setupAuthenticatedUser,
  setupFetchMock,
  setupUnauthenticatedUser,
} from "./mocks";
const STORAGE_KEY = "tranquil_pds_session";
describe("Dashboard", () => {
  beforeEach(() => {
    clearMocks();
    setupFetchMock();
  });
  describe("authentication guard", () => {
    it("redirects to login when not authenticated", async () => {
      setupUnauthenticatedUser();
      render(Dashboard);
      await waitFor(() => {
        expect(globalThis.location.pathname).toBe("/app/login");
      });
    });
    it("shows loading state while checking auth", () => {
      render(Dashboard);
      expect(screen.getByText(/loading/i)).toBeInTheDocument();
    });
  });
  describe("authenticated view", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
    });
    it("displays user account info and page structure", async () => {
      render(Dashboard);
      await waitFor(() => {
        expect(screen.getByRole("heading", { name: /dashboard/i }))
          .toBeInTheDocument();
        expect(screen.getByRole("heading", { name: /account overview/i }))
          .toBeInTheDocument();
        expect(screen.getAllByText(/@testuser\.test\.tranquil\.dev/).length)
          .toBeGreaterThan(0);
        expect(screen.getByText(/did:web:test\.tranquil\.dev:u:testuser/))
          .toBeInTheDocument();
        expect(screen.getByText("test@example.com")).toBeInTheDocument();
        expect(screen.getByText("Verified")).toBeInTheDocument();
        expect(screen.getByText("Verified")).toHaveClass("badge", "success");
      });
    });
    it("displays unverified badge when email not confirmed", async () => {
      setupAuthenticatedUser({ emailConfirmed: false });
      render(Dashboard);
      await waitFor(() => {
        expect(screen.getByText("Unverified")).toBeInTheDocument();
        expect(screen.getByText("Unverified")).toHaveClass("badge", "warning");
      });
    });
    it("displays all navigation cards", async () => {
      render(Dashboard);
      await waitFor(() => {
        const navCards = [
          { name: /app passwords/i, href: "/app/app-passwords" },
          { name: /account settings/i, href: "/app/settings" },
          { name: /communication preferences/i, href: "/app/comms" },
          { name: /repository explorer/i, href: "/app/repo" },
        ];
        for (const { name, href } of navCards) {
          const card = screen.getByRole("link", { name });
          expect(card).toBeInTheDocument();
          expect(card).toHaveAttribute("href", href);
        }
      });
    });
    it("displays invite codes card when invites are required and user is admin", async () => {
      setupAuthenticatedUser({ isAdmin: true });
      mockEndpoint(
        "com.atproto.server.describeServer",
        () =>
          jsonResponse(mockData.describeServer({ inviteCodeRequired: true })),
      );
      render(Dashboard);
      await waitFor(() => {
        const inviteCard = screen.getByRole("link", { name: /invite codes/i });
        expect(inviteCard).toBeInTheDocument();
        expect(inviteCard).toHaveAttribute("href", "/app/invite-codes");
      });
    });
  });
  describe("logout functionality", () => {
    beforeEach(() => {
      setupAuthenticatedUser();
      localStorage.setItem(STORAGE_KEY, JSON.stringify(mockData.session()));
      mockEndpoint("/oauth/revoke", () => jsonResponse({}));
    });
    it("calls oauth revoke and navigates to login on logout", async () => {
      let revokeCalled = false;
      mockEndpoint("/oauth/revoke", () => {
        revokeCalled = true;
        return jsonResponse({});
      });
      render(Dashboard);
      await waitFor(() => {
        expect(screen.getByRole("button", { name: /@testuser/i }))
          .toBeInTheDocument();
      });
      await fireEvent.click(screen.getByRole("button", { name: /@testuser/i }));
      await waitFor(() => {
        expect(screen.getByRole("button", { name: /sign out/i }))
          .toBeInTheDocument();
      });
      await fireEvent.click(screen.getByRole("button", { name: /sign out/i }));
      await waitFor(() => {
        expect(revokeCalled).toBe(true);
        expect(globalThis.location.pathname).toBe("/app/login");
      });
    });
    it("clears session from localStorage after logout", async () => {
      const storedSession = localStorage.getItem(STORAGE_KEY);
      expect(storedSession).not.toBeNull();
      render(Dashboard);
      await waitFor(() => {
        expect(screen.getByRole("button", { name: /@testuser/i }))
          .toBeInTheDocument();
      });
      await fireEvent.click(screen.getByRole("button", { name: /@testuser/i }));
      await waitFor(() => {
        expect(screen.getByRole("button", { name: /sign out/i }))
          .toBeInTheDocument();
      });
      await fireEvent.click(screen.getByRole("button", { name: /sign out/i }));
      await waitFor(() => {
        expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
      });
    });
  });
});
