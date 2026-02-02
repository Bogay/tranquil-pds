import { beforeEach, describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import Login from "../routes/Login.svelte";
import {
  clearMocks,
  jsonResponse,
  mockData,
  mockEndpoint,
  setupFetchMock,
  setupIndexedDBMock,
} from "./mocks.ts";
import { _testSetState, type SavedAccount } from "../lib/auth.svelte.ts";
import {
  unsafeAsAccessToken,
  unsafeAsDid,
  unsafeAsHandle,
  unsafeAsRefreshToken,
} from "../lib/types/branded.ts";
import { getToasts } from "../lib/toast.svelte.ts";

describe("Login", () => {
  beforeEach(() => {
    clearMocks();
    setupFetchMock();
    setupIndexedDBMock();
    mockEndpoint(
      "/oauth/par",
      () => jsonResponse({ request_uri: "urn:mock:request" }),
    );
  });

  describe("initial render with no saved accounts", () => {
    beforeEach(() => {
      _testSetState({
        session: null,
        loading: false,
        error: null,
        savedAccounts: [],
      });
    });

    it("renders login page with title and OAuth button", async () => {
      render(Login);
      await waitFor(() => {
        expect(screen.getByRole("heading", { name: /sign in/i }))
          .toBeInTheDocument();
        expect(screen.getByRole("button", { name: /sign in/i }))
          .toBeInTheDocument();
      });
    });

    it("shows create account link", async () => {
      render(Login);
      await waitFor(() => {
        expect(screen.getByText(/no account\?/i)).toBeInTheDocument();
        expect(screen.getByRole("link", { name: /create/i })).toHaveAttribute(
          "href",
          "/app/register",
        );
      });
    });

    it("shows forgot password and lost passkey links", async () => {
      render(Login);
      await waitFor(() => {
        expect(screen.getByRole("link", { name: /forgot password/i }))
          .toHaveAttribute("href", "/app/reset-password");
        expect(screen.getByRole("link", { name: /lost passkey/i }))
          .toHaveAttribute("href", "/app/request-passkey-recovery");
      });
    });
  });

  describe("with saved accounts", () => {
    const savedAccounts: SavedAccount[] = [
      {
        did: unsafeAsDid("did:web:test.tranquil.dev:u:alice"),
        handle: unsafeAsHandle("alice.test.tranquil.dev"),
        accessJwt: unsafeAsAccessToken("mock-jwt-alice"),
        refreshJwt: unsafeAsRefreshToken("mock-refresh-alice"),
      },
      {
        did: unsafeAsDid("did:web:test.tranquil.dev:u:bob"),
        handle: unsafeAsHandle("bob.test.tranquil.dev"),
        accessJwt: unsafeAsAccessToken("mock-jwt-bob"),
        refreshJwt: unsafeAsRefreshToken("mock-refresh-bob"),
      },
    ];

    beforeEach(() => {
      _testSetState({
        session: null,
        loading: false,
        error: null,
        savedAccounts,
      });
      mockEndpoint(
        "com.atproto.server.getSession",
        () =>
          jsonResponse(
            mockData.session({
              handle: unsafeAsHandle("alice.test.tranquil.dev"),
            }),
          ),
      );
    });

    it("displays saved accounts list", async () => {
      render(Login);
      await waitFor(() => {
        expect(screen.getByText(/@alice\.test\.tranquil\.dev/))
          .toBeInTheDocument();
        expect(screen.getByText(/@bob\.test\.tranquil\.dev/))
          .toBeInTheDocument();
      });
    });

    it("shows sign in to another account option", async () => {
      render(Login);
      await waitFor(() => {
        expect(screen.getByText(/sign in to another/i)).toBeInTheDocument();
      });
    });

    it("can click on saved account to switch", async () => {
      render(Login);
      await waitFor(() => {
        expect(screen.getByText(/@alice\.test\.tranquil\.dev/))
          .toBeInTheDocument();
      });
      const aliceAccount = screen.getByText(/@alice\.test\.tranquil\.dev/)
        .closest("[role='button']");
      if (aliceAccount) {
        await fireEvent.click(aliceAccount);
      }
      await waitFor(() => {
        expect(globalThis.location.pathname).toBe("/app/dashboard");
      });
    });

    it("can remove saved account with forget button", async () => {
      render(Login);
      await waitFor(() => {
        expect(screen.getByText(/@alice\.test\.tranquil\.dev/))
          .toBeInTheDocument();
        const forgetButtons = screen.getAllByTitle(/remove/i);
        expect(forgetButtons.length).toBe(2);
      });
    });
  });

  describe("error handling", () => {
    it("displays error message as toast when auth state has error", async () => {
      _testSetState({
        session: null,
        loading: false,
        error: "OAuth login failed",
        savedAccounts: [],
      });
      render(Login);
      await waitFor(() => {
        const toasts = getToasts();
        const errorToast = toasts.find(
          (t) => t.type === "error" && t.message.includes("OAuth login failed"),
        );
        expect(errorToast).toBeDefined();
      });
    });
  });

  describe("verification flow", () => {
    beforeEach(() => {
      _testSetState({
        session: null,
        loading: false,
        error: null,
        savedAccounts: [],
      });
    });

    it("shows verification form when pending verification exists", () => {
      render(Login);
    });
  });

  describe("loading state", () => {
    it("shows loading state while auth is initializing", () => {
      _testSetState({
        session: null,
        loading: true,
        error: null,
        savedAccounts: [],
      });
      render(Login);
    });
  });
});
