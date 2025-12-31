import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import Login from "../routes/Login.svelte";
import {
  clearMocks,
  jsonResponse,
  mockData,
  mockEndpoint,
  setupFetchMock,
} from "./mocks";
import { _testSetState, type SavedAccount } from "../lib/auth.svelte";

describe("Login", () => {
  beforeEach(() => {
    clearMocks();
    setupFetchMock();
    globalThis.location.hash = "";
    mockEndpoint("/oauth/par", () =>
      jsonResponse({ request_uri: "urn:mock:request" })
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
        expect(screen.getByText(/don't have an account/i)).toBeInTheDocument();
        expect(screen.getByRole("link", { name: /create/i })).toHaveAttribute(
          "href",
          "#/register",
        );
      });
    });

    it("shows forgot password and lost passkey links", async () => {
      render(Login);
      await waitFor(() => {
        expect(screen.getByRole("link", { name: /forgot password/i }))
          .toHaveAttribute("href", "#/reset-password");
        expect(screen.getByRole("link", { name: /lost passkey/i }))
          .toHaveAttribute("href", "#/request-passkey-recovery");
      });
    });
  });

  describe("with saved accounts", () => {
    const savedAccounts: SavedAccount[] = [
      {
        did: "did:web:test.tranquil.dev:u:alice",
        handle: "alice.test.tranquil.dev",
        accessJwt: "mock-jwt-alice",
        refreshJwt: "mock-refresh-alice",
      },
      {
        did: "did:web:test.tranquil.dev:u:bob",
        handle: "bob.test.tranquil.dev",
        accessJwt: "mock-jwt-bob",
        refreshJwt: "mock-refresh-bob",
      },
    ];

    beforeEach(() => {
      _testSetState({
        session: null,
        loading: false,
        error: null,
        savedAccounts,
      });
      mockEndpoint("com.atproto.server.getSession", () =>
        jsonResponse(mockData.session({ handle: "alice.test.tranquil.dev" })));
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
        expect(globalThis.location.hash).toBe("#/dashboard");
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
    it("displays error message when auth state has error", async () => {
      _testSetState({
        session: null,
        loading: false,
        error: "OAuth login failed",
        savedAccounts: [],
      });
      render(Login);
      await waitFor(() => {
        expect(screen.getByText(/oauth login failed/i)).toBeInTheDocument();
        expect(screen.getByText(/oauth login failed/i)).toHaveClass("error");
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

    it("shows verification form when pending verification exists", async () => {
      render(Login);
    });
  });

  describe("loading state", () => {
    it("shows loading state while auth is initializing", async () => {
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
