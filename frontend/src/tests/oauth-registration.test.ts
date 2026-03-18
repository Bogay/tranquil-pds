import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/svelte";
import {
  clearMocks,
  jsonResponse,
  mockData,
  mockEndpoint,
  setupFetchMock,
  setupIndexedDBMock,
} from "./mocks.ts";
import { _testSetState } from "../lib/auth.svelte.ts";

describe("OAuth Registration Flow", () => {
  beforeEach(() => {
    clearMocks();
    setupFetchMock();
    setupIndexedDBMock();
    sessionStorage.clear();
    vi.restoreAllMocks();

    Object.defineProperty(globalThis.location, "search", {
      value: "",
      writable: true,
      configurable: true,
    });
    Object.defineProperty(globalThis.location, "pathname", {
      value: "/app/register",
      writable: true,
      configurable: true,
    });
    Object.defineProperty(globalThis.location, "origin", {
      value: "http://localhost:3000",
      writable: true,
      configurable: true,
    });
    Object.defineProperty(globalThis.location, "href", {
      value: "http://localhost:3000/app/register",
      writable: true,
      configurable: true,
    });

    _testSetState({
      session: null,
      loading: false,
      error: null,
      savedAccounts: [],
    });
  });

  describe("startOAuthRegister", () => {
    it("calls PAR endpoint with prompt=create", async () => {
      let capturedBody: string | null = null;

      mockEndpoint("/oauth/par", (_url, options) => {
        capturedBody = options?.body as string;
        return jsonResponse(
          { request_uri: "urn:mock:request", expires_in: 60 },
          201,
        );
      });

      const { startOAuthRegister } = await import("../lib/oauth.ts");

      const hrefSetter = vi.fn();
      Object.defineProperty(globalThis.location, "href", {
        set: hrefSetter,
        get: () => "http://localhost:3000/app/register",
        configurable: true,
      });

      await startOAuthRegister();

      expect(capturedBody).not.toBeNull();
      const params = new URLSearchParams(capturedBody!);
      expect(params.get("prompt")).toBe("create");
      expect(params.get("response_type")).toBe("code");
      expect(params.get("scope")).toContain("atproto");
    });

    it("redirects to authorize endpoint after PAR", async () => {
      mockEndpoint("/oauth/par", () =>
        jsonResponse(
          { request_uri: "urn:mock:test-request-uri", expires_in: 60 },
          201,
        ));

      const { startOAuthRegister } = await import("../lib/oauth.ts");

      let redirectUrl: string | null = null;
      Object.defineProperty(globalThis.location, "href", {
        set: (url: string) => {
          redirectUrl = url;
        },
        get: () => "http://localhost:3000/app/register",
        configurable: true,
      });

      await startOAuthRegister();

      expect(redirectUrl).not.toBeNull();
      expect(redirectUrl).toContain("/oauth/authorize");
      expect(redirectUrl).toContain("request_uri=");
    });
  });

  describe("Register (passkey) component", () => {
    it("adds request_uri to URL when none present", async () => {
      mockEndpoint("/oauth/par", () =>
        jsonResponse(
          { request_uri: "urn:mock:request", expires_in: 60 },
          201,
        ));

      let redirectUrl: string | null = null;
      Object.defineProperty(globalThis.location, "href", {
        set: (url: string) => {
          redirectUrl = url;
        },
        get: () => "http://localhost:3000/app/register",
        configurable: true,
      });

      const Register = (await import("../routes/Register.svelte"))
        .default;
      render(Register);

      await waitFor(
        () => {
          expect(redirectUrl).not.toBeNull();
        },
        { timeout: 2000 },
      );

      expect(redirectUrl).toContain("request_uri=");
    });

    it("shows loading state while fetching request_uri", async () => {
      mockEndpoint("/oauth/par", () =>
        jsonResponse(
          { request_uri: "urn:mock:request", expires_in: 60 },
          201,
        ));

      Object.defineProperty(globalThis.location, "href", {
        set: () => {},
        get: () => "http://localhost:3000/app/register",
        configurable: true,
      });

      const Register = (await import("../routes/Register.svelte"))
        .default;
      const { container } = render(Register);

      await waitFor(() => {
        expect(container.querySelector(".loading")).toBeInTheDocument();
      });
    });

    it("logs error if OAuth initiation fails", async () => {
      mockEndpoint(
        "/oauth/par",
        () =>
          jsonResponse({
            error: "invalid_request",
            error_description: "Test error",
          }, 400),
      );

      const consoleSpy = vi.spyOn(console, "error").mockImplementation(
        () => {},
      );

      Object.defineProperty(globalThis.location, "href", {
        set: () => {},
        get: () => "http://localhost:3000/app/register",
        configurable: true,
      });

      const Register = (await import("../routes/Register.svelte"))
        .default;
      render(Register);

      await waitFor(
        () => {
          expect(consoleSpy).toHaveBeenCalledWith(
            expect.stringContaining("Failed to ensure OAuth request URI"),
            expect.anything(),
          );
        },
        { timeout: 2000 },
      );

      consoleSpy.mockRestore();
    });
  });

  describe("RegisterPassword component", () => {
    it("adds request_uri to URL when none present", async () => {
      mockEndpoint("/oauth/par", () =>
        jsonResponse(
          { request_uri: "urn:mock:request", expires_in: 60 },
          201,
        ));

      Object.defineProperty(globalThis.location, "pathname", {
        value: "/app/oauth/register-password",
        writable: true,
        configurable: true,
      });

      let redirectUrl: string | null = null;
      Object.defineProperty(globalThis.location, "href", {
        set: (url: string) => {
          redirectUrl = url;
        },
        get: () => "http://localhost:3000/app/oauth/register-password",
        configurable: true,
      });

      const RegisterPassword =
        (await import("../routes/Register.svelte")).default;
      render(RegisterPassword);

      await waitFor(
        () => {
          expect(redirectUrl).not.toBeNull();
        },
        { timeout: 2000 },
      );

      expect(redirectUrl).toContain("request_uri=");
    });

    it("renders form when request_uri is present", async () => {
      Object.defineProperty(globalThis.location, "search", {
        value: "?request_uri=urn:mock:test-request",
        writable: true,
        configurable: true,
      });
      Object.defineProperty(globalThis.location, "pathname", {
        value: "/app/oauth/register-password",
        writable: true,
        configurable: true,
      });

      mockEndpoint(
        "com.atproto.server.describeServer",
        () => jsonResponse(mockData.describeServer()),
      );
      mockEndpoint(
        "/oauth/sso/providers",
        () => jsonResponse({ providers: [] }),
      );

      const RegisterPassword =
        (await import("../routes/Register.svelte")).default;
      render(RegisterPassword);

      await waitFor(() => {
        expect(screen.getByLabelText(/handle/i)).toBeInTheDocument();
      });
    });
  });

  describe("RegisterSso component", () => {
    it("adds request_uri to URL when none present", async () => {
      mockEndpoint("/oauth/par", () =>
        jsonResponse(
          { request_uri: "urn:mock:request", expires_in: 60 },
          201,
        ));

      Object.defineProperty(globalThis.location, "pathname", {
        value: "/app/register-sso",
        writable: true,
        configurable: true,
      });

      let redirectUrl: string | null = null;
      Object.defineProperty(globalThis.location, "href", {
        set: (url: string) => {
          redirectUrl = url;
        },
        get: () => "http://localhost:3000/app/register-sso",
        configurable: true,
      });

      const RegisterSso =
        (await import("../routes/RegisterSso.svelte")).default;
      render(RegisterSso);

      await waitFor(
        () => {
          expect(redirectUrl).not.toBeNull();
        },
        { timeout: 2000 },
      );

      expect(redirectUrl).toContain("request_uri=");
    });

    it("renders SSO providers when request_uri is present", async () => {
      Object.defineProperty(globalThis.location, "search", {
        value: "?request_uri=urn:mock:test-request",
        writable: true,
        configurable: true,
      });
      Object.defineProperty(globalThis.location, "pathname", {
        value: "/app/register-sso",
        writable: true,
        configurable: true,
      });

      mockEndpoint("/oauth/sso/providers", () =>
        jsonResponse({
          providers: [{ provider: "google", name: "Google", icon: "google" }],
        }));

      const RegisterSso =
        (await import("../routes/RegisterSso.svelte")).default;
      render(RegisterSso);

      await waitFor(() => {
        expect(screen.getByText(/google/i)).toBeInTheDocument();
      });
    });

    it("passes request_uri when initiating SSO registration", async () => {
      Object.defineProperty(globalThis.location, "search", {
        value: "?request_uri=urn:mock:test-request-uri",
        writable: true,
        configurable: true,
      });
      Object.defineProperty(globalThis.location, "pathname", {
        value: "/app/register-sso",
        writable: true,
        configurable: true,
      });

      mockEndpoint("/oauth/sso/providers", () =>
        jsonResponse({
          providers: [{ provider: "google", name: "Google", icon: "google" }],
        }));

      let capturedBody: string | null = null;
      mockEndpoint("/oauth/sso/initiate", (_url, options) => {
        capturedBody = options?.body as string;
        return jsonResponse({ redirect_url: "https://google.com/oauth" });
      });

      Object.defineProperty(globalThis.location, "href", {
        set: () => {},
        get: () =>
          "http://localhost:3000/app/register-sso?request_uri=urn:mock:test-request-uri",
        configurable: true,
      });

      const RegisterSso =
        (await import("../routes/RegisterSso.svelte")).default;
      render(RegisterSso);

      await waitFor(() => {
        expect(screen.getByText(/google/i)).toBeInTheDocument();
      });

      const googleButton = screen.getByRole("button", { name: /google/i });
      googleButton.click();

      await waitFor(() => {
        expect(capturedBody).not.toBeNull();
      });

      const body = JSON.parse(capturedBody!);
      expect(body.request_uri).toBe("urn:mock:test-request-uri");
      expect(body.action).toBe("register");
    });
  });

  describe("AccountTypeSwitcher with OAuth context", () => {
    it("preserves request_uri in links when oauthRequestUri is provided", async () => {
      const AccountTypeSwitcher = (
        await import("../components/AccountTypeSwitcher.svelte")
      ).default;

      render(AccountTypeSwitcher, {
        props: {
          active: "passkey",
          ssoAvailable: true,
          oauthRequestUri: "urn:mock:test-request-uri",
        },
      });

      const passwordLink = screen.getByText(/password/i).closest("a");
      const ssoLink = screen.getByText(/sso/i).closest("a");

      expect(passwordLink?.getAttribute("href")).toContain("request_uri=");
      expect(passwordLink?.getAttribute("href")).toContain(
        encodeURIComponent("urn:mock:test-request-uri"),
      );
      expect(ssoLink?.getAttribute("href")).toContain("request_uri=");
    });

    it("uses oauth routes without request_uri when no oauthRequestUri provided", async () => {
      const AccountTypeSwitcher = (
        await import("../components/AccountTypeSwitcher.svelte")
      ).default;

      render(AccountTypeSwitcher, {
        props: {
          active: "passkey",
          ssoAvailable: true,
        },
      });

      const passwordLink = screen.getByText(/password/i).closest("a");
      expect(passwordLink?.getAttribute("href")).toBe(
        "/app/oauth/register-password",
      );
      expect(passwordLink?.getAttribute("href")).not.toContain("request_uri=");
    });

    it("passkey link goes to oauth/register when in OAuth context", async () => {
      const AccountTypeSwitcher = (
        await import("../components/AccountTypeSwitcher.svelte")
      ).default;

      render(AccountTypeSwitcher, {
        props: {
          active: "password",
          ssoAvailable: true,
          oauthRequestUri: "urn:mock:test-request-uri",
        },
      });

      const passkeyLink = screen.getByText(/passkey/i).closest("a");
      expect(passkeyLink?.getAttribute("href")).toContain("/oauth/register");
      expect(passkeyLink?.getAttribute("href")).toContain("request_uri=");
    });
  });

  describe("Register component (OAuth context)", () => {
    beforeEach(() => {
      Object.defineProperty(globalThis.location, "search", {
        value: "?request_uri=urn:mock:test-request",
        writable: true,
        configurable: true,
      });
      Object.defineProperty(globalThis.location, "pathname", {
        value: "/app/oauth/register",
        writable: true,
        configurable: true,
      });

      mockEndpoint(
        "com.atproto.server.describeServer",
        () => jsonResponse(mockData.describeServer()),
      );
      mockEndpoint(
        "/oauth/sso/providers",
        () => jsonResponse({ providers: [] }),
      );
      mockEndpoint(
        "/oauth/authorize",
        () => jsonResponse({ client_name: "Test App" }),
      );
    });

    it("renders registration form with AccountTypeSwitcher", async () => {
      const Register = (await import("../routes/Register.svelte"))
        .default;
      render(Register);

      await waitFor(() => {
        const switcher = document.querySelector(".account-type-switcher");
        expect(switcher).toBeInTheDocument();
        expect(switcher?.textContent).toContain("Passkey");
        expect(switcher?.textContent).toContain("Password");
      });
    });

    it("displays client name in subtitle when available", async () => {
      mockEndpoint(
        "/oauth/authorize",
        () => jsonResponse({ client_name: "Awesome App" }),
      );

      const Register = (await import("../routes/Register.svelte"))
        .default;
      render(Register);

      await waitFor(() => {
        expect(screen.getByText(/awesome app/i)).toBeInTheDocument();
      });
    });

    it("shows handle input field", async () => {
      const Register = (await import("../routes/Register.svelte"))
        .default;
      render(Register);

      await waitFor(() => {
        expect(screen.getByLabelText(/handle/i)).toBeInTheDocument();
      });
    });
  });
});
