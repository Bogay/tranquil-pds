import { vi } from "vitest";
import type { AppPassword, InviteCode, Session } from "../lib/api";
import { _testSetState } from "../lib/auth.svelte";
export interface MockResponse {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}
export type MockHandler = (
  url: string,
  options?: RequestInit,
) => MockResponse | Promise<MockResponse>;
const mockHandlers: Map<string, MockHandler> = new Map();
export function mockEndpoint(endpoint: string, handler: MockHandler): void {
  mockHandlers.set(endpoint, handler);
}
export function mockEndpointOnce(endpoint: string, handler: MockHandler): void {
  const originalHandler = mockHandlers.get(endpoint);
  mockHandlers.set(endpoint, (url, options) => {
    mockHandlers.set(endpoint, originalHandler!);
    return handler(url, options);
  });
}
export function clearMocks(): void {
  mockHandlers.clear();
}
function extractEndpoint(url: string): string {
  const match = url.match(/\/xrpc\/([^?]+)/);
  return match ? match[1] : url;
}
export function setupFetchMock(): void {
  global.fetch = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      const endpoint = extractEndpoint(url);
      const handler = mockHandlers.get(endpoint);
      if (handler) {
        const result = await handler(url, init);
        return {
          ok: result.ok,
          status: result.status,
          json: result.json,
          text: async () => JSON.stringify(await result.json()),
          headers: new Headers(),
          redirected: false,
          statusText: result.ok ? "OK" : "Error",
          type: "basic",
          url,
          clone: () => ({ ...result }) as Response,
          body: null,
          bodyUsed: false,
          arrayBuffer: async () => new ArrayBuffer(0),
          blob: async () => new Blob(),
          formData: async () => new FormData(),
        } as Response;
      }
      return {
        ok: false,
        status: 404,
        json: async () => ({
          error: "NotFound",
          message: `No mock for ${endpoint}`,
        }),
        text: async () =>
          JSON.stringify({
            error: "NotFound",
            message: `No mock for ${endpoint}`,
          }),
        headers: new Headers(),
        redirected: false,
        statusText: "Not Found",
        type: "basic",
        url,
        clone: function () {
          return this;
        },
        body: null,
        bodyUsed: false,
        arrayBuffer: async () => new ArrayBuffer(0),
        blob: async () => new Blob(),
        formData: async () => new FormData(),
      } as Response;
    },
  );
}
export function jsonResponse<T>(data: T, status = 200): MockResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => data,
  };
}
export function errorResponse(
  error: string,
  message: string,
  status = 400,
): MockResponse {
  return {
    ok: false,
    status,
    json: async () => ({ error, message }),
  };
}
export const mockData = {
  session: (overrides?: Partial<Session>): Session => ({
    did: "did:web:test.tranquil.dev:u:testuser",
    handle: "testuser.test.tranquil.dev",
    email: "test@example.com",
    emailConfirmed: true,
    accessJwt: "mock-access-jwt-token",
    refreshJwt: "mock-refresh-jwt-token",
    ...overrides,
  }),
  appPassword: (overrides?: Partial<AppPassword>): AppPassword => ({
    name: "Test App",
    createdAt: new Date().toISOString(),
    ...overrides,
  }),
  inviteCode: (overrides?: Partial<InviteCode>): InviteCode => ({
    code: "test-invite-123",
    available: 1,
    disabled: false,
    forAccount: "did:web:test.tranquil.dev:u:testuser",
    createdBy: "did:web:test.tranquil.dev:u:testuser",
    createdAt: new Date().toISOString(),
    uses: [],
    ...overrides,
  }),
  notificationPrefs: (overrides?: Record<string, unknown>) => ({
    preferredChannel: "email",
    email: "test@example.com",
    discordId: null,
    discordVerified: false,
    telegramUsername: null,
    telegramVerified: false,
    signalNumber: null,
    signalVerified: false,
    ...overrides,
  }),
  describeServer: () => ({
    availableUserDomains: ["test.tranquil.dev"],
    inviteCodeRequired: false,
    links: {
      privacyPolicy: "https://example.com/privacy",
      termsOfService: "https://example.com/tos",
    },
    selfHostedDidWebEnabled: true,
  }),
  describeRepo: (did: string) => ({
    handle: "testuser.test.tranquil.dev",
    did,
    didDoc: {},
    collections: [
      "app.bsky.feed.post",
      "app.bsky.feed.like",
      "app.bsky.graph.follow",
    ],
    handleIsCorrect: true,
  }),
};
export function setupDefaultMocks(): void {
  setupFetchMock();
  mockEndpoint(
    "com.atproto.server.getSession",
    () => jsonResponse(mockData.session()),
  );
  mockEndpoint("com.atproto.server.createSession", (_url, options) => {
    const body = JSON.parse((options?.body as string) || "{}");
    if (body.identifier && body.password === "correctpassword") {
      return jsonResponse(
        mockData.session({ handle: body.identifier.replace("@", "") }),
      );
    }
    return errorResponse(
      "AuthenticationRequired",
      "Invalid identifier or password",
      401,
    );
  });
  mockEndpoint(
    "com.atproto.server.refreshSession",
    () => jsonResponse(mockData.session()),
  );
  mockEndpoint("com.atproto.server.deleteSession", () => jsonResponse({}));
  mockEndpoint(
    "com.atproto.server.listAppPasswords",
    () => jsonResponse({ passwords: [mockData.appPassword()] }),
  );
  mockEndpoint("com.atproto.server.createAppPassword", (_url, options) => {
    const body = JSON.parse((options?.body as string) || "{}");
    return jsonResponse({
      name: body.name,
      password: "xxxx-xxxx-xxxx-xxxx",
      createdAt: new Date().toISOString(),
    });
  });
  mockEndpoint("com.atproto.server.revokeAppPassword", () => jsonResponse({}));
  mockEndpoint(
    "com.atproto.server.getAccountInviteCodes",
    () => jsonResponse({ codes: [mockData.inviteCode()] }),
  );
  mockEndpoint(
    "com.atproto.server.createInviteCode",
    () => jsonResponse({ code: "new-invite-" + Date.now() }),
  );
  mockEndpoint(
    "com.tranquil.account.getNotificationPrefs",
    () => jsonResponse(mockData.notificationPrefs()),
  );
  mockEndpoint(
    "com.tranquil.account.updateNotificationPrefs",
    () => jsonResponse({ success: true }),
  );
  mockEndpoint(
    "com.atproto.server.requestEmailUpdate",
    () => jsonResponse({ tokenRequired: true }),
  );
  mockEndpoint("com.atproto.server.updateEmail", () => jsonResponse({}));
  mockEndpoint("com.atproto.identity.updateHandle", () => jsonResponse({}));
  mockEndpoint(
    "com.atproto.server.requestAccountDelete",
    () => jsonResponse({}),
  );
  mockEndpoint("com.atproto.server.deleteAccount", () => jsonResponse({}));
  mockEndpoint(
    "com.atproto.server.describeServer",
    () => jsonResponse(mockData.describeServer()),
  );
  mockEndpoint("com.atproto.repo.describeRepo", (url) => {
    const params = new URLSearchParams(url.split("?")[1]);
    const repo = params.get("repo") || "did:web:test";
    return jsonResponse(mockData.describeRepo(repo));
  });
  mockEndpoint(
    "com.atproto.repo.listRecords",
    () => jsonResponse({ records: [] }),
  );
}
export function setupAuthenticatedUser(
  sessionOverrides?: Partial<Session>,
): Session {
  const session = mockData.session(sessionOverrides);
  _testSetState({
    session,
    loading: false,
    error: null,
  });
  return session;
}
export function setupUnauthenticatedUser(): void {
  _testSetState({
    session: null,
    loading: false,
    error: null,
  });
}
