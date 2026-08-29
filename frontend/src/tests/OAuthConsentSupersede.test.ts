import { beforeEach, describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import OAuthConsent from "../routes/OAuthConsent.svelte";
import {
  clearMocks,
  jsonResponse,
  mockEndpoint,
  setupFetchMock,
  setupIndexedDBMock,
} from "./mocks.ts";

const consentPayload = {
  request_uri: "urn:mock:request",
  client_id: "https://example.com",
  client_name: "Mixed Scope App",
  client_uri: null,
  logo_uri: null,
  transition_supersedes: true,
  scopes: [
    {
      scope: "atproto",
      category: "Core Access",
      required: true,
      description: "Baseline",
      display_name: "AT Protocol Access",
      granted: null,
      superseded: false,
    },
    {
      scope: "transition:generic",
      category: "Other",
      required: false,
      description: "Broad access",
      display_name: "Generic Access",
      granted: null,
      superseded: false,
    },
    {
      scope: "repo:app.bsky.feed.post?action=create",
      category: "Other",
      required: false,
      description: "Create posts",
      display_name: "repo:app.bsky.feed.post",
      granted: null,
      superseded: true,
    },
    {
      scope: "account:email?action=manage",
      category: "Other",
      required: false,
      description: "Manage email",
      display_name: "account:email",
      granted: null,
      superseded: false,
    },
    {
      scope: "transition:chat.bsky",
      category: "Other",
      required: false,
      description: "Chat access",
      display_name: "Chat Access",
      granted: null,
      superseded: false,
    },
  ],
  permission_sets: [],
  failed_sets: [],
  show_consent: true,
  did: "did:plc:example",
};

function boxFor(name: string): HTMLInputElement {
  const label = screen.getByText(name).closest("label");
  if (!label) throw new Error(`no label containing "${name}"`);
  const input = label.querySelector("input[type=checkbox]");
  if (!input) throw new Error(`no checkbox in label for "${name}"`);
  return input as HTMLInputElement;
}

describe("OAuthConsent transition:generic supersede behaviour", () => {
  beforeEach(() => {
    clearMocks();
    setupFetchMock();
    setupIndexedDBMock();
    Object.defineProperty(window.location, "search", {
      value: "?request_uri=urn:mock:request",
      writable: true,
      configurable: true,
    });
    mockEndpoint("/oauth/authorize/consent", () =>
      jsonResponse(consentPayload),
    );
  });

  it("warns that the itemised scopes are redundant", async () => {
    render(OAuthConsent);
    await waitFor(() =>
      expect(screen.getByText(/asked for broad access/i)).toBeTruthy(),
    );
    expect(
      screen.getByText(/specific permissions are meaningless/i),
    ).toBeTruthy();
  });

  it("warns about transition:generic even when nothing is superseded", async () => {
    mockEndpoint("/oauth/authorize/consent", () =>
      jsonResponse({
        ...consentPayload,
        transition_supersedes: false,
        scopes: consentPayload.scopes
          .filter((s) => !s.superseded)
          .map((s) => ({ ...s, superseded: false })),
      }),
    );
    render(OAuthConsent);

    await waitFor(() =>
      expect(screen.getByText(/asked for broad access/i)).toBeTruthy(),
    );
    expect(screen.getByText(/full read and write access/i)).toBeTruthy();
    expect(
      screen.queryByText(/specific permissions are meaningless/i),
    ).toBeNull();
  });

  it("drops the warning once transition:generic is declined", async () => {
    render(OAuthConsent);
    await waitFor(() => expect(boxFor("Generic Access")).toBeTruthy());

    await fireEvent.click(boxFor("Generic Access"));
    await waitFor(() =>
      expect(screen.queryByText(/asked for broad access/i)).toBeNull(),
    );
  });

  it("locks superseded scopes checked while transition:generic is selected", async () => {
    render(OAuthConsent);
    await waitFor(() => expect(boxFor("Generic Access")).toBeTruthy());

    const superseded = boxFor("repo:app.bsky.feed.post");
    expect(superseded.checked).toBe(true);
    expect(superseded.disabled).toBe(true);
  });

  it("leaves scopes generic does not cover editable", async () => {
    render(OAuthConsent);
    await waitFor(() => expect(boxFor("Chat Access")).toBeTruthy());

    expect(boxFor("Chat Access").disabled).toBe(false);
    expect(boxFor("account:email").disabled).toBe(false);
  });

  it("warns once a requested permission is switched off", async () => {
    render(OAuthConsent);
    await waitFor(() => expect(boxFor("Chat Access")).toBeTruthy());

    expect(screen.queryByText(/disabled some of the permissions/i)).toBeNull();
    await fireEvent.click(boxFor("Chat Access"));
    await waitFor(() =>
      expect(
        screen.getByText(/disabled some of the permissions/i),
      ).toBeTruthy(),
    );
  });

  it("hands control back once transition:generic is unchecked", async () => {
    render(OAuthConsent);
    await waitFor(() => expect(boxFor("Generic Access")).toBeTruthy());

    await fireEvent.click(boxFor("Generic Access"));

    await waitFor(() =>
      expect(boxFor("repo:app.bsky.feed.post").disabled).toBe(false),
    );
  });

  it("re-locks them when transition:generic is selected again", async () => {
    render(OAuthConsent);
    await waitFor(() => expect(boxFor("Generic Access")).toBeTruthy());

    const generic = boxFor("Generic Access");
    await fireEvent.click(generic);
    await waitFor(() =>
      expect(boxFor("repo:app.bsky.feed.post").disabled).toBe(false),
    );

    await fireEvent.click(boxFor("repo:app.bsky.feed.post"));
    await fireEvent.click(boxFor("Generic Access"));

    await waitFor(() => {
      const superseded = boxFor("repo:app.bsky.feed.post");
      expect(superseded.disabled).toBe(true);
      expect(superseded.checked).toBe(true);
    });
  });
});
