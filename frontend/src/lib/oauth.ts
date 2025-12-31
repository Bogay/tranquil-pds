const OAUTH_STATE_KEY = "tranquil_pds_oauth_state";
const OAUTH_VERIFIER_KEY = "tranquil_pds_oauth_verifier";
const SCOPES = [
  "atproto",
  "repo:*?action=create",
  "repo:*?action=update",
  "repo:*?action=delete",
  "blob:*/*",
].join(" ");
const CLIENT_ID = !(import.meta.env.DEV)
  ? `${globalThis.location.origin}/oauth/client-metadata.json`
  : `http://localhost/?scope=${SCOPES}`;
const REDIRECT_URI = `${globalThis.location.origin}/`;

interface OAuthState {
  state: string;
  codeVerifier: string;
  returnTo?: string;
}

function generateRandomString(length: number): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

async function sha256(plain: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  return crypto.subtle.digest("SHA-256", data);
}

function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(
    /=+$/,
    "",
  );
}

export async function generateCodeChallenge(verifier: string): Promise<string> {
  const hash = await sha256(verifier);
  return base64UrlEncode(hash);
}

export function generateState(): string {
  return generateRandomString(32);
}

export function generateCodeVerifier(): string {
  return generateRandomString(32);
}

export function saveOAuthState(state: OAuthState): void {
  sessionStorage.setItem(OAUTH_STATE_KEY, state.state);
  sessionStorage.setItem(OAUTH_VERIFIER_KEY, state.codeVerifier);
}

function getOAuthState(): OAuthState | null {
  const state = sessionStorage.getItem(OAUTH_STATE_KEY);
  const codeVerifier = sessionStorage.getItem(OAUTH_VERIFIER_KEY);
  if (!state || !codeVerifier) return null;
  return { state, codeVerifier };
}

function clearOAuthState(): void {
  sessionStorage.removeItem(OAUTH_STATE_KEY);
  sessionStorage.removeItem(OAUTH_VERIFIER_KEY);
}

export async function startOAuthLogin(): Promise<void> {
  const state = generateState();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  saveOAuthState({ state, codeVerifier });

  const parResponse = await fetch("/oauth/par", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: SCOPES,
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    }),
  });

  if (!parResponse.ok) {
    const error = await parResponse.json().catch(() => ({
      error: "Unknown error",
    }));
    throw new Error(
      error.error_description || error.error || "Failed to start OAuth flow",
    );
  }

  const { request_uri } = await parResponse.json();

  const authorizeUrl = new URL("/oauth/authorize", globalThis.location.origin);
  authorizeUrl.searchParams.set("client_id", CLIENT_ID);
  authorizeUrl.searchParams.set("request_uri", request_uri);

  globalThis.location.href = authorizeUrl.toString();
}

export interface OAuthTokens {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in?: number;
  scope?: string;
  sub: string;
}

export async function handleOAuthCallback(
  code: string,
  state: string,
): Promise<OAuthTokens> {
  const savedState = getOAuthState();
  if (!savedState) {
    throw new Error("No OAuth state found. Please try logging in again.");
  }

  if (savedState.state !== state) {
    clearOAuthState();
    throw new Error("OAuth state mismatch. Please try logging in again.");
  }

  const tokenResponse = await fetch("/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      code: code,
      redirect_uri: REDIRECT_URI,
      code_verifier: savedState.codeVerifier,
    }),
  });

  clearOAuthState();

  if (!tokenResponse.ok) {
    const error = await tokenResponse.json().catch(() => ({
      error: "Unknown error",
    }));
    throw new Error(
      error.error_description || error.error ||
        "Failed to exchange code for tokens",
    );
  }

  return tokenResponse.json();
}

export async function refreshOAuthToken(
  refreshToken: string,
): Promise<OAuthTokens> {
  const tokenResponse = await fetch("/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: CLIENT_ID,
      refresh_token: refreshToken,
    }),
  });

  if (!tokenResponse.ok) {
    const error = await tokenResponse.json().catch(() => ({
      error: "Unknown error",
    }));
    throw new Error(
      error.error_description || error.error || "Failed to refresh token",
    );
  }

  return tokenResponse.json();
}

export function checkForOAuthCallback():
  | { code: string; state: string }
  | null {
  if (globalThis.location.hash === "#/migrate") {
    return null;
  }

  const params = new URLSearchParams(globalThis.location.search);
  const code = params.get("code");
  const state = params.get("state");

  if (code && state) {
    return { code, state };
  }

  return null;
}

export function clearOAuthCallbackParams(): void {
  const url = new URL(globalThis.location.href);
  url.search = "";
  globalThis.history.replaceState({}, "", url.toString());
}
