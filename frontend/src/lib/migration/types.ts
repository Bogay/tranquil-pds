export type InboundStep =
  | "welcome"
  | "source-handle"
  | "choose-handle"
  | "review"
  | "migrating"
  | "passkey-setup"
  | "app-password"
  | "email-verify"
  | "plc-token"
  | "did-web-update"
  | "finalizing"
  | "success"
  | "error";

export type AuthMethod = "password" | "passkey";

export type OutboundStep =
  | "welcome"
  | "target-pds"
  | "new-account"
  | "review"
  | "migrating"
  | "plc-token"
  | "finalizing"
  | "success"
  | "error";

export type MigrationDirection = "inbound" | "outbound";

export interface MigrationProgress {
  repoExported: boolean;
  repoImported: boolean;
  blobsTotal: number;
  blobsMigrated: number;
  blobsFailed: string[];
  prefsMigrated: boolean;
  plcSigned: boolean;
  activated: boolean;
  deactivated: boolean;
  currentOperation: string;
}

export interface InboundMigrationState {
  direction: "inbound";
  step: InboundStep;
  sourcePdsUrl: string;
  sourceDid: string;
  sourceHandle: string;
  targetHandle: string;
  targetEmail: string;
  targetPassword: string;
  inviteCode: string;
  sourceAccessToken: string | null;
  sourceRefreshToken: string | null;
  serviceAuthToken: string | null;
  emailVerifyToken: string;
  plcToken: string;
  progress: MigrationProgress;
  error: string | null;
  targetVerificationMethod: string | null;
  authMethod: AuthMethod;
  passkeySetupToken: string | null;
  oauthCodeVerifier: string | null;
  generatedAppPassword: string | null;
  generatedAppPasswordName: string | null;
  needsReauth?: boolean;
  resumeToStep?: InboundStep;
}

export interface OutboundMigrationState {
  direction: "outbound";
  step: OutboundStep;
  localDid: string;
  localHandle: string;
  targetPdsUrl: string;
  targetPdsDid: string;
  targetHandle: string;
  targetEmail: string;
  targetPassword: string;
  inviteCode: string;
  targetAccessToken: string | null;
  targetRefreshToken: string | null;
  serviceAuthToken: string | null;
  plcToken: string;
  progress: MigrationProgress;
  error: string | null;
  targetServerInfo: ServerDescription | null;
}

export type MigrationState = InboundMigrationState | OutboundMigrationState;

export interface StoredMigrationState {
  version: 1;
  direction: MigrationDirection;
  step: string;
  startedAt: string;
  sourcePdsUrl: string;
  targetPdsUrl: string;
  sourceDid: string;
  sourceHandle: string;
  targetHandle: string;
  targetEmail: string;
  authMethod?: AuthMethod;
  passkeySetupToken?: string;
  progress: {
    repoExported: boolean;
    repoImported: boolean;
    blobsTotal: number;
    blobsMigrated: number;
    prefsMigrated: boolean;
    plcSigned: boolean;
  };
  lastErrorStep?: string;
  lastError?: string;
}

export interface ServerDescription {
  did: string;
  availableUserDomains: string[];
  inviteCodeRequired: boolean;
  phoneVerificationRequired?: boolean;
  links?: {
    privacyPolicy?: string;
    termsOfService?: string;
  };
}

export interface Session {
  did: string;
  handle: string;
  email?: string;
  accessJwt: string;
  refreshJwt: string;
  active?: boolean;
}

export interface DidDocument {
  id: string;
  alsoKnownAs?: string[];
  verificationMethod?: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyMultibase?: string;
  }>;
  service?: Array<{
    id: string;
    type: string;
    serviceEndpoint: string;
  }>;
}

export interface DidCredentials {
  rotationKeys?: string[];
  alsoKnownAs?: string[];
  verificationMethods?: {
    atproto?: string;
  };
  services?: {
    atproto_pds?: {
      type: string;
      endpoint: string;
    };
  };
}

export interface PlcOperation {
  type: "plc_operation";
  prev: string | null;
  sig: string;
  rotationKeys: string[];
  verificationMethods: {
    atproto: string;
  };
  alsoKnownAs: string[];
  services: {
    atproto_pds: {
      type: string;
      endpoint: string;
    };
  };
}

export interface AccountStatus {
  activated: boolean;
  validDid: boolean;
  repoCommit: string;
  repoRev: string;
  repoBlocks: number;
  indexedRecords: number;
  privateStateValues: number;
  expectedBlobs: number;
  importedBlobs: number;
}

export interface BlobRef {
  $type: "blob";
  ref: { $link: string };
  mimeType: string;
  size: number;
}

export interface CreateAccountParams {
  did?: string;
  handle: string;
  email: string;
  password: string;
  inviteCode?: string;
  recoveryKey?: string;
}

export interface CreatePasskeyAccountParams {
  did?: string;
  handle: string;
  email: string;
  inviteCode?: string;
}

export interface PasskeyAccountSetup {
  setupToken: string;
  did: string;
  handle: string;
  setupExpiresAt: string;
  accessJwt?: string;
}

export interface CompletePasskeySetupResponse {
  did: string;
  handle: string;
  appPassword: string;
  appPasswordName: string;
}

export interface StartPasskeyRegistrationResponse {
  options: unknown;
}

export interface OAuthServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  grant_types_supported?: string[];
  code_challenge_methods_supported?: string[];
  dpop_signing_alg_values_supported?: string[];
}

export interface OAuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

export interface Preferences {
  preferences: unknown[];
}

export class MigrationError extends Error {
  constructor(
    message: string,
    public code: string,
    public recoverable: boolean = false,
    public details?: unknown,
  ) {
    super(message);
    this.name = "MigrationError";
  }
}

export function getErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  if (typeof err === "string") {
    return err;
  }
  return String(err);
}
