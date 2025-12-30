export type InboundStep =
  | "welcome"
  | "source-login"
  | "choose-handle"
  | "review"
  | "migrating"
  | "email-verify"
  | "plc-token"
  | "did-web-update"
  | "finalizing"
  | "success"
  | "error";

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
  requires2FA: boolean;
  twoFactorCode: string;
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
