import { z } from "zod";
import {
  unsafeAsAccessToken,
  unsafeAsAtUri,
  unsafeAsCid,
  unsafeAsDid,
  unsafeAsEmail,
  unsafeAsHandle,
  unsafeAsInviteCode,
  unsafeAsISODate,
  unsafeAsNsid,
  unsafeAsPublicKeyMultibase,
  unsafeAsRefreshToken,
  unsafeAsRkey,
} from "./branded.ts";

const did = z.string().transform((s) => unsafeAsDid(s));
const handle = z.string().transform((s) => unsafeAsHandle(s));
const accessToken = z.string().transform((s) => unsafeAsAccessToken(s));
const refreshToken = z.string().transform((s) => unsafeAsRefreshToken(s));
const cid = z.string().transform((s) => unsafeAsCid(s));
const nsid = z.string().transform((s) => unsafeAsNsid(s));
const atUri = z.string().transform((s) => unsafeAsAtUri(s));
const _rkey = z.string().transform((s) => unsafeAsRkey(s));
const isoDate = z.string().transform((s) => unsafeAsISODate(s));
const email = z.string().transform((s) => unsafeAsEmail(s));
const inviteCode = z.string().transform((s) => unsafeAsInviteCode(s));
const publicKeyMultibase = z.string().transform((s) =>
  unsafeAsPublicKeyMultibase(s)
);

export const verificationChannel = z.enum([
  "email",
  "discord",
  "telegram",
  "signal",
]);
export const didType = z.enum(["plc", "web", "web-external"]);
export const accountStatus = z.enum([
  "active",
  "deactivated",
  "migrated",
  "suspended",
  "deleted",
]);
export const sessionType = z.enum(["oauth", "legacy", "app_password"]);
export const reauthMethod = z.enum(["password", "totp", "passkey"]);

export const sessionSchema = z.object({
  did: did,
  handle: handle,
  email: email.optional(),
  emailConfirmed: z.boolean().optional(),
  preferredChannel: verificationChannel.optional(),
  preferredChannelVerified: z.boolean().optional(),
  isAdmin: z.boolean().optional(),
  active: z.boolean().optional(),
  status: accountStatus.optional(),
  migratedToPds: z.string().optional(),
  migratedAt: isoDate.optional(),
  accessJwt: accessToken,
  refreshJwt: refreshToken,
});

export const serverLinksSchema = z.object({
  privacyPolicy: z.string().optional(),
  termsOfService: z.string().optional(),
});

export const serverDescriptionSchema = z.object({
  availableUserDomains: z.array(z.string()),
  inviteCodeRequired: z.boolean(),
  links: serverLinksSchema.optional(),
  version: z.string().optional(),
  availableCommsChannels: z.array(verificationChannel).optional(),
  selfHostedDidWebEnabled: z.boolean().optional(),
});

export const appPasswordSchema = z.object({
  name: z.string(),
  createdAt: isoDate,
  scopes: z.string().optional(),
  createdByController: z.string().optional(),
});

export const createdAppPasswordSchema = z.object({
  name: z.string(),
  password: z.string(),
  createdAt: isoDate,
  scopes: z.string().optional(),
});

export const inviteCodeUseSchema = z.object({
  usedBy: did,
  usedByHandle: handle.optional(),
  usedAt: isoDate,
});

export const inviteCodeInfoSchema = z.object({
  code: inviteCode,
  available: z.number(),
  disabled: z.boolean(),
  forAccount: did,
  createdBy: did,
  createdAt: isoDate,
  uses: z.array(inviteCodeUseSchema),
});

export const sessionInfoSchema = z.object({
  id: z.string(),
  sessionType: sessionType,
  clientName: z.string().nullable(),
  createdAt: isoDate,
  expiresAt: isoDate,
  isCurrent: z.boolean(),
});

export const listSessionsResponseSchema = z.object({
  sessions: z.array(sessionInfoSchema),
});

export const totpStatusSchema = z.object({
  enabled: z.boolean(),
  hasBackupCodes: z.boolean(),
});

export const totpSecretSchema = z.object({
  uri: z.string(),
  qrBase64: z.string(),
});

export const enableTotpResponseSchema = z.object({
  success: z.boolean(),
  backupCodes: z.array(z.string()),
});

export const passkeyInfoSchema = z.object({
  id: z.string(),
  credentialId: z.string(),
  friendlyName: z.string().nullable(),
  createdAt: isoDate,
  lastUsed: isoDate.nullable(),
});

export const listPasskeysResponseSchema = z.object({
  passkeys: z.array(passkeyInfoSchema),
});

export const trustedDeviceSchema = z.object({
  id: z.string(),
  userAgent: z.string().nullable(),
  friendlyName: z.string().nullable(),
  trustedAt: isoDate.nullable(),
  trustedUntil: isoDate.nullable(),
  lastSeenAt: isoDate,
});

export const listTrustedDevicesResponseSchema = z.object({
  devices: z.array(trustedDeviceSchema),
});

export const reauthStatusSchema = z.object({
  requiresReauth: z.boolean(),
  lastReauthAt: isoDate.nullable(),
  availableMethods: z.array(reauthMethod),
});

export const reauthResponseSchema = z.object({
  success: z.boolean(),
  reauthAt: isoDate,
});

export const notificationPrefsSchema = z.object({
  preferredChannel: verificationChannel,
  email: email,
  discordUsername: z.string().nullable(),
  discordVerified: z.boolean(),
  telegramUsername: z.string().nullable(),
  telegramVerified: z.boolean(),
  signalUsername: z.string().nullable(),
  signalVerified: z.boolean(),
});

export const verificationMethodSchema = z.object({
  id: z.string(),
  type: z.string(),
  controller: z.string(),
  publicKeyMultibase: publicKeyMultibase,
});

export const serviceEndpointSchema = z.object({
  id: z.string(),
  type: z.string(),
  serviceEndpoint: z.string(),
});

export const didDocumentSchema = z.object({
  "@context": z.array(z.string()),
  id: did,
  alsoKnownAs: z.array(z.string()),
  verificationMethod: z.array(verificationMethodSchema),
  service: z.array(serviceEndpointSchema),
});

export const repoDescriptionSchema = z.object({
  handle: handle,
  did: did,
  didDoc: didDocumentSchema,
  collections: z.array(nsid),
  handleIsCorrect: z.boolean(),
});

export const recordInfoSchema = z.object({
  uri: atUri,
  cid: cid,
  value: z.unknown(),
});

export const listRecordsResponseSchema = z.object({
  records: z.array(recordInfoSchema),
  cursor: z.string().optional(),
});

export const recordResponseSchema = z.object({
  uri: atUri,
  cid: cid,
  value: z.unknown(),
});

export const createRecordResponseSchema = z.object({
  uri: atUri,
  cid: cid,
});

export const serverStatsSchema = z.object({
  userCount: z.number(),
  repoCount: z.number(),
  recordCount: z.number(),
  blobStorageBytes: z.number(),
});

export const serverConfigSchema = z.object({
  serverName: z.string(),
  primaryColor: z.string().nullable(),
  primaryColorDark: z.string().nullable(),
  secondaryColor: z.string().nullable(),
  secondaryColorDark: z.string().nullable(),
  logoCid: cid.nullable(),
});

export const passwordStatusSchema = z.object({
  hasPassword: z.boolean(),
});

export const successResponseSchema = z.object({
  success: z.boolean(),
});

export const legacyLoginPreferenceSchema = z.object({
  allowLegacyLogin: z.boolean(),
  hasMfa: z.boolean(),
});

export const accountInfoSchema = z.object({
  did: did,
  handle: handle,
  email: email.optional(),
  indexedAt: isoDate,
  emailConfirmedAt: isoDate.optional(),
  invitesDisabled: z.boolean().optional(),
  deactivatedAt: isoDate.optional(),
});

export const searchAccountsResponseSchema = z.object({
  cursor: z.string().optional(),
  accounts: z.array(accountInfoSchema),
});

export const backupInfoSchema = z.object({
  id: z.string(),
  repoRev: z.string(),
  repoRootCid: cid,
  blockCount: z.number(),
  sizeBytes: z.number(),
  createdAt: isoDate,
});

export const listBackupsResponseSchema = z.object({
  backups: z.array(backupInfoSchema),
  backupEnabled: z.boolean(),
});

export const createBackupResponseSchema = z.object({
  id: z.string(),
  repoRev: z.string(),
  sizeBytes: z.number(),
  blockCount: z.number(),
});

export type ValidatedSession = z.infer<typeof sessionSchema>;
export type ValidatedServerDescription = z.infer<
  typeof serverDescriptionSchema
>;
export type ValidatedAppPassword = z.infer<typeof appPasswordSchema>;
export type ValidatedCreatedAppPassword = z.infer<
  typeof createdAppPasswordSchema
>;
export type ValidatedInviteCodeInfo = z.infer<typeof inviteCodeInfoSchema>;
export type ValidatedSessionInfo = z.infer<typeof sessionInfoSchema>;
export type ValidatedListSessionsResponse = z.infer<
  typeof listSessionsResponseSchema
>;
export type ValidatedTotpStatus = z.infer<typeof totpStatusSchema>;
export type ValidatedTotpSecret = z.infer<typeof totpSecretSchema>;
export type ValidatedEnableTotpResponse = z.infer<
  typeof enableTotpResponseSchema
>;
export type ValidatedPasskeyInfo = z.infer<typeof passkeyInfoSchema>;
export type ValidatedListPasskeysResponse = z.infer<
  typeof listPasskeysResponseSchema
>;
export type ValidatedTrustedDevice = z.infer<typeof trustedDeviceSchema>;
export type ValidatedListTrustedDevicesResponse = z.infer<
  typeof listTrustedDevicesResponseSchema
>;
export type ValidatedReauthStatus = z.infer<typeof reauthStatusSchema>;
export type ValidatedReauthResponse = z.infer<typeof reauthResponseSchema>;
export type ValidatedNotificationPrefs = z.infer<
  typeof notificationPrefsSchema
>;
export type ValidatedDidDocument = z.infer<typeof didDocumentSchema>;
export type ValidatedRepoDescription = z.infer<typeof repoDescriptionSchema>;
export type ValidatedListRecordsResponse = z.infer<
  typeof listRecordsResponseSchema
>;
export type ValidatedRecordResponse = z.infer<typeof recordResponseSchema>;
export type ValidatedCreateRecordResponse = z.infer<
  typeof createRecordResponseSchema
>;
export type ValidatedServerStats = z.infer<typeof serverStatsSchema>;
export type ValidatedServerConfig = z.infer<typeof serverConfigSchema>;
export type ValidatedPasswordStatus = z.infer<typeof passwordStatusSchema>;
export type ValidatedSuccessResponse = z.infer<typeof successResponseSchema>;
export type ValidatedLegacyLoginPreference = z.infer<
  typeof legacyLoginPreferenceSchema
>;
export type ValidatedAccountInfo = z.infer<typeof accountInfoSchema>;
export type ValidatedSearchAccountsResponse = z.infer<
  typeof searchAccountsResponseSchema
>;
export type ValidatedBackupInfo = z.infer<typeof backupInfoSchema>;
export type ValidatedListBackupsResponse = z.infer<
  typeof listBackupsResponseSchema
>;
export type ValidatedCreateBackupResponse = z.infer<
  typeof createBackupResponseSchema
>;
