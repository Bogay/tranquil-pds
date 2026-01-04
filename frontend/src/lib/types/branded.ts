declare const __brand: unique symbol

type Brand<T, B extends string> = T & { readonly [__brand]: B }

export type Did = Brand<string, 'Did'>
export type DidPlc = Brand<Did, 'DidPlc'>
export type DidWeb = Brand<Did, 'DidWeb'>

export type Handle = Brand<string, 'Handle'>
export type AccessToken = Brand<string, 'AccessToken'>
export type RefreshToken = Brand<string, 'RefreshToken'>
export type ServiceToken = Brand<string, 'ServiceToken'>
export type SetupToken = Brand<string, 'SetupToken'>

export type Cid = Brand<string, 'Cid'>
export type Rkey = Brand<string, 'Rkey'>
export type AtUri = Brand<string, 'AtUri'>
export type Nsid = Brand<string, 'Nsid'>

export type ISODateString = Brand<string, 'ISODateString'>
export type EmailAddress = Brand<string, 'EmailAddress'>
export type InviteCode = Brand<string, 'InviteCode'>

export type PublicKeyMultibase = Brand<string, 'PublicKeyMultibase'>
export type DidKeyString = Brand<string, 'DidKeyString'>

const DID_PLC_REGEX = /^did:plc:[a-z2-7]{24}$/
const DID_WEB_REGEX = /^did:web:.+$/
const HANDLE_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/
const AT_URI_REGEX = /^at:\/\/[^/]+\/[^/]+\/[^/]+$/
const CID_REGEX = /^[a-z2-7]{59}$|^baf[a-z2-7]+$/
const NSID_REGEX = /^[a-z]([a-z0-9-]*[a-z0-9])?(\.[a-z]([a-z0-9-]*[a-z0-9])?)+$/
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/

export function isDid(s: string): s is Did {
  return s.startsWith('did:plc:') || s.startsWith('did:web:')
}

export function isDidPlc(s: string): s is DidPlc {
  return DID_PLC_REGEX.test(s)
}

export function isDidWeb(s: string): s is DidWeb {
  return DID_WEB_REGEX.test(s)
}

export function isHandle(s: string): s is Handle {
  return HANDLE_REGEX.test(s) && s.length <= 253
}

export function isAtUri(s: string): s is AtUri {
  return AT_URI_REGEX.test(s)
}

export function isCid(s: string): s is Cid {
  return CID_REGEX.test(s)
}

export function isNsid(s: string): s is Nsid {
  return NSID_REGEX.test(s)
}

export function isEmail(s: string): s is EmailAddress {
  return EMAIL_REGEX.test(s)
}

export function isISODate(s: string): s is ISODateString {
  return ISO_DATE_REGEX.test(s)
}

export function asDid(s: string): Did {
  if (!isDid(s)) throw new TypeError(`Invalid DID: ${s}`)
  return s
}

export function asDidPlc(s: string): DidPlc {
  if (!isDidPlc(s)) throw new TypeError(`Invalid DID:PLC: ${s}`)
  return s as DidPlc
}

export function asDidWeb(s: string): DidWeb {
  if (!isDidWeb(s)) throw new TypeError(`Invalid DID:WEB: ${s}`)
  return s as DidWeb
}

export function asHandle(s: string): Handle {
  if (!isHandle(s)) throw new TypeError(`Invalid handle: ${s}`)
  return s
}

export function asAtUri(s: string): AtUri {
  if (!isAtUri(s)) throw new TypeError(`Invalid AT-URI: ${s}`)
  return s
}

export function asCid(s: string): Cid {
  if (!isCid(s)) throw new TypeError(`Invalid CID: ${s}`)
  return s
}

export function asNsid(s: string): Nsid {
  if (!isNsid(s)) throw new TypeError(`Invalid NSID: ${s}`)
  return s
}

export function asEmail(s: string): EmailAddress {
  if (!isEmail(s)) throw new TypeError(`Invalid email: ${s}`)
  return s
}

export function asISODate(s: string): ISODateString {
  if (!isISODate(s)) throw new TypeError(`Invalid ISO date: ${s}`)
  return s
}

export function unsafeAsDid(s: string): Did {
  return s as Did
}

export function unsafeAsHandle(s: string): Handle {
  return s as Handle
}

export function unsafeAsAccessToken(s: string): AccessToken {
  return s as AccessToken
}

export function unsafeAsRefreshToken(s: string): RefreshToken {
  return s as RefreshToken
}

export function unsafeAsServiceToken(s: string): ServiceToken {
  return s as ServiceToken
}

export function unsafeAsSetupToken(s: string): SetupToken {
  return s as SetupToken
}

export function unsafeAsCid(s: string): Cid {
  return s as Cid
}

export function unsafeAsRkey(s: string): Rkey {
  return s as Rkey
}

export function unsafeAsAtUri(s: string): AtUri {
  return s as AtUri
}

export function unsafeAsNsid(s: string): Nsid {
  return s as Nsid
}

export function unsafeAsISODate(s: string): ISODateString {
  return s as ISODateString
}

export function unsafeAsEmail(s: string): EmailAddress {
  return s as EmailAddress
}

export function unsafeAsInviteCode(s: string): InviteCode {
  return s as InviteCode
}

export function unsafeAsPublicKeyMultibase(s: string): PublicKeyMultibase {
  return s as PublicKeyMultibase
}

export function unsafeAsDidKey(s: string): DidKeyString {
  return s as DidKeyString
}

export function parseAtUri(uri: AtUri): { repo: Did; collection: Nsid; rkey: Rkey } {
  const parts = uri.replace('at://', '').split('/')
  return {
    repo: unsafeAsDid(parts[0]),
    collection: unsafeAsNsid(parts[1]),
    rkey: unsafeAsRkey(parts[2]),
  }
}

export function makeAtUri(repo: Did, collection: Nsid, rkey: Rkey): AtUri {
  return `at://${repo}/${collection}/${rkey}` as AtUri
}
