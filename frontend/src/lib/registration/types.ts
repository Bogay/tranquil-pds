import type { VerificationChannel, DidType } from '../api'

export type RegistrationMode = 'password' | 'passkey'

export type RegistrationStep =
  | 'info'
  | 'key-choice'
  | 'initial-did-doc'
  | 'creating'
  | 'passkey'
  | 'app-password'
  | 'verify'
  | 'updated-did-doc'
  | 'activating'
  | 'redirect-to-dashboard'

export interface RegistrationInfo {
  handle: string
  email: string
  password?: string
  inviteCode?: string
  didType: DidType
  externalDid?: string
  verificationChannel: VerificationChannel
  discordId?: string
  telegramUsername?: string
  signalNumber?: string
}

export interface ExternalDidWebState {
  keyMode: 'reserved' | 'byod'
  reservedSigningKey?: string
  byodPrivateKey?: Uint8Array
  byodPublicKeyMultibase?: string
  initialDidDocument?: string
  updatedDidDocument?: string
}

export interface AccountResult {
  did: string
  handle: string
  setupToken?: string
  appPassword?: string
  appPasswordName?: string
}

export interface SessionState {
  accessJwt: string
  refreshJwt: string
}
