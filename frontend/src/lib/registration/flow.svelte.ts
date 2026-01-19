import { api, ApiError } from "../api.ts";
import { setSession } from "../auth.svelte.ts";
import {
  createServiceJwt,
  generateDidDocument,
  generateKeypair,
} from "../crypto.ts";
import {
  unsafeAsDid,
  unsafeAsEmail,
  unsafeAsHandle,
} from "../types/branded.ts";
import type {
  AccountResult,
  ExternalDidWebState,
  RegistrationInfo,
  RegistrationMode,
  RegistrationStep,
  SessionState,
} from "./types.ts";
import {
  clearRegistrationState,
  loadRegistrationState,
  saveRegistrationState,
} from "./storage.ts";

export interface RegistrationFlowState {
  mode: RegistrationMode;
  step: RegistrationStep;
  info: RegistrationInfo;
  externalDidWeb: ExternalDidWebState;
  account: AccountResult | null;
  session: SessionState | null;
  error: string | null;
  submitting: boolean;
  pdsHostname: string;
  emailInUse: boolean;
  discordInUse: boolean;
  telegramInUse: boolean;
  signalInUse: boolean;
}

export function createRegistrationFlow(
  mode: RegistrationMode,
  pdsHostname: string,
) {
  const state = $state<RegistrationFlowState>({
    mode,
    step: "info",
    info: {
      handle: "",
      email: "",
      password: "",
      inviteCode: "",
      didType: "plc",
      externalDid: "",
      verificationChannel: "email",
      discordId: "",
      telegramUsername: "",
      signalNumber: "",
    },
    externalDidWeb: {
      keyMode: "reserved",
    },
    account: null,
    session: null,
    error: null,
    submitting: false,
    pdsHostname,
    emailInUse: false,
    discordInUse: false,
    telegramInUse: false,
    signalInUse: false,
  });

  function getPdsEndpoint(): string {
    return `https://${state.pdsHostname}`;
  }

  function getPdsDid(): string {
    return `did:web:${state.pdsHostname}`;
  }

  function getFullHandle(): string {
    return `${state.info.handle.trim()}.${state.pdsHostname}`;
  }

  function extractDomain(did: string): string {
    return did.replace("did:web:", "").replace(/%3A/g, ":");
  }

  function persistState() {
    if (state.step !== "info" && state.step !== "creating") {
      saveRegistrationState(
        state.mode,
        state.step,
        state.pdsHostname,
        state.info,
        state.externalDidWeb,
        state.account,
        state.session,
      );
    }
  }

  function setError(err: unknown) {
    if (err instanceof ApiError) {
      state.error = err.message || "An error occurred";
    } else if (err instanceof Error) {
      state.error = err.message || "An error occurred";
    } else {
      state.error = "An error occurred";
    }
  }

  async function checkEmailInUse(email: string): Promise<void> {
    if (!email.trim() || !email.includes("@")) {
      state.emailInUse = false;
      return;
    }
    try {
      const result = await api.checkEmailInUse(email.trim());
      state.emailInUse = result.inUse;
    } catch {
      state.emailInUse = false;
    }
  }

  async function checkCommsChannelInUse(
    channel: "discord" | "telegram" | "signal",
    identifier: string,
  ): Promise<void> {
    const trimmed = identifier.trim();
    if (!trimmed) {
      state[`${channel}InUse`] = false;
      return;
    }
    try {
      const result = await api.checkCommsChannelInUse(channel, trimmed);
      state[`${channel}InUse`] = result.inUse;
    } catch {
      state[`${channel}InUse`] = false;
    }
  }

  function proceedFromInfo() {
    state.error = null;
    if (state.info.didType === "web-external") {
      state.step = "key-choice";
    } else {
      state.step = "creating";
    }
  }

  async function selectKeyMode(keyMode: "reserved" | "byod") {
    state.submitting = true;
    state.error = null;
    state.externalDidWeb.keyMode = keyMode;

    try {
      let publicKeyMultibase: string;

      if (keyMode === "reserved") {
        const result = await api.reserveSigningKey(
          unsafeAsDid(state.info.externalDid!.trim()),
        );
        state.externalDidWeb.reservedSigningKey = result.signingKey;
        publicKeyMultibase = result.signingKey.replace("did:key:", "");
      } else {
        const keypair = generateKeypair();
        state.externalDidWeb.byodPrivateKey = keypair.privateKey;
        state.externalDidWeb.byodPublicKeyMultibase =
          keypair.publicKeyMultibase;
        publicKeyMultibase = keypair.publicKeyMultibase;
      }

      const didDoc = generateDidDocument(
        state.info.externalDid!.trim(),
        publicKeyMultibase,
        getFullHandle(),
        getPdsEndpoint(),
      );
      state.externalDidWeb.initialDidDocument = JSON.stringify(
        didDoc,
        null,
        "\t",
      );
      state.step = "initial-did-doc";
      persistState();
    } catch (err) {
      setError(err);
    } finally {
      state.submitting = false;
    }
  }

  function confirmInitialDidDoc() {
    state.step = "creating";
  }

  async function createPasswordAccount() {
    state.submitting = true;
    state.error = null;

    try {
      let byodToken: string | undefined;

      if (
        state.info.didType === "web-external" &&
        state.externalDidWeb.keyMode === "byod" &&
        state.externalDidWeb.byodPrivateKey
      ) {
        byodToken = await createServiceJwt(
          state.externalDidWeb.byodPrivateKey,
          state.info.externalDid!.trim(),
          getPdsDid(),
          "com.atproto.server.createAccount",
        );
      }

      const result = await api.createAccount({
        handle: state.info.handle.trim(),
        email: state.info.email.trim(),
        password: state.info.password!,
        inviteCode: state.info.inviteCode?.trim() || undefined,
        didType: state.info.didType,
        did: state.info.didType === "web-external"
          ? state.info.externalDid!.trim()
          : undefined,
        signingKey: state.info.didType === "web-external" &&
            state.externalDidWeb.keyMode === "reserved"
          ? state.externalDidWeb.reservedSigningKey
          : undefined,
        verificationChannel: state.info.verificationChannel,
        discordId: state.info.discordId?.trim() || undefined,
        telegramUsername: state.info.telegramUsername?.trim() || undefined,
        signalNumber: state.info.signalNumber?.trim() || undefined,
      }, byodToken);

      state.account = {
        did: result.did,
        handle: result.handle,
      };
      state.step = "verify";
      persistState();
    } catch (err) {
      setError(err);
    } finally {
      state.submitting = false;
    }
  }

  async function createPasskeyAccount() {
    state.submitting = true;
    state.error = null;

    try {
      let byodToken: string | undefined;

      if (
        state.info.didType === "web-external" &&
        state.externalDidWeb.keyMode === "byod" &&
        state.externalDidWeb.byodPrivateKey
      ) {
        byodToken = await createServiceJwt(
          state.externalDidWeb.byodPrivateKey,
          state.info.externalDid!.trim(),
          getPdsDid(),
          "com.atproto.server.createAccount",
        );
      }

      const result = await api.createPasskeyAccount({
        handle: unsafeAsHandle(state.info.handle.trim()),
        email: state.info.email?.trim()
          ? unsafeAsEmail(state.info.email.trim())
          : undefined,
        inviteCode: state.info.inviteCode?.trim() || undefined,
        didType: state.info.didType,
        did: state.info.didType === "web-external"
          ? unsafeAsDid(state.info.externalDid!.trim())
          : undefined,
        signingKey: state.info.didType === "web-external" &&
            state.externalDidWeb.keyMode === "reserved"
          ? state.externalDidWeb.reservedSigningKey
          : undefined,
        verificationChannel: state.info.verificationChannel,
        discordId: state.info.discordId?.trim() || undefined,
        telegramUsername: state.info.telegramUsername?.trim() || undefined,
        signalNumber: state.info.signalNumber?.trim() || undefined,
      }, byodToken);

      state.account = {
        did: result.did,
        handle: result.handle,
        setupToken: result.setupToken,
      };
      state.step = "passkey";
      persistState();
    } catch (err) {
      setError(err);
    } finally {
      state.submitting = false;
    }
  }

  function setPasskeyComplete(appPassword: string, appPasswordName: string) {
    if (state.account) {
      state.account.appPassword = appPassword;
      state.account.appPasswordName = appPasswordName;
    }
    state.step = "app-password";
    persistState();
  }

  function proceedFromAppPassword() {
    state.step = "verify";
    persistState();
  }

  async function verifyAccount(code: string) {
    state.submitting = true;
    state.error = null;

    try {
      const confirmResult = await api.confirmSignup(
        state.account!.did,
        code.trim(),
      );

      if (state.info.didType === "web-external") {
        const password = state.mode === "passkey"
          ? state.account!.appPassword!
          : state.info.password!;
        const session = await api.createSession(state.account!.did, password);
        state.session = {
          accessJwt: session.accessJwt,
          refreshJwt: session.refreshJwt,
        };

        if (state.externalDidWeb.keyMode === "byod") {
          const credentials = await api.getRecommendedDidCredentials(
            session.accessJwt,
          );
          const newPublicKeyMultibase =
            credentials.verificationMethods?.atproto?.replace("did:key:", "") ||
            "";

          const didDoc = generateDidDocument(
            state.info.externalDid!.trim(),
            newPublicKeyMultibase,
            state.account!.handle,
            getPdsEndpoint(),
          );
          state.externalDidWeb.updatedDidDocument = JSON.stringify(
            didDoc,
            null,
            "\t",
          );
          state.step = "updated-did-doc";
          persistState();
        } else {
          await api.activateAccount(session.accessJwt);
          await finalizeSession();
          state.step = "redirect-to-dashboard";
        }
      } else {
        state.session = {
          accessJwt: confirmResult.accessJwt,
          refreshJwt: confirmResult.refreshJwt,
        };
        await finalizeSession();
        state.step = "redirect-to-dashboard";
      }
    } catch (err) {
      setError(err);
    } finally {
      state.submitting = false;
    }
  }

  async function activateAccount() {
    state.submitting = true;
    state.error = null;

    try {
      await api.activateAccount(state.session!.accessJwt);
      await finalizeSession();
      state.step = "redirect-to-dashboard";
    } catch (err) {
      setError(err);
    } finally {
      state.submitting = false;
    }
  }

  let checkingVerification = false;

  async function checkAndAdvanceIfVerified(): Promise<boolean> {
    if (checkingVerification || !state.account) return false;

    checkingVerification = true;
    try {
      const result = await api.checkEmailVerified(state.account.did);
      if (!result.verified) return false;

      if (state.info.didType === "web-external") {
        const password = state.mode === "passkey"
          ? state.account.appPassword!
          : state.info.password!;
        const session = await api.createSession(state.account.did, password);
        state.session = {
          accessJwt: session.accessJwt,
          refreshJwt: session.refreshJwt,
        };

        if (state.externalDidWeb.keyMode === "byod") {
          const credentials = await api.getRecommendedDidCredentials(
            session.accessJwt,
          );
          const newPublicKeyMultibase =
            credentials.verificationMethods?.atproto?.replace("did:key:", "") ||
            "";

          const didDoc = generateDidDocument(
            state.info.externalDid!.trim(),
            newPublicKeyMultibase,
            state.account.handle,
            getPdsEndpoint(),
          );
          state.externalDidWeb.updatedDidDocument = JSON.stringify(
            didDoc,
            null,
            "\t",
          );
          state.step = "updated-did-doc";
          persistState();
        } else {
          await api.activateAccount(session.accessJwt);
          await finalizeSession();
          state.step = "redirect-to-dashboard";
        }
      } else {
        const password = state.mode === "passkey"
          ? state.account.appPassword!
          : state.info.password!;
        const session = await api.createSession(state.account.did, password);
        state.session = {
          accessJwt: session.accessJwt,
          refreshJwt: session.refreshJwt,
        };
        await finalizeSession();
        state.step = "redirect-to-dashboard";
      }

      return true;
    } catch {
      return false;
    } finally {
      checkingVerification = false;
    }
  }

  function goBack() {
    switch (state.step) {
      case "key-choice":
        state.step = "info";
        break;
      case "initial-did-doc":
        state.step = "key-choice";
        break;
      case "passkey":
        state.step = state.info.didType === "web-external"
          ? "initial-did-doc"
          : "info";
        break;
    }
  }

  async function finalizeSession() {
    if (!state.session || !state.account) return;
    clearRegistrationState();
    setSession({
      did: state.account.did,
      handle: state.account.handle,
      accessJwt: state.session.accessJwt,
      refreshJwt: state.session.refreshJwt,
    });
  }

  return {
    get state() {
      return state;
    },
    get info() {
      return state.info;
    },
    get externalDidWeb() {
      return state.externalDidWeb;
    },
    get account() {
      return state.account;
    },
    get session() {
      return state.session;
    },

    getPdsEndpoint,
    getPdsDid,
    getFullHandle,
    extractDomain,

    proceedFromInfo,
    selectKeyMode,
    confirmInitialDidDoc,
    createPasswordAccount,
    createPasskeyAccount,
    setPasskeyComplete,
    proceedFromAppPassword,
    verifyAccount,
    checkAndAdvanceIfVerified,
    activateAccount,
    finalizeSession,
    goBack,
    checkEmailInUse,
    checkCommsChannelInUse,

    setError(msg: string) {
      state.error = msg;
    },
    clearError() {
      state.error = null;
    },
    setSubmitting(val: boolean) {
      state.submitting = val;
    },
  };
}

export type RegistrationFlow = ReturnType<typeof createRegistrationFlow>;

export function restoreRegistrationFlow(): RegistrationFlow | null {
  const saved = loadRegistrationState();
  if (
    !saved || saved.step === "info" || saved.step === "redirect-to-dashboard"
  ) {
    return null;
  }

  const flow = createRegistrationFlow(saved.mode, saved.pdsHostname);

  flow.state.step = saved.step;
  flow.state.info = { ...flow.state.info, ...saved.info };
  flow.state.externalDidWeb = {
    ...flow.state.externalDidWeb,
    ...saved.externalDidWeb,
  };
  flow.state.account = saved.account;
  flow.state.session = saved.session;

  return flow;
}

export {
  clearRegistrationState,
  getRegistrationResumeInfo,
  hasPendingRegistration,
} from "./storage.ts";
