import { api, ApiError } from "../api";
import {
  createServiceJwt,
  generateDidDocument,
  generateKeypair,
} from "../crypto";
import type {
  AccountResult,
  ExternalDidWebState,
  RegistrationInfo,
  RegistrationMode,
  RegistrationStep,
  SessionState,
} from "./types";

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
}

export function createRegistrationFlow(
  mode: RegistrationMode,
  pdsHostname: string,
) {
  let state = $state<RegistrationFlowState>({
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

  function setError(err: unknown) {
    if (err instanceof ApiError) {
      state.error = err.message || "An error occurred";
    } else if (err instanceof Error) {
      state.error = err.message || "An error occurred";
    } else {
      state.error = "An error occurred";
    }
  }

  async function proceedFromInfo() {
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
          state.info.externalDid!.trim(),
        );
        state.externalDidWeb.reservedSigningKey = result.signingKey;
        publicKeyMultibase = result.signingKey.replace("did:key:", "");
      } else {
        const keypair = await generateKeypair();
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
    } catch (err) {
      setError(err);
    } finally {
      state.submitting = false;
    }
  }

  async function confirmInitialDidDoc() {
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
        handle: state.info.handle.trim(),
        email: state.info.email?.trim() || undefined,
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
        setupToken: result.setupToken,
      };
      state.step = "passkey";
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
  }

  function proceedFromAppPassword() {
    state.step = "verify";
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
    const { setSession } = await import("../auth.svelte");
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
    activateAccount,
    finalizeSession,
    goBack,

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
