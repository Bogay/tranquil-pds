import type {
  InboundMigrationState,
  InboundStep,
  MigrationProgress,
  OutboundMigrationState,
  OutboundStep,
  ServerDescription,
  StoredMigrationState,
} from "./types";
import {
  AtprotoClient,
  createLocalClient,
  resolvePdsUrl,
} from "./atproto-client";
import {
  clearMigrationState,
  loadMigrationState,
  saveMigrationState,
  updateProgress,
  updateStep,
} from "./storage";

function createInitialProgress(): MigrationProgress {
  return {
    repoExported: false,
    repoImported: false,
    blobsTotal: 0,
    blobsMigrated: 0,
    blobsFailed: [],
    prefsMigrated: false,
    plcSigned: false,
    activated: false,
    deactivated: false,
    currentOperation: "",
  };
}

export function createInboundMigrationFlow() {
  let state = $state<InboundMigrationState>({
    direction: "inbound",
    step: "welcome",
    sourcePdsUrl: "",
    sourceDid: "",
    sourceHandle: "",
    targetHandle: "",
    targetEmail: "",
    targetPassword: "",
    inviteCode: "",
    sourceAccessToken: null,
    sourceRefreshToken: null,
    serviceAuthToken: null,
    emailVerifyToken: "",
    plcToken: "",
    progress: createInitialProgress(),
    error: null,
    requires2FA: false,
    twoFactorCode: "",
  });

  let sourceClient: AtprotoClient | null = null;
  let localClient: AtprotoClient | null = null;
  let localServerInfo: ServerDescription | null = null;

  function setStep(step: InboundStep) {
    state.step = step;
    state.error = null;
    saveMigrationState(state);
    updateStep(step);
  }

  function setError(error: string) {
    state.error = error;
    saveMigrationState(state);
  }

  function setProgress(updates: Partial<MigrationProgress>) {
    state.progress = { ...state.progress, ...updates };
    updateProgress(updates);
  }

  async function loadLocalServerInfo(): Promise<ServerDescription> {
    if (!localClient) {
      localClient = createLocalClient();
    }
    if (!localServerInfo) {
      localServerInfo = await localClient.describeServer();
    }
    return localServerInfo;
  }

  async function resolveSourcePds(handle: string): Promise<void> {
    try {
      const { did, pdsUrl } = await resolvePdsUrl(handle);
      state.sourcePdsUrl = pdsUrl;
      state.sourceDid = did;
      state.sourceHandle = handle;
      sourceClient = new AtprotoClient(pdsUrl);
    } catch (e) {
      throw new Error(`Could not resolve handle: ${(e as Error).message}`);
    }
  }

  async function loginToSource(
    handle: string,
    password: string,
    twoFactorCode?: string,
  ): Promise<void> {
    if (!state.sourcePdsUrl) {
      await resolveSourcePds(handle);
    }

    if (!sourceClient) {
      sourceClient = new AtprotoClient(state.sourcePdsUrl);
    }

    try {
      const session = await sourceClient.login(handle, password, twoFactorCode);
      state.sourceAccessToken = session.accessJwt;
      state.sourceRefreshToken = session.refreshJwt;
      state.sourceDid = session.did;
      state.sourceHandle = session.handle;
      state.requires2FA = false;
      saveMigrationState(state);
    } catch (e) {
      const err = e as Error & { error?: string };
      if (err.error === "AuthFactorTokenRequired") {
        state.requires2FA = true;
        throw new Error("Two-factor authentication required. Please enter the code sent to your email.");
      }
      throw e;
    }
  }

  async function checkHandleAvailability(handle: string): Promise<boolean> {
    if (!localClient) {
      localClient = createLocalClient();
    }
    try {
      await localClient.resolveHandle(handle);
      return false;
    } catch {
      return true;
    }
  }

  async function authenticateToLocal(email: string, password: string): Promise<void> {
    if (!localClient) {
      localClient = createLocalClient();
    }
    await localClient.loginDeactivated(email, password);
  }

  async function startMigration(): Promise<void> {
    if (!sourceClient || !state.sourceAccessToken) {
      throw new Error("Not logged in to source PDS");
    }

    if (!localClient) {
      localClient = createLocalClient();
    }

    setStep("migrating");
    setProgress({ currentOperation: "Getting service auth token..." });

    try {
      const serverInfo = await loadLocalServerInfo();
      const { token } = await sourceClient.getServiceAuth(
        serverInfo.did,
        "com.atproto.server.createAccount",
      );
      state.serviceAuthToken = token;

      setProgress({ currentOperation: "Creating account on new PDS..." });

      const accountParams = {
        did: state.sourceDid,
        handle: state.targetHandle,
        email: state.targetEmail,
        password: state.targetPassword,
        inviteCode: state.inviteCode || undefined,
      };

      const session = await localClient.createAccount(accountParams, token);
      localClient.setAccessToken(session.accessJwt);

      setProgress({ currentOperation: "Exporting repository..." });

      const car = await sourceClient.getRepo(state.sourceDid);
      setProgress({ repoExported: true, currentOperation: "Importing repository..." });

      await localClient.importRepo(car);
      setProgress({ repoImported: true, currentOperation: "Counting blobs..." });

      const accountStatus = await localClient.checkAccountStatus();
      setProgress({
        blobsTotal: accountStatus.expectedBlobs,
        currentOperation: "Migrating blobs...",
      });

      await migrateBlobs();

      setProgress({ currentOperation: "Migrating preferences..." });
      await migratePreferences();

      setStep("email-verify");
    } catch (e) {
      const err = e as Error & { error?: string; status?: number };
      const message = err.message || err.error || `Unknown error (status ${err.status || 'unknown'})`;
      setError(message);
      setStep("error");
    }
  }

  async function migrateBlobs(): Promise<void> {
    if (!sourceClient || !localClient) return;

    let cursor: string | undefined;
    let migrated = 0;

    do {
      const { blobs, cursor: nextCursor } = await localClient.listMissingBlobs(
        cursor,
        100,
      );

      for (const blob of blobs) {
        try {
          setProgress({
            currentOperation: `Migrating blob ${migrated + 1}/${state.progress.blobsTotal}...`,
          });

          const blobData = await sourceClient.getBlob(state.sourceDid, blob.cid);
          await localClient.uploadBlob(blobData, "application/octet-stream");
          migrated++;
          setProgress({ blobsMigrated: migrated });
        } catch (e) {
          state.progress.blobsFailed.push(blob.cid);
        }
      }

      cursor = nextCursor;
    } while (cursor);
  }

  async function migratePreferences(): Promise<void> {
    if (!sourceClient || !localClient) return;

    try {
      const prefs = await sourceClient.getPreferences();
      await localClient.putPreferences(prefs);
      setProgress({ prefsMigrated: true });
    } catch {
    }
  }

  async function submitEmailVerifyToken(token: string, localPassword?: string): Promise<void> {
    if (!localClient) {
      localClient = createLocalClient();
    }

    state.emailVerifyToken = token;
    setError(null);

    try {
      await localClient.verifyToken(token, state.targetEmail);

      if (!sourceClient) {
        setStep("source-login");
        setError("Email verified! Please log in to your old account again to complete the migration.");
        return;
      }

      if (localPassword) {
        setProgress({ currentOperation: "Authenticating to new PDS..." });
        await localClient.loginDeactivated(state.targetEmail, localPassword);
      }

      if (!localClient.getAccessToken()) {
        setError("Email verified! Please enter your password to continue.");
        return;
      }

      setProgress({ currentOperation: "Requesting PLC operation token..." });
      await sourceClient.requestPlcOperationSignature();
      setStep("plc-token");
    } catch (e) {
      const err = e as Error & { error?: string; status?: number };
      const message = err.message || err.error || `Unknown error (status ${err.status || 'unknown'})`;
      setError(message);
    }
  }

  async function resendEmailVerification(): Promise<void> {
    if (!localClient) {
      localClient = createLocalClient();
    }
    await localClient.resendMigrationVerification();
  }

  let checkingEmailVerification = false;

  async function checkEmailVerifiedAndProceed(): Promise<boolean> {
    if (checkingEmailVerification) return false;
    if (!sourceClient || !localClient) return false;

    checkingEmailVerification = true;
    try {
      await localClient.loginDeactivated(state.targetEmail, state.targetPassword);
      await sourceClient.requestPlcOperationSignature();
      setStep("plc-token");
      return true;
    } catch (e) {
      const err = e as Error & { error?: string };
      if (err.error === "AccountNotVerified") {
        return false;
      }
      return false;
    } finally {
      checkingEmailVerification = false;
    }
  }

  async function submitPlcToken(token: string): Promise<void> {
    if (!sourceClient || !localClient) {
      throw new Error("Not connected to PDSes");
    }

    state.plcToken = token;
    setStep("finalizing");
    setProgress({ currentOperation: "Signing PLC operation..." });

    try {
      const credentials = await localClient.getRecommendedDidCredentials();

      const { operation } = await sourceClient.signPlcOperation({
        token,
        ...credentials,
      });

      setProgress({ plcSigned: true, currentOperation: "Submitting PLC operation..." });
      await localClient.submitPlcOperation(operation);

      setProgress({ currentOperation: "Activating account (waiting for DID propagation)..." });
      await localClient.activateAccount();
      setProgress({ activated: true });

      setProgress({ currentOperation: "Deactivating old account..." });
      try {
        await sourceClient.deactivateAccount();
        setProgress({ deactivated: true });
      } catch {
      }

      setStep("success");
      clearMigrationState();
    } catch (e) {
      const err = e as Error & { error?: string; status?: number };
      const message = err.message || err.error || `Unknown error (status ${err.status || 'unknown'})`;
      state.step = "plc-token";
      state.error = message;
      saveMigrationState(state);
    }
  }

  async function requestPlcToken(): Promise<void> {
    if (!sourceClient) {
      throw new Error("Not connected to source PDS");
    }
    setProgress({ currentOperation: "Requesting PLC operation token..." });
    await sourceClient.requestPlcOperationSignature();
  }

  async function resendPlcToken(): Promise<void> {
    if (!sourceClient) {
      throw new Error("Not connected to source PDS");
    }
    await sourceClient.requestPlcOperationSignature();
  }

  function reset(): void {
    state = {
      direction: "inbound",
      step: "welcome",
      sourcePdsUrl: "",
      sourceDid: "",
      sourceHandle: "",
      targetHandle: "",
      targetEmail: "",
      targetPassword: "",
      inviteCode: "",
      sourceAccessToken: null,
      sourceRefreshToken: null,
      serviceAuthToken: null,
      emailVerifyToken: "",
      plcToken: "",
      progress: createInitialProgress(),
      error: null,
      requires2FA: false,
      twoFactorCode: "",
    };
    sourceClient = null;
    clearMigrationState();
  }

  async function resumeFromState(stored: StoredMigrationState): Promise<void> {
    if (stored.direction !== "inbound") return;

    state.sourcePdsUrl = stored.sourcePdsUrl;
    state.sourceDid = stored.sourceDid;
    state.sourceHandle = stored.sourceHandle;
    state.targetHandle = stored.targetHandle;
    state.targetEmail = stored.targetEmail;
    state.progress = {
      ...createInitialProgress(),
      ...stored.progress,
    };

    state.step = "source-login";
  }

  function getLocalSession(): { accessJwt: string; did: string; handle: string } | null {
    if (!localClient) return null;
    const token = localClient.getAccessToken();
    if (!token) return null;
    return {
      accessJwt: token,
      did: state.sourceDid,
      handle: state.targetHandle,
    };
  }

  return {
    get state() { return state; },
    setStep,
    setError,
    loadLocalServerInfo,
    loginToSource,
    authenticateToLocal,
    checkHandleAvailability,
    startMigration,
    submitEmailVerifyToken,
    resendEmailVerification,
    checkEmailVerifiedAndProceed,
    requestPlcToken,
    submitPlcToken,
    resendPlcToken,
    reset,
    resumeFromState,
    getLocalSession,

    updateField<K extends keyof InboundMigrationState>(
      field: K,
      value: InboundMigrationState[K],
    ) {
      state[field] = value;
    },
  };
}

export function createOutboundMigrationFlow() {
  let state = $state<OutboundMigrationState>({
    direction: "outbound",
    step: "welcome",
    localDid: "",
    localHandle: "",
    targetPdsUrl: "",
    targetPdsDid: "",
    targetHandle: "",
    targetEmail: "",
    targetPassword: "",
    inviteCode: "",
    targetAccessToken: null,
    targetRefreshToken: null,
    serviceAuthToken: null,
    plcToken: "",
    progress: createInitialProgress(),
    error: null,
    targetServerInfo: null,
  });

  let localClient: AtprotoClient | null = null;
  let targetClient: AtprotoClient | null = null;

  function setStep(step: OutboundStep) {
    state.step = step;
    state.error = null;
    saveMigrationState(state);
    updateStep(step);
  }

  function setError(error: string) {
    state.error = error;
    saveMigrationState(state);
  }

  function setProgress(updates: Partial<MigrationProgress>) {
    state.progress = { ...state.progress, ...updates };
    updateProgress(updates);
  }

  async function validateTargetPds(url: string): Promise<ServerDescription> {
    const normalizedUrl = url.replace(/\/$/, "");
    targetClient = new AtprotoClient(normalizedUrl);

    try {
      const serverInfo = await targetClient.describeServer();
      state.targetPdsUrl = normalizedUrl;
      state.targetPdsDid = serverInfo.did;
      state.targetServerInfo = serverInfo;
      return serverInfo;
    } catch (e) {
      throw new Error(`Could not connect to PDS: ${(e as Error).message}`);
    }
  }

  function initLocalClient(accessToken: string, did?: string, handle?: string): void {
    localClient = createLocalClient();
    localClient.setAccessToken(accessToken);
    if (did) {
      state.localDid = did;
    }
    if (handle) {
      state.localHandle = handle;
    }
  }

  async function startMigration(currentDid: string): Promise<void> {
    if (!localClient || !targetClient) {
      throw new Error("Not connected to PDSes");
    }

    setStep("migrating");
    setProgress({ currentOperation: "Getting service auth token..." });

    try {
      const { token } = await localClient.getServiceAuth(
        state.targetPdsDid,
        "com.atproto.server.createAccount",
      );
      state.serviceAuthToken = token;

      setProgress({ currentOperation: "Creating account on new PDS..." });

      const accountParams = {
        did: currentDid,
        handle: state.targetHandle,
        email: state.targetEmail,
        password: state.targetPassword,
        inviteCode: state.inviteCode || undefined,
      };

      const session = await targetClient.createAccount(accountParams, token);
      state.targetAccessToken = session.accessJwt;
      state.targetRefreshToken = session.refreshJwt;
      targetClient.setAccessToken(session.accessJwt);

      setProgress({ currentOperation: "Exporting repository..." });

      const car = await localClient.getRepo(currentDid);
      setProgress({ repoExported: true, currentOperation: "Importing repository..." });

      await targetClient.importRepo(car);
      setProgress({ repoImported: true, currentOperation: "Counting blobs..." });

      const accountStatus = await targetClient.checkAccountStatus();
      setProgress({
        blobsTotal: accountStatus.expectedBlobs,
        currentOperation: "Migrating blobs...",
      });

      await migrateBlobs(currentDid);

      setProgress({ currentOperation: "Migrating preferences..." });
      await migratePreferences();

      setProgress({ currentOperation: "Requesting PLC operation token..." });
      await localClient.requestPlcOperationSignature();

      setStep("plc-token");
    } catch (e) {
      const err = e as Error & { error?: string; status?: number };
      const message = err.message || err.error || `Unknown error (status ${err.status || 'unknown'})`;
      setError(message);
      setStep("error");
    }
  }

  async function migrateBlobs(did: string): Promise<void> {
    if (!localClient || !targetClient) return;

    let cursor: string | undefined;
    let migrated = 0;

    do {
      const { blobs, cursor: nextCursor } = await targetClient.listMissingBlobs(
        cursor,
        100,
      );

      for (const blob of blobs) {
        try {
          setProgress({
            currentOperation: `Migrating blob ${migrated + 1}/${state.progress.blobsTotal}...`,
          });

          const blobData = await localClient.getBlob(did, blob.cid);
          await targetClient.uploadBlob(blobData, "application/octet-stream");
          migrated++;
          setProgress({ blobsMigrated: migrated });
        } catch (e) {
          state.progress.blobsFailed.push(blob.cid);
        }
      }

      cursor = nextCursor;
    } while (cursor);
  }

  async function migratePreferences(): Promise<void> {
    if (!localClient || !targetClient) return;

    try {
      const prefs = await localClient.getPreferences();
      await targetClient.putPreferences(prefs);
      setProgress({ prefsMigrated: true });
    } catch {
    }
  }

  async function submitPlcToken(token: string): Promise<void> {
    if (!localClient || !targetClient) {
      throw new Error("Not connected to PDSes");
    }

    state.plcToken = token;
    setStep("finalizing");
    setProgress({ currentOperation: "Signing PLC operation..." });

    try {
      const credentials = await targetClient.getRecommendedDidCredentials();

      const { operation } = await localClient.signPlcOperation({
        token,
        ...credentials,
      });

      setProgress({ plcSigned: true, currentOperation: "Submitting PLC operation..." });

      await targetClient.submitPlcOperation(operation);

      setProgress({ currentOperation: "Activating account on new PDS..." });
      await targetClient.activateAccount();
      setProgress({ activated: true });

      setProgress({ currentOperation: "Deactivating old account..." });
      try {
        await localClient.deactivateAccount();
        setProgress({ deactivated: true });
      } catch {
      }

      if (state.localDid.startsWith("did:web:")) {
        setProgress({ currentOperation: "Updating DID document forwarding..." });
        try {
          await localClient.updateMigrationForwarding(state.targetPdsUrl);
        } catch (e) {
          console.warn("Failed to update migration forwarding:", e);
        }
      }

      setStep("success");
      clearMigrationState();
    } catch (e) {
      const err = e as Error & { error?: string; status?: number };
      const message = err.message || err.error || `Unknown error (status ${err.status || 'unknown'})`;
      setError(message);
      setStep("plc-token");
    }
  }

  async function resendPlcToken(): Promise<void> {
    if (!localClient) {
      throw new Error("Not connected to local PDS");
    }
    await localClient.requestPlcOperationSignature();
  }

  function reset(): void {
    state = {
      direction: "outbound",
      step: "welcome",
      localDid: "",
      localHandle: "",
      targetPdsUrl: "",
      targetPdsDid: "",
      targetHandle: "",
      targetEmail: "",
      targetPassword: "",
      inviteCode: "",
      targetAccessToken: null,
      targetRefreshToken: null,
      serviceAuthToken: null,
      plcToken: "",
      progress: createInitialProgress(),
      error: null,
      targetServerInfo: null,
    };
    localClient = null;
    targetClient = null;
    clearMigrationState();
  }

  return {
    get state() { return state; },
    setStep,
    setError,
    validateTargetPds,
    initLocalClient,
    startMigration,
    submitPlcToken,
    resendPlcToken,
    reset,

    updateField<K extends keyof OutboundMigrationState>(
      field: K,
      value: OutboundMigrationState[K],
    ) {
      state[field] = value;
    },
  };
}

export type InboundMigrationFlow = ReturnType<typeof createInboundMigrationFlow>;
export type OutboundMigrationFlow = ReturnType<typeof createOutboundMigrationFlow>;
