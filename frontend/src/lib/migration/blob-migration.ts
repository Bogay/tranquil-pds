import type { AtprotoClient } from "./atproto-client";
import type { MigrationProgress } from "./types";

export interface BlobMigrationResult {
  migrated: number;
  failed: string[];
  total: number;
  sourceUnreachable: boolean;
}

export async function migrateBlobs(
  localClient: AtprotoClient,
  sourceClient: AtprotoClient | null,
  userDid: string,
  onProgress: (update: Partial<MigrationProgress>) => void,
): Promise<BlobMigrationResult> {
  const missingBlobs: string[] = [];
  let cursor: string | undefined;

  console.log("[blob-migration] Starting blob migration for", userDid);
  console.log(
    "[blob-migration] Source client:",
    sourceClient ? "available" : "NOT AVAILABLE",
  );

  onProgress({ currentOperation: "Checking for missing blobs..." });

  do {
    const { blobs, cursor: nextCursor } = await localClient.listMissingBlobs(
      cursor,
      100,
    );
    console.log(
      "[blob-migration] listMissingBlobs returned",
      blobs.length,
      "blobs, cursor:",
      nextCursor,
    );
    for (const blob of blobs) {
      missingBlobs.push(blob.cid);
    }
    cursor = nextCursor;
  } while (cursor);

  console.log("[blob-migration] Total missing blobs:", missingBlobs.length);
  onProgress({ blobsTotal: missingBlobs.length });

  if (missingBlobs.length === 0) {
    console.log("[blob-migration] No blobs to migrate");
    onProgress({ currentOperation: "No blobs to migrate" });
    return { migrated: 0, failed: [], total: 0, sourceUnreachable: false };
  }

  if (!sourceClient) {
    console.warn(
      "[blob-migration] No source client available, cannot fetch blobs",
    );
    onProgress({
      currentOperation:
        `${missingBlobs.length} media files missing. No source PDS URL available - your old server may have shut down. Posts will work, but some images/media may be unavailable.`,
    });
    return {
      migrated: 0,
      failed: missingBlobs,
      total: missingBlobs.length,
      sourceUnreachable: true,
    };
  }

  onProgress({ currentOperation: `Migrating ${missingBlobs.length} blobs...` });

  let migrated = 0;
  const failed: string[] = [];
  let sourceUnreachable = false;

  for (const cid of missingBlobs) {
    if (sourceUnreachable) {
      failed.push(cid);
      continue;
    }

    try {
      onProgress({
        currentOperation: `Migrating blob ${
          migrated + 1
        }/${missingBlobs.length}...`,
      });

      console.log("[blob-migration] Fetching blob", cid, "from source");
      const blobData = await sourceClient.getBlob(userDid, cid);
      console.log(
        "[blob-migration] Got blob",
        cid,
        "size:",
        blobData.byteLength,
      );
      await localClient.uploadBlob(blobData, "application/octet-stream");
      console.log("[blob-migration] Uploaded blob", cid);
      migrated++;
      onProgress({ blobsMigrated: migrated });
    } catch (e) {
      const errorMessage = (e as Error).message || String(e);
      console.error(
        "[blob-migration] Failed to migrate blob",
        cid,
        ":",
        errorMessage,
      );

      const isNetworkError =
        errorMessage.includes("fetch") ||
        errorMessage.includes("network") ||
        errorMessage.includes("CORS") ||
        errorMessage.includes("Failed to fetch") ||
        errorMessage.includes("NetworkError") ||
        errorMessage.includes("blocked by CORS");

      if (isNetworkError) {
        sourceUnreachable = true;
        console.warn(
          "[blob-migration] Source appears unreachable (likely CORS or network issue), skipping remaining blobs",
        );
        const remaining = missingBlobs.length - migrated - 1;
        if (migrated > 0) {
          onProgress({
            currentOperation:
              `Source PDS unreachable (browser security restriction). ${migrated} media files migrated successfully. ${remaining + 1} could not be fetched - these may need to be re-uploaded.`,
          });
        } else {
          onProgress({
            currentOperation:
              `Cannot reach source PDS (browser security restriction). This commonly happens when the old server has shut down or doesn't allow cross-origin requests. Your posts will work, but ${missingBlobs.length} media files couldn't be recovered.`,
          });
        }
      }
      failed.push(cid);
    }
  }

  if (migrated === missingBlobs.length) {
    onProgress({
      currentOperation: `All ${migrated} blobs migrated successfully`,
    });
  } else if (migrated > 0) {
    onProgress({
      currentOperation:
        `${migrated}/${missingBlobs.length} blobs migrated. ${failed.length} failed.`,
    });
  } else {
    onProgress({
      currentOperation: `Could not migrate blobs (${failed.length} missing)`,
    });
  }

  return { migrated, failed, total: missingBlobs.length, sourceUnreachable };
}
