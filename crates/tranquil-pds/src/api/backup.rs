use crate::api::error::ApiError;
use crate::api::{EmptyResponse, EnabledResponse};
use crate::auth::{Active, Auth};
use crate::scheduled::generate_full_backup;
use crate::state::AppState;
use crate::storage::{BackupStorage, backup_retention_count};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cid::Cid;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use tracing::{error, info, warn};
use tranquil_db::{BackupRepository, OldBackupInfo};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInfo {
    pub id: String,
    pub repo_rev: String,
    pub repo_root_cid: String,
    pub block_count: i32,
    pub size_bytes: i64,
    pub created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListBackupsOutput {
    pub backups: Vec<BackupInfo>,
    pub backup_enabled: bool,
}

pub async fn list_backups(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, crate::api::error::ApiError> {
    let (user_id, backup_enabled) = match state.backup_repo.get_user_backup_status(&auth.did).await
    {
        Ok(Some(status)) => status,
        Ok(None) => {
            return Ok(ApiError::AccountNotFound.into_response());
        }
        Err(e) => {
            error!("DB error fetching user: {:?}", e);
            return Ok(ApiError::InternalError(None).into_response());
        }
    };

    let backups = match state.backup_repo.list_backups_for_user(user_id).await {
        Ok(rows) => rows,
        Err(e) => {
            error!("DB error fetching backups: {:?}", e);
            return Ok(ApiError::InternalError(None).into_response());
        }
    };

    let backup_list: Vec<BackupInfo> = backups
        .into_iter()
        .map(|b| BackupInfo {
            id: b.id.to_string(),
            repo_rev: b.repo_rev,
            repo_root_cid: b.repo_root_cid,
            block_count: b.block_count,
            size_bytes: b.size_bytes,
            created_at: b.created_at.to_rfc3339(),
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(ListBackupsOutput {
            backups: backup_list,
            backup_enabled,
        }),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct GetBackupQuery {
    pub id: String,
}

pub async fn get_backup(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Query(query): Query<GetBackupQuery>,
) -> Result<Response, crate::api::error::ApiError> {
    let backup_id = match uuid::Uuid::parse_str(&query.id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(ApiError::InvalidRequest("Invalid backup ID".into()).into_response());
        }
    };

    let backup_info = match state
        .backup_repo
        .get_backup_storage_info(backup_id, &auth.did)
        .await
    {
        Ok(Some(b)) => b,
        Ok(None) => {
            return Ok(ApiError::BackupNotFound.into_response());
        }
        Err(e) => {
            error!("DB error fetching backup: {:?}", e);
            return Ok(ApiError::InternalError(None).into_response());
        }
    };

    let backup_storage = match state.backup_storage.as_ref() {
        Some(storage) => storage,
        None => {
            return Ok(ApiError::BackupsDisabled.into_response());
        }
    };

    let car_bytes = match backup_storage.get_backup(&backup_info.storage_key).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to fetch backup from storage: {:?}", e);
            return Ok(
                ApiError::InternalError(Some("Failed to retrieve backup".into())).into_response(),
            );
        }
    };

    Ok((
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/vnd.ipld.car"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                &format!("attachment; filename=\"{}.car\"", backup_info.repo_rev),
            ),
        ],
        car_bytes,
    )
        .into_response())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBackupOutput {
    pub id: String,
    pub repo_rev: String,
    pub size_bytes: i64,
    pub block_count: i32,
}

pub async fn create_backup(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, crate::api::error::ApiError> {
    let backup_storage = match state.backup_storage.as_ref() {
        Some(storage) => storage,
        None => {
            return Ok(ApiError::BackupsDisabled.into_response());
        }
    };

    let user = match state.backup_repo.get_user_for_backup(&auth.did).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return Ok(ApiError::AccountNotFound.into_response());
        }
        Err(e) => {
            error!("DB error fetching user: {:?}", e);
            return Ok(ApiError::InternalError(None).into_response());
        }
    };

    if user.deactivated_at.is_some() {
        return Ok(ApiError::AccountDeactivated.into_response());
    }

    let repo_rev = match &user.repo_rev {
        Some(rev) => rev.clone(),
        None => {
            return Ok(ApiError::RepoNotReady.into_response());
        }
    };

    let head_cid = match Cid::from_str(&user.repo_root_cid) {
        Ok(c) => c,
        Err(_) => {
            return Ok(
                ApiError::InternalError(Some("Invalid repo root CID".into())).into_response(),
            );
        }
    };

    let car_bytes = match generate_full_backup(
        state.repo_repo.as_ref(),
        &state.block_store,
        user.id,
        &head_cid,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to generate CAR: {:?}", e);
            return Ok(
                ApiError::InternalError(Some("Failed to generate backup".into())).into_response(),
            );
        }
    };

    let block_count = crate::scheduled::count_car_blocks(&car_bytes);
    let size_bytes = car_bytes.len() as i64;

    let storage_key = match backup_storage
        .put_backup(&user.did, &repo_rev, &car_bytes)
        .await
    {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to upload backup: {:?}", e);
            return Ok(
                ApiError::InternalError(Some("Failed to store backup".into())).into_response(),
            );
        }
    };

    let backup_id = match state
        .backup_repo
        .insert_backup(
            user.id,
            &storage_key,
            &user.repo_root_cid,
            &repo_rev,
            block_count,
            size_bytes,
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            error!("DB error inserting backup: {:?}", e);
            if let Err(rollback_err) = backup_storage.delete_backup(&storage_key).await {
                error!(
                    storage_key = %storage_key,
                    error = %rollback_err,
                    "Failed to rollback orphaned backup from S3"
                );
            }
            return Ok(
                ApiError::InternalError(Some("Failed to record backup".into())).into_response(),
            );
        }
    };

    info!(
        did = %user.did,
        rev = %repo_rev,
        size_bytes,
        "Created manual backup"
    );

    let retention = backup_retention_count();
    if let Err(e) = cleanup_old_backups(
        state.backup_repo.as_ref(),
        backup_storage.as_ref(),
        user.id,
        retention,
    )
    .await
    {
        warn!(did = %user.did, error = %e, "Failed to cleanup old backups after manual backup");
    }

    Ok((
        StatusCode::OK,
        Json(CreateBackupOutput {
            id: backup_id.to_string(),
            repo_rev,
            size_bytes,
            block_count,
        }),
    )
        .into_response())
}

async fn cleanup_old_backups(
    backup_repo: &dyn BackupRepository,
    backup_storage: &dyn BackupStorage,
    user_id: uuid::Uuid,
    retention_count: u32,
) -> Result<(), String> {
    let old_backups: Vec<OldBackupInfo> = backup_repo
        .get_old_backups(user_id, retention_count as i64)
        .await
        .map_err(|e| format!("DB error fetching old backups: {}", e))?;

    for backup in old_backups {
        if let Err(e) = backup_storage.delete_backup(&backup.storage_key).await {
            warn!(
                storage_key = %backup.storage_key,
                error = %e,
                "Failed to delete old backup from storage, skipping DB cleanup to avoid orphan"
            );
            continue;
        }

        backup_repo
            .delete_backup(backup.id)
            .await
            .map_err(|e| format!("Failed to delete old backup record: {}", e))?;
    }

    Ok(())
}

#[derive(Deserialize)]
pub struct DeleteBackupQuery {
    pub id: String,
}

pub async fn delete_backup(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Query(query): Query<DeleteBackupQuery>,
) -> Result<Response, crate::api::error::ApiError> {
    let backup_id = match uuid::Uuid::parse_str(&query.id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(ApiError::InvalidRequest("Invalid backup ID".into()).into_response());
        }
    };

    let backup = match state
        .backup_repo
        .get_backup_for_deletion(backup_id, &auth.did)
        .await
    {
        Ok(Some(b)) => b,
        Ok(None) => {
            return Ok(ApiError::BackupNotFound.into_response());
        }
        Err(e) => {
            error!("DB error fetching backup: {:?}", e);
            return Ok(ApiError::InternalError(None).into_response());
        }
    };

    if backup.deactivated_at.is_some() {
        return Ok(ApiError::AccountDeactivated.into_response());
    }

    if let Some(backup_storage) = state.backup_storage.as_ref()
        && let Err(e) = backup_storage.delete_backup(&backup.storage_key).await
    {
        warn!(
            storage_key = %backup.storage_key,
            error = %e,
            "Failed to delete backup from storage (continuing anyway)"
        );
    }

    if let Err(e) = state.backup_repo.delete_backup(backup.id).await {
        error!("DB error deleting backup: {:?}", e);
        return Ok(ApiError::InternalError(Some("Failed to delete backup".into())).into_response());
    }

    info!(did = %auth.did, backup_id = %backup_id, "Deleted backup");

    Ok(EmptyResponse::ok().into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetBackupEnabledInput {
    pub enabled: bool,
}

pub async fn set_backup_enabled(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<SetBackupEnabledInput>,
) -> Result<Response, crate::api::error::ApiError> {
    let deactivated_at = match state
        .backup_repo
        .get_user_deactivated_status(&auth.did)
        .await
    {
        Ok(Some(status)) => status,
        Ok(None) => {
            return Ok(ApiError::AccountNotFound.into_response());
        }
        Err(e) => {
            error!("DB error fetching user: {:?}", e);
            return Ok(ApiError::InternalError(None).into_response());
        }
    };

    if deactivated_at.is_some() {
        return Ok(ApiError::AccountDeactivated.into_response());
    }

    if let Err(e) = state
        .backup_repo
        .update_backup_enabled(&auth.did, input.enabled)
        .await
    {
        error!("DB error updating backup_enabled: {:?}", e);
        return Ok(
            ApiError::InternalError(Some("Failed to update setting".into())).into_response(),
        );
    }

    info!(did = %auth.did, enabled = input.enabled, "Updated backup_enabled setting");

    Ok(EnabledResponse::response(input.enabled).into_response())
}

pub async fn export_blobs(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, crate::api::error::ApiError> {
    let user_id = match state.backup_repo.get_user_id_by_did(&auth.did).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return Ok(ApiError::AccountNotFound.into_response());
        }
        Err(e) => {
            error!("DB error fetching user: {:?}", e);
            return Ok(ApiError::InternalError(None).into_response());
        }
    };

    let blobs = match state.backup_repo.get_blobs_for_export(user_id).await {
        Ok(rows) => rows,
        Err(e) => {
            error!("DB error fetching blobs: {:?}", e);
            return Ok(ApiError::InternalError(None).into_response());
        }
    };

    if blobs.is_empty() {
        return Ok((
            StatusCode::OK,
            [
                (axum::http::header::CONTENT_TYPE, "application/zip"),
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    "attachment; filename=\"blobs.zip\"",
                ),
            ],
            Vec::<u8>::new(),
        )
            .into_response());
    }

    let mut zip_buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut zip_buffer);

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        let mut exported: Vec<serde_json::Value> = Vec::new();
        let mut skipped: Vec<serde_json::Value> = Vec::new();

        for blob in &blobs {
            let blob_data = match state.blob_store.get(&blob.storage_key).await {
                Ok(data) => data,
                Err(e) => {
                    warn!(cid = %blob.cid, error = %e, "Failed to fetch blob, skipping");
                    skipped.push(json!({
                        "cid": blob.cid,
                        "mimeType": blob.mime_type,
                        "reason": "fetch_failed"
                    }));
                    continue;
                }
            };

            let extension = mime_to_extension(&blob.mime_type);
            let filename = format!("{}{}", blob.cid, extension);

            if let Err(e) = zip.start_file(&filename, options) {
                warn!(filename = %filename, error = %e, "Failed to start zip file entry");
                skipped.push(json!({
                    "cid": blob.cid,
                    "mimeType": blob.mime_type,
                    "reason": "zip_entry_failed"
                }));
                continue;
            }

            if let Err(e) = std::io::Write::write_all(&mut zip, &blob_data) {
                warn!(filename = %filename, error = %e, "Failed to write blob to zip");
                skipped.push(json!({
                    "cid": blob.cid,
                    "mimeType": blob.mime_type,
                    "reason": "write_failed"
                }));
                continue;
            }

            exported.push(json!({
                "cid": blob.cid,
                "filename": filename,
                "mimeType": blob.mime_type,
                "sizeBytes": blob_data.len()
            }));
        }

        let manifest = json!({
            "exportedAt": chrono::Utc::now().to_rfc3339(),
            "totalBlobs": blobs.len(),
            "exportedCount": exported.len(),
            "skippedCount": skipped.len(),
            "exported": exported,
            "skipped": skipped
        });

        if zip.start_file("manifest.json", options).is_ok() {
            let _ = std::io::Write::write_all(
                &mut zip,
                serde_json::to_string_pretty(&manifest)
                    .unwrap_or_else(|_| "{}".to_string())
                    .as_bytes(),
            );
        }

        if let Err(e) = zip.finish() {
            error!("Failed to finish zip: {:?}", e);
            return Ok(
                ApiError::InternalError(Some("Failed to create zip file".into())).into_response(),
            );
        }
    }

    let zip_bytes = zip_buffer.into_inner();

    info!(did = %auth.did, blob_count = blobs.len(), size_bytes = zip_bytes.len(), "Exported blobs");

    Ok((
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/zip"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"blobs.zip\"",
            ),
        ],
        zip_bytes,
    )
        .into_response())
}

fn mime_to_extension(mime_type: &str) -> &'static str {
    match mime_type {
        "application/font-sfnt" => ".otf",
        "application/font-tdpfr" => ".pfr",
        "application/font-woff" => ".woff",
        "application/gzip" => ".gz",
        "application/json" => ".json",
        "application/json5" => ".json5",
        "application/jsonml+json" => ".jsonml",
        "application/octet-stream" => ".bin",
        "application/pdf" => ".pdf",
        "application/zip" => ".zip",
        "audio/aac" => ".aac",
        "audio/ac3" => ".ac3",
        "audio/aiff" => ".aiff",
        "audio/annodex" => ".axa",
        "audio/audible" => ".aa",
        "audio/basic" => ".au",
        "audio/flac" => ".flac",
        "audio/m4a" => ".m4a",
        "audio/m4b" => ".m4b",
        "audio/m4p" => ".m4p",
        "audio/mid" => ".mid",
        "audio/midi" => ".midi",
        "audio/mp4" => ".mp4a",
        "audio/mpeg" => ".mp3",
        "audio/ogg" => ".ogg",
        "audio/s3m" => ".s3m",
        "audio/scpls" => ".pls",
        "audio/silk" => ".sil",
        "audio/vnd.audible.aax" => ".aax",
        "audio/vnd.dece.audio" => ".uva",
        "audio/vnd.digital-winds" => ".eol",
        "audio/vnd.dlna.adts" => ".adt",
        "audio/vnd.dra" => ".dra",
        "audio/vnd.dts" => ".dts",
        "audio/vnd.dts.hd" => ".dtshd",
        "audio/vnd.lucent.voice" => ".lvp",
        "audio/vnd.ms-playready.media.pya" => ".pya",
        "audio/vnd.nuera.ecelp4800" => ".ecelp4800",
        "audio/vnd.nuera.ecelp7470" => ".ecelp7470",
        "audio/vnd.nuera.ecelp9600" => ".ecelp9600",
        "audio/vnd.rip" => ".rip",
        "audio/wav" => ".wav",
        "audio/webm" => ".weba",
        "audio/x-caf" => ".caf",
        "audio/x-gsm" => ".gsm",
        "audio/x-m4r" => ".m4r",
        "audio/x-matroska" => ".mka",
        "audio/x-mpegurl" => ".m3u",
        "audio/x-ms-wax" => ".wax",
        "audio/x-ms-wma" => ".wma",
        "audio/x-pn-realaudio" => ".ra",
        "audio/x-pn-realaudio-plugin" => ".rpm",
        "audio/x-sd2" => ".sd2",
        "audio/x-smd" => ".smd",
        "audio/xm" => ".xm",
        "font/collection" => ".ttc",
        "font/ttf" => ".ttf",
        "font/woff" => ".woff",
        "font/woff2" => ".woff2",
        "image/apng" => ".apng",
        "image/avif" => ".avif",
        "image/avif-sequence" => ".avifs",
        "image/bmp" => ".bmp",
        "image/cgm" => ".cgm",
        "image/cis-cod" => ".cod",
        "image/g3fax" => ".g3",
        "image/gif" => ".gif",
        "image/heic" => ".heic",
        "image/heic-sequence" => ".heics",
        "image/heif" => ".heif",
        "image/heif-sequence" => ".heifs",
        "image/ief" => ".ief",
        "image/jp2" => ".jp2",
        "image/jpeg" => ".jpg",
        "image/jpm" => ".jpm",
        "image/jpx" => ".jpf",
        "image/jxl" => ".jxl",
        "image/ktx" => ".ktx",
        "image/pict" => ".pct",
        "image/png" => ".png",
        "image/prs.btif" => ".btif",
        "image/qoi" => ".qoi",
        "image/sgi" => ".sgi",
        "image/svg+xml" => ".svg",
        "image/tiff" => ".tiff",
        "image/vnd.dece.graphic" => ".uvg",
        "image/vnd.djvu" => ".djv",
        "image/vnd.fastbidsheet" => ".fbs",
        "image/vnd.fpx" => ".fpx",
        "image/vnd.fst" => ".fst",
        "image/vnd.fujixerox.edmics-mmr" => ".mmr",
        "image/vnd.fujixerox.edmics-rlc" => ".rlc",
        "image/vnd.ms-modi" => ".mdi",
        "image/vnd.ms-photo" => ".wdp",
        "image/vnd.net-fpx" => ".npx",
        "image/vnd.radiance" => ".hdr",
        "image/vnd.rn-realflash" => ".rf",
        "image/vnd.wap.wbmp" => ".wbmp",
        "image/vnd.xiff" => ".xif",
        "image/webp" => ".webp",
        "image/x-3ds" => ".3ds",
        "image/x-adobe-dng" => ".dng",
        "image/x-canon-cr2" => ".cr2",
        "image/x-canon-cr3" => ".cr3",
        "image/x-canon-crw" => ".crw",
        "image/x-cmu-raster" => ".ras",
        "image/x-cmx" => ".cmx",
        "image/x-epson-erf" => ".erf",
        "image/x-freehand" => ".fh",
        "image/x-fuji-raf" => ".raf",
        "image/x-icon" => ".ico",
        "image/x-jg" => ".art",
        "image/x-jng" => ".jng",
        "image/x-kodak-dcr" => ".dcr",
        "image/x-kodak-k25" => ".k25",
        "image/x-kodak-kdc" => ".kdc",
        "image/x-macpaint" => ".mac",
        "image/x-minolta-mrw" => ".mrw",
        "image/x-mrsid-image" => ".sid",
        "image/x-nikon-nef" => ".nef",
        "image/x-nikon-nrw" => ".nrw",
        "image/x-olympus-orf" => ".orf",
        "image/x-panasonic-rw" => ".raw",
        "image/x-panasonic-rw2" => ".rw2",
        "image/x-pentax-pef" => ".pef",
        "image/x-portable-anymap" => ".pnm",
        "image/x-portable-bitmap" => ".pbm",
        "image/x-portable-graymap" => ".pgm",
        "image/x-portable-pixmap" => ".ppm",
        "image/x-qoi" => ".qoi",
        "image/x-quicktime" => ".qti",
        "image/x-rgb" => ".rgb",
        "image/x-sigma-x3f" => ".x3f",
        "image/x-sony-arw" => ".arw",
        "image/x-sony-sr2" => ".sr2",
        "image/x-sony-srf" => ".srf",
        "image/x-tga" => ".tga",
        "image/x-xbitmap" => ".xbm",
        "image/x-xcf" => ".xcf",
        "image/x-xpixmap" => ".xpm",
        "image/x-xwindowdump" => ".xwd",
        "model/gltf+json" => ".gltf",
        "model/gltf-binary" => ".glb",
        "model/iges" => ".igs",
        "model/mesh" => ".msh",
        "model/vnd.collada+xml" => ".dae",
        "model/vnd.gdl" => ".gdl",
        "model/vnd.gtw" => ".gtw",
        "model/vnd.vtu" => ".vtu",
        "model/vrml" => ".vrml",
        "model/x3d+binary" => ".x3db",
        "model/x3d+vrml" => ".x3dv",
        "model/x3d+xml" => ".x3d",
        "text/css" => ".css",
        "text/html" => ".html",
        "text/plain" => ".txt",
        "video/3gpp" => ".3gp",
        "video/3gpp2" => ".3g2",
        "video/annodex" => ".axv",
        "video/divx" => ".divx",
        "video/h261" => ".h261",
        "video/h263" => ".h263",
        "video/h264" => ".h264",
        "video/jpeg" => ".jpgv",
        "video/jpm" => ".jpgm",
        "video/mj2" => ".mj2",
        "video/mp4" => ".mp4",
        "video/mpeg" => ".mpg",
        "video/ogg" => ".ogv",
        "video/quicktime" => ".mov",
        "video/vnd.dece.hd" => ".uvh",
        "video/vnd.dece.mobile" => ".uvm",
        "video/vnd.dece.pd" => ".uvp",
        "video/vnd.dece.sd" => ".uvs",
        "video/vnd.dece.video" => ".uvv",
        "video/vnd.dlna.mpeg-tts" => ".ts",
        "video/vnd.dvb.file" => ".dvb",
        "video/vnd.fvt" => ".fvt",
        "video/vnd.mpegurl" => ".m4u",
        "video/vnd.ms-playready.media.pyv" => ".pyv",
        "video/vnd.uvvu.mp4" => ".uvu",
        "video/vnd.vivo" => ".viv",
        "video/webm" => ".webm",
        "video/x-dv" => ".dv",
        "video/x-f4v" => ".f4v",
        "video/x-fli" => ".fli",
        "video/x-flv" => ".flv",
        "video/x-ivf" => ".ivf",
        "video/x-la-asf" => ".lsf",
        "video/x-m4v" => ".m4v",
        "video/x-matroska" => ".mkv",
        "video/x-mng" => ".mng",
        "video/x-ms-asf" => ".asf",
        "video/x-ms-vob" => ".vob",
        "video/x-ms-wm" => ".wm",
        "video/x-ms-wmp" => ".wmp",
        "video/x-ms-wmv" => ".wmv",
        "video/x-ms-wmx" => ".wmx",
        "video/x-ms-wvx" => ".wvx",
        "video/x-msvideo" => ".avi",
        "video/x-sgi-movie" => ".movie",
        "video/x-smv" => ".smv",
        _ => ".bin",
    }
}
