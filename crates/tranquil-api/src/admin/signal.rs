use axum::{Json, extract::State};
use base64::{Engine, engine::general_purpose::STANDARD};
use image::{ImageBuffer, Luma};
use serde::Serialize;
use tranquil_pds::api::error::ApiError;
use tranquil_pds::auth::{Admin, Auth};
use tranquil_pds::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalStatusOutput {
    pub enabled: bool,
    pub linked: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalLinkOutput {
    pub qr_base64: String,
}

pub async fn get_signal_status(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
) -> Result<Json<SignalStatusOutput>, ApiError> {
    let enabled = tranquil_config::get().signal.enabled;
    let linked = match &state.signal_sender {
        Some(slot) => slot.is_linked().await,
        None => false,
    };

    Ok(Json(SignalStatusOutput { enabled, linked }))
}

pub async fn link_signal_device(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
) -> Result<Json<SignalLinkOutput>, ApiError> {
    let slot = state
        .signal_sender
        .as_ref()
        .ok_or_else(|| ApiError::InvalidRequest("Signal is not enabled".into()))?;

    if slot.is_linked().await {
        return Err(ApiError::InvalidRequest(
            "Signal device already linked".into(),
        ));
    }

    let (generation, link_cancel) = slot.begin_link().await;

    let device_name = tranquil_signal::DeviceName::new("tranquil-pds".to_string())
        .map_err(|e| ApiError::InternalError(Some(format!("invalid device name: {e}"))))?;

    let signal_store = state
        .signal_store_provider
        .as_ref()
        .ok_or_else(|| ApiError::InternalError(Some("Signal store not configured".into())))?;

    let link_result = signal_store
        .link_signal_device(
            device_name,
            state.shutdown.clone(),
            link_cancel,
            slot.linking_flag(),
        )
        .await
        .map_err(|e| ApiError::InternalError(Some(format!("Signal linking failed: {e}"))))?;

    let qr_base64 = url_to_qr_png_base64(link_result.url.as_str())
        .map_err(|e| ApiError::InternalError(Some(format!("QR generation failed: {e}"))))?;

    let slot_for_task = slot.clone();
    let shutdown = state.shutdown.clone();
    tokio::spawn(async move {
        let result = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                tracing::info!("Signal linking aborted due to server shutdown");
                return;
            }
            r = link_result.completion => r,
        };
        match result {
            Ok(Ok(client)) => {
                if slot_for_task.complete_link(generation, client).await {
                    tracing::info!("Signal device linked successfully");
                } else {
                    tracing::warn!(
                        "Signal link completed but generation mismatch or already linked; discarding"
                    );
                }
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, "Signal device linking failed");
            }
            Err(_) => {
                tracing::error!("Signal linking task dropped without completing");
            }
        }
    });

    Ok(Json(SignalLinkOutput { qr_base64 }))
}

pub async fn unlink_signal_device(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let slot = state
        .signal_sender
        .as_ref()
        .ok_or_else(|| ApiError::InvalidRequest("Signal is not enabled".into()))?;

    let signal_store = state
        .signal_store_provider
        .as_ref()
        .ok_or_else(|| ApiError::InternalError(Some("Signal store not configured".into())))?;

    signal_store
        .clear_signal_data()
        .await
        .map_err(|e| ApiError::InternalError(Some(format!("Failed to clear signal data: {e}"))))?;

    slot.unlink().await;

    Ok(Json(serde_json::json!({})))
}

const QR_MODULE_SCALE: u32 = 8;
const QR_QUIET_ZONE_MODULES: u32 = 4;

fn url_to_qr_png_base64(url: &str) -> Result<String, String> {
    let qr = qrcodegen::QrCode::encode_text(url, qrcodegen::QrCodeEcc::Medium)
        .map_err(|e| format!("QR encode failed: {e:?}"))?;
    let size = u32::try_from(qr.size()).map_err(|_| "QR size is negative".to_string())?;
    let img_size = size
        .checked_add(
            QR_QUIET_ZONE_MODULES
                .checked_mul(2)
                .ok_or("border overflow")?,
        )
        .ok_or("image size overflow")?
        .checked_mul(QR_MODULE_SCALE)
        .ok_or("scaled size overflow")?;

    let img: ImageBuffer<Luma<u8>, Vec<u8>> = ImageBuffer::from_fn(img_size, img_size, |x, y| {
        let module_x = x / QR_MODULE_SCALE;
        let module_y = y / QR_MODULE_SCALE;
        match (
            module_x.checked_sub(QR_QUIET_ZONE_MODULES),
            module_y.checked_sub(QR_QUIET_ZONE_MODULES),
        ) {
            (Some(mx), Some(my)) if mx < size && my < size => {
                if qr.get_module(mx as i32, my as i32) {
                    Luma([0u8])
                } else {
                    Luma([255u8])
                }
            }
            _ => Luma([255u8]),
        }
    });

    let mut png_bytes = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut png_bytes);
    img.write_to(&mut cursor, image::ImageFormat::Png)
        .map_err(|e| format!("PNG encode failed: {e}"))?;

    Ok(STANDARD.encode(&png_bytes))
}
