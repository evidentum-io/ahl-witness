//! The HTTP surface: submit a checkpoint to be witnessed, and read back cosigned checkpoints,
//! refusal evidence, and freshness (core spec §3.3; adaptor profile §11).
//!
//! Every handler blocks on [`crate::store::Store`] (`SQLite`) inside
//! [`tokio::task::spawn_blocking`], so a slow database call never stalls the async runtime.
//! Business rules live in [`crate::witness`], [`crate::consistency`], [`crate::governance`]
//! and [`crate::freshness`] and are unit-tested there directly; the tests in this module check
//! wiring — status codes and request/response shapes — not the rules themselves.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::checkpoint::Checkpoint;
use crate::config::{LogAnchor, WitnessSigner};
use crate::error::WitnessError;
use crate::store::Store;
use crate::witness::{
    published_checkpoint, witness_checkpoint, CosignedCheckpoint, PublishedCheckpoint,
    RefusalEvidence, WitnessOutcome,
};

/// Shared application state, cheap to clone (every field is `Arc`-backed).
#[derive(Clone)]
pub struct AppState {
    /// The durable store.
    pub store: Arc<Store>,
    /// This witness's signing identity.
    pub signer: Arc<dyn WitnessSigner>,
    /// Genesis governance anchors, keyed by `log_id`.
    pub anchors: Arc<HashMap<String, LogAnchor>>,
}

/// Build the witness's router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/witness-key", get(witness_key_handler))
        .route("/v1/logs/{log_id}/witness", post(witness_handler))
        .route("/v1/logs/{log_id}/checkpoint", get(latest_checkpoint_handler))
        .route("/v1/logs/{log_id}/checkpoints", get(history_handler))
        .route("/v1/logs/{log_id}/refusals", get(refusals_handler))
        .route("/v1/logs/{log_id}/freshness", get(freshness_handler))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

/// A [`WitnessError`] wrapped for [`IntoResponse`], mapping each variant to the HTTP status
/// that best matches its meaning.
struct ApiError(WitnessError);

impl From<WitnessError> for ApiError {
    fn from(value: WitnessError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            WitnessError::UnknownLog { .. } => StatusCode::NOT_FOUND,
            WitnessError::Store(_)
            | WitnessError::StoreInit(_)
            | WitnessError::IndexOverflow { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        };
        (status, Json(json!({ "error": self.0.to_string() }))).into_response()
    }
}

async fn blocking<T, F>(f: F) -> Result<T, ApiError>
where
    F: FnOnce() -> Result<T, WitnessError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result.map_err(ApiError::from),
        Err(_join_error) => Err(ApiError::from(WitnessError::StoreInit(
            "blocking task did not complete".to_owned(),
        ))),
    }
}

fn decode_base64_field(value: &str, reason: &'static str) -> Result<Vec<u8>, ApiError> {
    let stripped = value
        .strip_prefix("base64:")
        .ok_or_else(|| ApiError::from(WitnessError::MalformedEnvelope { reason }))?;
    B64.decode(stripped).map_err(|_| ApiError::from(WitnessError::MalformedEnvelope { reason }))
}

fn anchor_for<'a>(
    anchors: &'a HashMap<String, LogAnchor>,
    log_id: &str,
) -> Result<&'a LogAnchor, ApiError> {
    anchors
        .get(log_id)
        .ok_or_else(|| ApiError::from(WitnessError::UnknownLog { log_id: log_id.to_owned() }))
}

// ---------------------------------------------------------------------------
// Witness identity
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct WitnessKeyResponse {
    witness_id: String,
    key_id: String,
}

async fn witness_key_handler(State(state): State<AppState>) -> Json<WitnessKeyResponse> {
    Json(WitnessKeyResponse {
        witness_id: state.signer.witness_id().to_owned(),
        key_id: state.signer.key_id(),
    })
}

// ---------------------------------------------------------------------------
// Witnessing (core spec §3.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct WitnessRequest {
    checkpoint: Checkpoint,
    /// `"base64:" || base64(the 98-byte blob)` (adaptor profile §6.4), optional.
    raw: Option<String>,
    /// Entries covering `[0, checkpoint.tree_size)`, each `"base64:" || base64(JCS(envelope))`.
    entries: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status")]
enum WitnessResponse {
    #[serde(rename = "cosigned")]
    Cosigned {
        #[serde(flatten)]
        checkpoint: Box<CosignedCheckpoint>,
    },
    #[serde(rename = "refused")]
    Refused {
        #[serde(flatten)]
        evidence: Box<RefusalEvidence>,
    },
}

async fn witness_handler(
    State(state): State<AppState>,
    Path(log_id): Path<String>,
    Json(req): Json<WitnessRequest>,
) -> Result<Response, ApiError> {
    let anchor = anchor_for(&state.anchors, &log_id)?.clone();
    let raw = req
        .raw
        .as_deref()
        .map(|v| decode_base64_field(v, "raw must be `base64:...`"))
        .transpose()?;
    let entries = req
        .entries
        .iter()
        .map(|e| decode_base64_field(e, "entries[] must be `base64:...`"))
        .collect::<Result<Vec<_>, _>>()?;

    let store = Arc::clone(&state.store);
    let signer = Arc::clone(&state.signer);
    let now = crate::now_nanos().map_err(ApiError::from)?;
    let outcome = blocking(move || {
        witness_checkpoint(
            &store,
            signer.as_ref(),
            &anchor,
            &req.checkpoint,
            raw.as_deref(),
            &entries,
            now,
        )
    })
    .await?;

    Ok(match outcome {
        WitnessOutcome::Cosigned(checkpoint) => {
            (StatusCode::CREATED, Json(WitnessResponse::Cosigned { checkpoint })).into_response()
        }
        WitnessOutcome::Refused(evidence) => {
            (StatusCode::CONFLICT, Json(WitnessResponse::Refused { evidence })).into_response()
        }
    })
}

// ---------------------------------------------------------------------------
// Reading cosigned checkpoints
// ---------------------------------------------------------------------------

async fn latest_checkpoint_handler(
    State(state): State<AppState>,
    Path(log_id): Path<String>,
) -> Result<Response, ApiError> {
    anchor_for(&state.anchors, &log_id)?;
    let store = Arc::clone(&state.store);
    let log_id_for_query = log_id.clone();
    let view = blocking(move || published_checkpoint(&store, &log_id_for_query)).await?;
    Ok(match view {
        PublishedCheckpoint::Checkpoint(cosigned) => {
            (StatusCode::OK, Json(cosigned)).into_response()
        }
        PublishedCheckpoint::Equivocated { floor_tree_size } => {
            equivocated_response(&log_id, floor_tree_size)
        }
        PublishedCheckpoint::None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "log_id": log_id, "note": "no retained checkpoint yet" })),
        )
            .into_response(),
    })
}

/// The response body core spec §7.3 requires once a log has equivocated: report the
/// divergence, never a chosen branch (see [`crate::witness`]'s module docs, "Equivocation
/// ends the series").
fn equivocated_response(log_id: &str, floor_tree_size: u64) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "log_id": log_id,
            "equivocated": true,
            "floor_tree_size": floor_tree_size,
            "note": "two authenticated checkpoints diverged at this tree_size; nothing at or \
                     beyond it is canonical (core spec §7.3); see /refusals for the evidence",
        })),
    )
        .into_response()
}

async fn history_handler(
    State(state): State<AppState>,
    Path(log_id): Path<String>,
) -> Result<Json<Vec<CosignedCheckpoint>>, ApiError> {
    anchor_for(&state.anchors, &log_id)?;
    let store = Arc::clone(&state.store);
    let history = blocking(move || store.list_cosigned(&log_id)).await?;
    Ok(Json(history.into_iter().map(|r| r.cosigned).collect()))
}

async fn refusals_handler(
    State(state): State<AppState>,
    Path(log_id): Path<String>,
) -> Result<Json<Vec<RefusalEvidence>>, ApiError> {
    anchor_for(&state.anchors, &log_id)?;
    let store = Arc::clone(&state.store);
    let refusals = blocking(move || store.list_refusals(&log_id)).await?;
    Ok(Json(refusals))
}

// ---------------------------------------------------------------------------
// Freshness (core spec §3.3 item 4)
// ---------------------------------------------------------------------------

async fn freshness_handler(
    State(state): State<AppState>,
    Path(log_id): Path<String>,
) -> Result<Response, ApiError> {
    anchor_for(&state.anchors, &log_id)?;
    let store = Arc::clone(&state.store);
    let log_id_for_query = log_id.clone();
    // Freshness is itself a claim grounded on the retained checkpoint: an equivocated log
    // MUST NOT have a freshness number reported for it either (core spec §7.3). Check the
    // equivocation floor first, in the same blocking call as the raw retained row, so the
    // two reads are consistent with each other.
    let (floor, retained) = blocking(move || {
        Ok((store.equivocation_floor(&log_id_for_query)?, store.get_retained(&log_id_for_query)?))
    })
    .await?;
    if let Some(floor_tree_size) = floor {
        return Ok(equivocated_response(&log_id, floor_tree_size));
    }
    let Some(retained) = retained else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(json!({ "log_id": log_id, "note": "no retained checkpoint yet" })),
        )
            .into_response());
    };
    let now = crate::now_nanos().map_err(ApiError::from)?;
    let freshness = crate::freshness::evaluate(
        &retained.checkpoint().checkpoint_time,
        retained.cadence_nanos,
        retained.grace_nanos,
        now,
    )
    .map_err(ApiError::from)?;
    Ok(Json(freshness).into_response())
}

#[cfg(test)]
mod tests {
    use atl_core::core::merkle::{compute_root, Hash};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;
    use crate::config::{Ed25519WitnessSigner, KeyObjectSpec, LogAnchorSpec};
    use crate::metadata::log_leaf_hash;

    struct Harness {
        state: AppState,
        log_id: String,
        log_key: ahl_core::TestKey,
        genesis_leaf: Hash,
    }

    fn genesis_manifest_bytes(
        log_id: &str,
        producer: &ahl_core::TestKey,
        log_key: &ahl_core::TestKey,
    ) -> Vec<u8> {
        let payload = serde_json::json!({
            "type": "manifest",
            "producer": "producer-1",
            "keys": [
                { "key_id": producer.key_id(), "pubkey": producer.pubkey(), "valid_from_index": 0 }
            ],
            "log": {
                "log_id": log_id,
                "operator": "op-1",
                "adaptor": { "id": "ahl-adaptor-atl-v1", "hash": "sha256:00" },
                "checkpoint_cadence": "PT5M",
                "cadence_epoch": "2026-01-01T00:00:00Z",
                "witness_grace_period": "PT1M",
                "keys": [
                    { "key_id": log_key.key_id(), "pubkey": log_key.pubkey(), "valid_from_index": 0 }
                ],
            },
        });
        ahl_core::jcs(&ahl_core::envelope(payload, producer))
    }

    fn harness() -> Harness {
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"a0".repeat(32)).expect("seed");
        let log_key = ahl_core::TestKey::from_seed_hex("log", &"a1".repeat(32)).expect("seed");
        let log_id = format!("sha256:{}", "a2".repeat(32));
        let genesis_bytes = genesis_manifest_bytes(&log_id, &producer, &log_key);
        let genesis_id =
            ahl_core::entry_id(&serde_json::from_slice(&genesis_bytes).expect("well-formed json"));
        let genesis_leaf = log_leaf_hash(&genesis_bytes);

        let anchor = LogAnchor::resolve(&LogAnchorSpec {
            log_id: log_id.clone(),
            genesis_manifest_entry_id: genesis_id,
            genesis_producer_keys: vec![KeyObjectSpec {
                key_id: producer.key_id(),
                pubkey: producer.pubkey(),
                valid_from_index: 0,
            }],
        })
        .expect("valid anchor");

        let mut anchors = HashMap::new();
        anchors.insert(log_id.clone(), anchor);

        let store = Store::open_in_memory().expect("in-memory store");
        let signer = Ed25519WitnessSigner::from_seed("witness-1", &[3u8; 32]).expect("32 bytes");

        Harness {
            state: AppState {
                store: Arc::new(store),
                signer: Arc::new(signer),
                anchors: Arc::new(anchors),
            },
            log_id,
            log_key,
            genesis_leaf,
        }
    }

    fn signed_checkpoint(hx: &Harness, root: Hash, time: &str) -> Checkpoint {
        let mut cp = Checkpoint {
            log_id: hx.log_id.clone(),
            tree_size: 1,
            root_hash: format!("sha256:{}", hex::encode(root)),
            checkpoint_time: time.to_owned(),
            key_id: hx.log_key.key_id(),
            signature: String::new(),
        };
        let blob = crate::checkpoint::checkpoint_blob(&cp).expect("well-formed");
        cp.signature = hx.log_key.sign(&blob);
        cp
    }

    fn witness_body(cp: &Checkpoint, entries: &[Vec<u8>]) -> serde_json::Value {
        json!({
            "checkpoint": cp,
            "raw": null,
            "entries": entries.iter().map(|e| format!("base64:{}", B64.encode(e))).collect::<Vec<_>>(),
        })
    }

    #[tokio::test]
    async fn health_reports_ok() {
        let app = router(harness().state);
        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).expect("valid request"))
            .await
            .expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn witness_key_reports_the_configured_identity() {
        let app = router(harness().state);
        let response = app
            .oneshot(Request::get("/v1/witness-key").body(Body::empty()).expect("valid request"))
            .await
            .expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(value["witness_id"], "witness-1");
    }

    #[tokio::test]
    async fn a_genesis_only_checkpoint_is_cosigned_over_http() {
        let hx = harness();
        let app = router(hx.state.clone());
        let root = compute_root(&[hx.genesis_leaf]);
        let cp = signed_checkpoint(&hx, root, "2026-01-01T00:00:00.000000000Z");
        let genesis_bytes = genesis_manifest_bytes(
            &hx.log_id,
            &ahl_core::TestKey::from_seed_hex("producer", &"a0".repeat(32)).expect("seed"),
            &hx.log_key,
        );
        let body = witness_body(&cp, &[genesis_bytes]);

        let request = Request::post(format!("/v1/logs/{}/witness", hx.log_id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
            .expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::CREATED);

        let request = Request::get(format!("/v1/logs/{}/checkpoint", hx.log_id))
            .body(Body::empty())
            .expect("valid");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);

        let request = Request::get(format!("/v1/logs/{}/checkpoints", hx.log_id))
            .body(Body::empty())
            .expect("valid");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let history: Vec<CosignedCheckpoint> = serde_json::from_slice(&body).expect("json");
        assert_eq!(history.len(), 1);

        let request = Request::get(format!("/v1/logs/{}/freshness", hx.log_id))
            .body(Body::empty())
            .expect("valid");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_unknown_log_is_a_404() {
        let app = router(harness().state);
        let request = Request::get("/v1/logs/sha256:missing/checkpoint")
            .body(Body::empty())
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn freshness_before_any_checkpoint_is_a_404() {
        let app = router(harness().state);
        let hx_log_id = format!("sha256:{}", "a2".repeat(32));
        let request = Request::get(format!("/v1/logs/{hx_log_id}/freshness"))
            .body(Body::empty())
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn an_equivocating_checkpoint_is_refused_over_http() {
        let hx = harness();
        let app = router(hx.state.clone());
        let producer =
            ahl_core::TestKey::from_seed_hex("producer", &"a0".repeat(32)).expect("seed");
        let genesis_bytes = genesis_manifest_bytes(&hx.log_id, &producer, &hx.log_key);

        let root = compute_root(&[hx.genesis_leaf]);
        let cp1 = signed_checkpoint(&hx, root, "2026-01-01T00:00:00.000000000Z");
        let body1 = witness_body(&cp1, std::slice::from_ref(&genesis_bytes));
        let request = Request::post(format!("/v1/logs/{}/witness", hx.log_id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body1).expect("serialize")))
            .expect("valid request");
        assert_eq!(
            app.clone().oneshot(request).await.expect("service call").status(),
            StatusCode::CREATED
        );

        let cp2 = signed_checkpoint(&hx, [0x55u8; 32], "2026-01-01T00:05:00.000000000Z");
        let body2 = witness_body(&cp2, &[genesis_bytes]);
        let request = Request::post(format!("/v1/logs/{}/witness", hx.log_id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body2).expect("serialize")))
            .expect("valid request");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let request = Request::get(format!("/v1/logs/{}/refusals", hx.log_id))
            .body(Body::empty())
            .expect("valid");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let refusals: Vec<RefusalEvidence> = serde_json::from_slice(&body).expect("json");
        assert_eq!(refusals.len(), 1);

        // Core spec §7.3: the published view now reports the divergence, not the branch
        // cosigned before it was found — checked over both the checkpoint and freshness
        // read endpoints.
        let request = Request::get(format!("/v1/logs/{}/checkpoint", hx.log_id))
            .body(Body::empty())
            .expect("valid");
        let response = app.clone().oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(value["equivocated"], true);
        assert_eq!(value["floor_tree_size"], 1);

        let request = Request::get(format!("/v1/logs/{}/freshness", hx.log_id))
            .body(Body::empty())
            .expect("valid");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn a_malformed_witness_request_is_a_400() {
        let hx = harness();
        let app = router(hx.state.clone());
        let cp = signed_checkpoint(&hx, [0u8; 32], "2026-01-01T00:00:00.000000000Z");
        let body = json!({ "checkpoint": cp, "raw": "not-base64-prefixed", "entries": [] });
        let request = Request::post(format!("/v1/logs/{}/witness", hx.log_id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn witnessing_against_an_unconfigured_log_is_a_404() {
        let app = router(harness().state);
        let cp = Checkpoint {
            log_id: "sha256:unconfigured".to_owned(),
            tree_size: 1,
            root_hash: format!("sha256:{}", "00".repeat(32)),
            checkpoint_time: "2026-01-01T00:00:00.000000000Z".to_owned(),
            key_id: "sha256:bb".to_owned(),
            signature: "base64:AAAA".to_owned(),
        };
        let body = witness_body(&cp, &[]);
        let request = Request::post("/v1/logs/sha256:unconfigured/witness")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
