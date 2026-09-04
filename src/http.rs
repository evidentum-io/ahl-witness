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
        .route(
            "/v1/logs/{log_id}/rotation-cosignatures/{manifest_entry_index}",
            get(rotation_cosignatures_handler),
        )
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
            WitnessError::UnknownLog { .. } | WitnessError::UnknownRotationCosignature { .. } => {
                StatusCode::NOT_FOUND
            }
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
#[serde(deny_unknown_fields)]
struct WitnessRequest {
    checkpoint: Checkpoint,
    /// `"base64:" || base64(the 98-byte blob)` (adaptor profile §6.4), optional.
    ///
    /// The framing belongs HERE and not inside `checkpoint`: §11.1 excludes it from the
    /// cosignature preimage, so carrying it inside the object the witness cosigns would
    /// describe a submission the witness cannot honour as sent.
    raw: Option<String>,
    /// Entries covering `[0, checkpoint.tree_size)`, each `"base64:" || base64(JCS(envelope))`.
    entries: Vec<String>,
}

/// The members a witness submission defines, and the members its checkpoint defines.
const REQUEST_MEMBERS: [&str; 3] = ["checkpoint", "raw", "entries"];
const CHECKPOINT_MEMBERS: [&str; 6] =
    ["log_id", "tree_size", "root_hash", "checkpoint_time", "key_id", "signature"];

/// Parse a submission, refusing any member the request or its checkpoint does not define.
///
/// `deny_unknown_fields` on the two types already refuses the same material; this runs first so
/// that the refusal is one of this crate's own errors, NAMING the offending member, rather than
/// the extractor's generic deserialization rejection. The member matters to whoever sent it:
/// the case in practice is `raw` placed inside the checkpoint, which is a correct member of a
/// receipt-borne checkpoint (I-D §7.1) and belongs at the request's top level here, and a
/// submitter told only "the body did not deserialize" has to guess that.
fn parse_witness_request(body: serde_json::Value) -> Result<WitnessRequest, WitnessError> {
    if let Some(members) = body.as_object() {
        if let Some(extra) = members.keys().find(|m| !REQUEST_MEMBERS.contains(&m.as_str())) {
            return Err(WitnessError::UnknownRequestMember { member: extra.clone() });
        }
        if let Some(checkpoint) = members.get("checkpoint").and_then(serde_json::Value::as_object) {
            if let Some(extra) =
                checkpoint.keys().find(|m| !CHECKPOINT_MEMBERS.contains(&m.as_str()))
            {
                return Err(WitnessError::UnknownCheckpointMember { member: extra.clone() });
            }
        }
    }
    Ok(serde_json::from_value(body)?)
}

#[derive(Debug, Serialize)]
#[serde(tag = "status")]
enum WitnessResponse {
    #[serde(rename = "cosigned")]
    Cosigned {
        #[serde(flatten)]
        checkpoint: Box<CosignedCheckpoint>,
    },
    /// Cosigned as ROTATION-ANCHORING material under the OUTGOING governance state (I-D
    /// §7.1). Reported under its own status rather than as an ordinary cosigning, because the
    /// result is deliberately absent from the series routes: a submitter told only "cosigned"
    /// would have no way to tell the two apart except by the checkpoint's later absence.
    #[serde(rename = "cosigned-rotation")]
    CosignedRotation {
        /// The entry index of the rotating manifest this checkpoint anchors.
        manifest_entry_index: u64,
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
    Json(body): Json<serde_json::Value>,
) -> Result<Response, ApiError> {
    let anchor = anchor_for(&state.anchors, &log_id)?.clone();
    let req = parse_witness_request(body).map_err(ApiError::from)?;
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
        WitnessOutcome::CosignedRotation { manifest_entry_index, cosigned } => (
            StatusCode::CREATED,
            Json(WitnessResponse::CosignedRotation { manifest_entry_index, checkpoint: cosigned }),
        )
            .into_response(),
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

/// The cosignatures this witness holds over rotation-anchoring material for one rotation.
///
/// The `witnesses` member is in the shape of I-D §7.1's `anchoring.witnesses[]` — the same
/// shape a `governance.rotation_proofs[]` element's own `witnesses` takes — so a receipt
/// producer copies it into the element a mirror serves and changes nothing. `checkpoint` is
/// carried alongside so that the pairing is checkable without a second request: a cosignature
/// is over one checkpoint, and an element whose `checkpoint` is a different one is not the
/// element these cosignatures attest.
#[derive(Debug, Serialize)]
struct RotationCosignaturesResponse {
    log_id: String,
    manifest_entry_index: u64,
    checkpoint: crate::checkpoint::Checkpoint,
    witnesses: Vec<RotationWitnessEntry>,
}

/// One `anchoring.witnesses[]` element (I-D §7.1).
#[derive(Debug, Serialize)]
struct RotationWitnessEntry {
    witness_id: String,
    key_id: String,
    cosignature: String,
    cosigned_at: String,
}

async fn rotation_cosignatures_handler(
    State(state): State<AppState>,
    Path((log_id, manifest_entry_index)): Path<(String, u64)>,
) -> Result<Response, ApiError> {
    anchor_for(&state.anchors, &log_id)?;
    let store = Arc::clone(&state.store);
    let queried = log_id.clone();
    let held =
        blocking(move || store.list_rotation_cosignatures(&queried, manifest_entry_index)).await?;

    // Several cosignatures for one rotation are legitimate — any checkpoint past the rotating
    // index and signed by the outgoing key is rotation material — so the earliest is served,
    // deterministically, and the ones over other checkpoints are not mixed into one element:
    // `anchoring.witnesses[]` is an array of cosignatures over ONE checkpoint.
    let Some(first) = held.first() else {
        return Err(ApiError::from(WitnessError::UnknownRotationCosignature {
            manifest_entry_index,
        }));
    };
    let checkpoint = first.checkpoint.clone();
    let witnesses = held
        .iter()
        .filter(|cosigned| cosigned.checkpoint == checkpoint)
        .map(|cosigned| RotationWitnessEntry {
            witness_id: cosigned.witness_id.clone(),
            key_id: cosigned.key_id.clone(),
            cosignature: cosigned.cosignature.clone(),
            cosigned_at: cosigned.cosigned_at.clone(),
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(RotationCosignaturesResponse { log_id, manifest_entry_index, checkpoint, witnesses }),
    )
        .into_response())
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
            "ahl_version": ahl_core::AHL_VERSION,
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

    /// Post a submission and return `(status, error text)`.
    async fn refusal_for(hx: &Harness, body: &serde_json::Value) -> (StatusCode, String) {
        let app = router(hx.state.clone());
        let request = Request::post(format!("/v1/logs/{}/witness", hx.log_id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).expect("serialize")))
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        let status = response.status();
        let bytes = response.into_body().collect().await.expect("body").to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
        (status, value["error"].as_str().unwrap_or_default().to_owned())
    }

    /// `raw` inside the checkpoint is the submission the end-to-end pilot sent: a correct
    /// member of a RECEIPT-borne checkpoint (I-D §7.1), and not a member of the object this
    /// witness cosigns. Deserializing past it would have the witness cosign six members while
    /// the submitter believed it had cosigned seven.
    #[tokio::test]
    async fn a_checkpoint_carrying_raw_is_refused_and_the_member_is_named() {
        let hx = harness();
        let cp = signed_checkpoint(
            &hx,
            compute_root(&[hx.genesis_leaf]),
            "2026-01-01T00:00:00.000000000Z",
        );
        let mut body = witness_body(&cp, &[]);
        body["checkpoint"]["raw"] = json!(format!("base64:{}", B64.encode([0u8; 98])));

        let (status, error) = refusal_for(&hx, &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(error.contains("`raw`"), "the refusal must name the member: {error}");
        // And it must say where the framing does belong, since `raw` is legitimate material.
        assert!(error.contains("top-level `raw`"), "{error}");
    }

    #[tokio::test]
    async fn an_unknown_checkpoint_member_is_refused_and_named() {
        let hx = harness();
        let cp = signed_checkpoint(
            &hx,
            compute_root(&[hx.genesis_leaf]),
            "2026-01-01T00:00:00.000000000Z",
        );
        let mut body = witness_body(&cp, &[]);
        body["checkpoint"]["origin_id"] = json!(hx.log_id.clone());

        let (status, error) = refusal_for(&hx, &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(error.contains("`origin_id`"), "the refusal must name the member: {error}");
    }

    #[tokio::test]
    async fn an_unknown_request_member_is_refused_and_named() {
        let hx = harness();
        let cp = signed_checkpoint(
            &hx,
            compute_root(&[hx.genesis_leaf]),
            "2026-01-01T00:00:00.000000000Z",
        );
        let mut body = witness_body(&cp, &[]);
        body["consistency_proof"] = json!([]);

        let (status, error) = refusal_for(&hx, &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(error.contains("`consistency_proof`"), "the refusal must name the member: {error}");
    }

    /// The whole point of the projection, end to end: what this witness signs is exactly what
    /// `ahl_core::cosignature_bytes` builds from the six members — including when the verifier
    /// holds the checkpoint in the RECEIPT-borne form, `raw` and all. A verifier that
    /// serialised that form as it stands would build different bytes and reject a genuine
    /// cosignature, which is the defect adaptor §11.1's erratum settles.
    #[tokio::test]
    async fn the_cosignature_verifies_over_the_projection_of_a_checkpoint_carrying_raw() {
        let hx = harness();
        let app = router(hx.state.clone());
        let root = compute_root(&[hx.genesis_leaf]);
        let cp = signed_checkpoint(&hx, root, "2026-01-01T00:00:00.000000000Z");
        let genesis_bytes = genesis_manifest_bytes(
            &hx.log_id,
            &ahl_core::TestKey::from_seed_hex("producer", &"a0".repeat(32)).expect("seed"),
            &hx.log_key,
        );
        let blob = crate::checkpoint::checkpoint_blob(&cp).expect("well-formed");
        let mut body = witness_body(&cp, &[genesis_bytes]);
        body["raw"] = json!(format!("base64:{}", B64.encode(blob)));

        let request = Request::post(format!("/v1/logs/{}/witness", hx.log_id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
            .expect("valid request");
        let response = app.oneshot(request).await.expect("service call");
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = response.into_body().collect().await.expect("body").to_bytes();
        let cosigned: CosignedCheckpoint = serde_json::from_slice(&bytes).expect("json");

        // The checkpoint as a RECEIPT carries it: the six members plus the `raw` framing.
        let mut receipt_borne = serde_json::to_value(&cosigned.checkpoint).expect("serialize");
        receipt_borne["raw"] = json!(format!("base64:{}", B64.encode(blob)));

        let projected =
            ahl_core::CosignedCheckpoint::project(&receipt_borne).expect("six members plus raw");
        let expected = ahl_core::cosignature_bytes(&projected, &cosigned.witness_id);
        assert_eq!(
            expected,
            ahl_core::cosignature_bytes(&cp.cosigned().expect("cosignable"), &cosigned.witness_id),
            "carrying `raw` must not change the preimage"
        );

        let witness_key = Ed25519WitnessSigner::from_seed("witness-1", &[3u8; 32])
            .expect("32 bytes")
            .verifying_key();
        assert!(
            ahl_core::verify_signature(&witness_key, &expected, &cosigned.cosignature)
                .expect("well-formed signature"),
            "the cosignature must verify over the six-member projection"
        );
    }
    // -----------------------------------------------------------------------
    // Rotation-anchoring cosignatures (I-D §7.1)
    // -----------------------------------------------------------------------

    /// A log that has performed a log-key rotation, driven through the real router, and the
    /// receipt cross-check that decides whether what this witness serves is the thing I-D §7.1
    /// defines.
    ///
    /// Three entries: the genesis manifest at index 0 under the OUTGOING log key, a successor
    /// at index 1 that replaces the log key set with the INCOMING one, and a subject statement
    /// at index 2. Every payload is a complete I-D §6.2/§2.2 statement rather than the minimum
    /// this crate itself reads, because `a_receipt_carrying_the_served_cosignature_verifies`
    /// hands the whole corpus to `ahl_core::receipt::verify_receipt_report`.
    mod rotation {
        use std::collections::BTreeMap;

        use ahl_core::receipt::{
            verify_receipt_report, AdaptorCapabilities, AdaptorProfile, Limits, Outcome,
            TrustPolicy,
        };
        use serde_json::Value;

        use super::*;

        /// The artifact a verifier holds under `ahl-adaptor-atl-v1` in these tests. Its bytes
        /// are what the manifests' `log.adaptor.hash` pins, recomputed rather than transcribed.
        const PROFILE_DOCUMENT: &[u8] = b"ahl-adaptor-atl-v1 test artifact";

        /// The entry index the rotating manifest is anchored at.
        const ROTATING_INDEX: u64 = 1;

        /// The witness seed the harness's signer uses.
        const WITNESS_SEED: u8 = 0x0b;

        fn manifest_payload(
            log_id: &str,
            producer: &ahl_core::TestKey,
            log_key: &ahl_core::TestKey,
            witness: &ahl_core::TestKey,
            predecessor: Option<&str>,
        ) -> Value {
            let mut payload = json!({
                "ahl_version": ahl_core::AHL_VERSION,
                "type": "manifest",
                "producer": "producer-1",
                "issued_at": "2026-01-01T00:00:00Z",
                "valid_time": "2026-01-01T00:00:00Z",
                "keys": [ { "key_id": producer.key_id(), "pubkey": producer.pubkey() } ],
                "log": {
                    "log_id": log_id,
                    "operator": "log-operator-1",
                    "adaptor": {
                        "id": ahl_core::ATL_PROFILE_ID,
                        "hash": ahl_core::sha256_hex(PROFILE_DOCUMENT),
                    },
                    "checkpoint_cadence": "PT1H",
                    "cadence_epoch": "2026-01-01T00:00:00Z",
                    "witness_grace_period": "PT15M",
                    "keys": [ {
                        "key_id": log_key.key_id(),
                        "pubkey": log_key.pubkey(),
                        "valid_from_index": 0,
                    } ],
                },
                "witnesses": [ {
                    "witness_id": "witness-1",
                    "keys": [ {
                        "key_id": witness.key_id(),
                        "pubkey": witness.pubkey(),
                        "valid_from_index": 0,
                    } ],
                } ],
                "datasets": {
                    "records": {
                        "canonicalization": "jcs",
                        "commitment_mode": "plain",
                        "key_access": "not-applicable",
                        "authority": {
                            "producer": "producer-1",
                            "key_ids": [ producer.key_id() ],
                        },
                    },
                },
                "pipelines": { "include": [], "exclude": [] },
                "windows": { "anchoring": "PT24H", "propagation": "P30D" },
                "retention": { "statements": "P10Y" },
                "properties": { "reproducible_reconstruction": false },
                "level": "L3",
            });
            if let Some(predecessor) = predecessor {
                payload["predecessor"] = json!(predecessor);
            }
            payload
        }

        struct Corpus {
            state: AppState,
            outgoing: ahl_core::TestKey,
            incoming: ahl_core::TestKey,
            producer: ahl_core::TestKey,
            witness: ahl_core::TestKey,
            log_id: String,
            genesis_entry_id: String,
            envelopes: Vec<Value>,
            entries: Vec<Vec<u8>>,
            leaves: Vec<Hash>,
            root: Hash,
        }

        impl Corpus {
            fn app(&self) -> Router {
                router(self.state.clone())
            }

            fn checkpoint(&self, key: &ahl_core::TestKey, time: &str) -> Checkpoint {
                let mut cp = Checkpoint {
                    log_id: self.log_id.clone(),
                    tree_size: 3,
                    root_hash: format!("sha256:{}", hex::encode(self.root)),
                    checkpoint_time: time.to_owned(),
                    key_id: key.key_id(),
                    signature: String::new(),
                };
                let blob = crate::checkpoint::checkpoint_blob(&cp).expect("well-formed");
                cp.signature = key.sign(&blob);
                cp
            }
        }

        fn corpus() -> Corpus {
            let producer =
                ahl_core::TestKey::from_seed_hex("producer", &"c1".repeat(32)).expect("seed");
            let outgoing =
                ahl_core::TestKey::from_seed_hex("log-out", &"c2".repeat(32)).expect("seed");
            let incoming =
                ahl_core::TestKey::from_seed_hex("log-in", &"c3".repeat(32)).expect("seed");
            let witness = ahl_core::TestKey::from_seed_hex(
                "witness-1",
                &format!("{WITNESS_SEED:02x}").repeat(32),
            )
            .expect("seed");
            let log_id = format!("sha256:{}", "c4".repeat(32));

            let genesis = ahl_core::envelope(
                manifest_payload(&log_id, &producer, &outgoing, &witness, None),
                &producer,
            );
            let genesis_entry_id = ahl_core::entry_id(&genesis);
            let rotating = ahl_core::envelope(
                manifest_payload(&log_id, &producer, &incoming, &witness, Some(&genesis_entry_id)),
                &producer,
            );
            let rotating_statement_id =
                ahl_core::statement_id(&rotating).expect("well-formed envelope");
            let subject = ahl_core::envelope(
                json!({
                    "ahl_version": ahl_core::AHL_VERSION,
                    "type": "ingestion",
                    "producer": "producer-1",
                    "issued_at": "2026-01-01T00:00:00Z",
                    "valid_time": "2026-01-01T00:00:00Z",
                    "manifest": rotating_statement_id,
                    "dataset": "records",
                    "origin": "batch:2026-01-01/records-01",
                    "record": format!("sha256:{}", "d1".repeat(32)),
                }),
                &producer,
            );

            let envelopes = vec![genesis, rotating, subject];
            let entries: Vec<Vec<u8>> = envelopes.iter().map(ahl_core::jcs).collect();
            let leaves: Vec<Hash> = entries.iter().map(|b| log_leaf_hash(b)).collect();
            let root = compute_root(&leaves);

            let anchor = LogAnchor::resolve(&LogAnchorSpec {
                log_id: log_id.clone(),
                genesis_manifest_entry_id: genesis_entry_id.clone(),
                genesis_producer_keys: vec![KeyObjectSpec {
                    key_id: producer.key_id(),
                    pubkey: producer.pubkey(),
                    valid_from_index: 0,
                }],
            })
            .expect("valid anchor");
            let mut anchors = HashMap::new();
            anchors.insert(log_id.clone(), anchor);
            let signer = Ed25519WitnessSigner::from_seed("witness-1", &[WITNESS_SEED; 32])
                .expect("32 bytes");
            assert_eq!(signer.key_id(), witness.key_id(), "the manifests declare this key");

            Corpus {
                state: AppState {
                    store: Arc::new(Store::open_in_memory().expect("in-memory store")),
                    signer: Arc::new(signer),
                    anchors: Arc::new(anchors),
                },
                outgoing,
                incoming,
                producer,
                witness,
                log_id,
                genesis_entry_id,
                envelopes,
                entries,
                leaves,
                root,
            }
        }

        async fn submit(corpus: &Corpus, app: &Router, cp: &Checkpoint) -> (StatusCode, Value) {
            let request = Request::post(format!("/v1/logs/{}/witness", corpus.log_id))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&witness_body(cp, &corpus.entries)).expect("serialize"),
                ))
                .expect("valid request");
            let response = app.clone().oneshot(request).await.expect("service call");
            let status = response.status();
            let body = response.into_body().collect().await.expect("body").to_bytes();
            (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
        }

        async fn get_json(app: &Router, uri: &str) -> (StatusCode, Value) {
            let request = Request::get(uri).body(Body::empty()).expect("valid request");
            let response = app.clone().oneshot(request).await.expect("service call");
            let status = response.status();
            let body = response.into_body().collect().await.expect("body").to_bytes();
            (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
        }

        /// A genuine RFC 6962 inclusion path (leaf to root) for `leaves[index]`.
        fn path_for(corpus: &Corpus, index: u64) -> Vec<String> {
            let tree_size = u64::try_from(corpus.leaves.len()).expect("small test size");
            let proof =
                atl_core::core::merkle::generate_inclusion_proof(index, tree_size, |level, at| {
                    if level == 0 {
                        corpus.leaves.get(usize::try_from(at).ok()?).copied()
                    } else {
                        None
                    }
                })
                .expect("index within tree");
            ahl_core::proof_path_hex(&proof)
        }

        /// Assemble a `statement-anchored` receipt over `corpus`, carrying `element` as its
        /// one `governance.rotation_proofs[]` element and `anchoring_witnesses` as the
        /// cosignatures over `anchoring_cp`.
        fn receipt_over(
            corpus: &Corpus,
            anchoring_cp: &Checkpoint,
            anchoring_witnesses: &Value,
            element: &Value,
        ) -> Value {
            let key_object = |key_id: String, pubkey: String, entry_index: u64| {
                json!({
                    "key_id": key_id,
                    "pubkey": pubkey,
                    "source": "manifest-chain",
                    "binding": { "entry_index": entry_index },
                })
            };
            let witness_key_object = |entry_index: u64| {
                json!({
                    "witness_id": "witness-1",
                    "key_id": corpus.witness.key_id(),
                    "pubkey": corpus.witness.pubkey(),
                    "source": "manifest-chain",
                    "binding": { "entry_index": entry_index },
                })
            };
            json!({
                "ahl_receipt_version": "2",
                "spec_version": "0.4.0",
                "claim": {
                    "type": "statement-anchored",
                    "assurance": {
                        "governance": "declared",
                        "competing_triggers": "not-checked",
                        "witnessed": true,
                        "continued_history": false,
                        "content_binding": "none",
                    },
                },
                "subject": {
                    "statement_id": ahl_core::statement_id(&corpus.envelopes[2]).expect("id"),
                    "entry_id": ahl_core::entry_id(&corpus.envelopes[2]),
                    "entry_index": 2,
                    "manifest": ahl_core::statement_id(&corpus.envelopes[1]).expect("id"),
                },
                "envelope": corpus.envelopes[2],
                "keys": {
                    // The same physical key is listed once per manifest version it is drawn
                    // from: the version active for the anchoring checkpoint, and — for the
                    // rotation material alone — the predecessor version §7.1's transition
                    // exception names.
                    "log": [
                        key_object(
                            corpus.incoming.key_id(), corpus.incoming.pubkey(), ROTATING_INDEX
                        ),
                        key_object(corpus.outgoing.key_id(), corpus.outgoing.pubkey(), 0),
                    ],
                    "witness": [ witness_key_object(ROTATING_INDEX), witness_key_object(0) ],
                    "producer": [ key_object(
                        corpus.producer.key_id(), corpus.producer.pubkey(), ROTATING_INDEX
                    ) ],
                },
                "anchoring": {
                    "adaptor": {
                        "id": ahl_core::ATL_PROFILE_ID,
                        "hash": ahl_core::sha256_hex(PROFILE_DOCUMENT),
                    },
                    "checkpoint": anchoring_cp,
                    "inclusion_path": path_for(corpus, 2),
                    "witnesses": anchoring_witnesses,
                },
                "governance": {
                    "genesis_entry_id": corpus.genesis_entry_id,
                    "chain": [
                        {
                            "envelope": corpus.envelopes[0],
                            "entry_index": 0,
                            "inclusion_path": path_for(corpus, 0),
                        },
                        {
                            "envelope": corpus.envelopes[1],
                            "entry_index": ROTATING_INDEX,
                            "inclusion_path": path_for(corpus, ROTATING_INDEX),
                        },
                    ],
                    "rotation_proofs": [ element ],
                    "currency": { "mode": "declared" },
                },
            })
        }

        #[tokio::test]
        async fn the_rotation_cosignature_is_served_apart_from_the_series() {
            let corpus = corpus();
            let app = corpus.app();
            let rotation_cp = corpus.checkpoint(&corpus.outgoing, "2026-01-01T01:00:00.000000000Z");

            let (status, body) = submit(&corpus, &app, &rotation_cp).await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
            assert_eq!(body["status"], "cosigned-rotation");
            assert_eq!(body["manifest_entry_index"], ROTATING_INDEX);

            // Served on its own route, in the `anchoring.witnesses[]` element shape.
            let (status, served) = get_json(
                &app,
                &format!("/v1/logs/{}/rotation-cosignatures/{ROTATING_INDEX}", corpus.log_id),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{served}");
            assert_eq!(served["manifest_entry_index"], ROTATING_INDEX);
            assert_eq!(served["checkpoint"], serde_json::to_value(&rotation_cp).expect("json"));
            let witnesses = served["witnesses"].as_array().expect("an array");
            assert_eq!(witnesses.len(), 1);
            assert_eq!(witnesses[0]["witness_id"], "witness-1");
            assert_eq!(witnesses[0]["key_id"], corpus.witness.key_id());

            // And nowhere else: not the latest cosigned checkpoint, not in the history, not a
            // freshness answer.
            assert_eq!(
                get_json(&app, &format!("/v1/logs/{}/checkpoint", corpus.log_id)).await.0,
                StatusCode::NOT_FOUND
            );
            let (status, history) =
                get_json(&app, &format!("/v1/logs/{}/checkpoints", corpus.log_id)).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(history, json!([]));
            assert_eq!(
                get_json(&app, &format!("/v1/logs/{}/freshness", corpus.log_id)).await.0,
                StatusCode::NOT_FOUND
            );

            // A rotation this log did not perform has no cosignature to serve.
            assert_eq!(
                get_json(&app, &format!("/v1/logs/{}/rotation-cosignatures/0", corpus.log_id))
                    .await
                    .0,
                StatusCode::NOT_FOUND
            );
        }

        #[tokio::test]
        async fn an_incoming_key_checkpoint_is_an_ordinary_cosign() {
            let corpus = corpus();
            let app = corpus.app();
            let series_cp = corpus.checkpoint(&corpus.incoming, "2026-01-01T01:00:00.000000000Z");

            let (status, body) = submit(&corpus, &app, &series_cp).await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
            assert_eq!(body["status"], "cosigned");
            assert_eq!(
                get_json(&app, &format!("/v1/logs/{}/checkpoint", corpus.log_id)).await.0,
                StatusCode::OK
            );
            assert_eq!(
                get_json(
                    &app,
                    &format!("/v1/logs/{}/rotation-cosignatures/{ROTATING_INDEX}", corpus.log_id)
                )
                .await
                .0,
                StatusCode::NOT_FOUND
            );
        }

        /// The cross-check that decides whether the cosignature this witness serves is the
        /// thing I-D §7.1 asks for at L3: a receipt whose `governance.rotation_proofs[0]`
        /// carries it, verified by `ahl-core`'s own verifier, which requires at least one
        /// element of that member to verify "under a witness key of the OUTGOING state".
        ///
        /// Nothing served is edited on the way in. If this witness had cosigned the wrong
        /// projection, cosigned under an identity the outgoing manifest does not declare, or
        /// served a cosignature over a different checkpoint from the one the element carries,
        /// §7.5.1 4b(M)'s rotation-anchoring rule would reject the receipt.
        #[tokio::test]
        async fn a_receipt_carrying_the_served_cosignature_verifies() {
            let corpus = corpus();
            let app = corpus.app();
            let rotation_cp = corpus.checkpoint(&corpus.outgoing, "2026-01-01T01:00:00.000000000Z");
            let anchoring_cp =
                corpus.checkpoint(&corpus.incoming, "2026-01-01T02:00:00.000000000Z");

            let (status, rotation_body) = submit(&corpus, &app, &rotation_cp).await;
            assert_eq!(status, StatusCode::CREATED, "{rotation_body}");
            let (status, series_body) = submit(&corpus, &app, &anchoring_cp).await;
            assert_eq!(status, StatusCode::CREATED, "{series_body}");
            assert_eq!(series_body["status"], "cosigned");

            let (status, served) = get_json(
                &app,
                &format!("/v1/logs/{}/rotation-cosignatures/{ROTATING_INDEX}", corpus.log_id),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{served}");

            let receipt = receipt_over(
                &corpus,
                &anchoring_cp,
                &json!([{
                    "witness_id": series_body["witness_id"],
                    "key_id": series_body["key_id"],
                    "cosignature": series_body["cosignature"],
                    "cosigned_at": series_body["cosigned_at"],
                }]),
                &json!({
                    "manifest_entry_index": ROTATING_INDEX,
                    "checkpoint": served["checkpoint"],
                    "inclusion_path": path_for(&corpus, ROTATING_INDEX),
                    "witnesses": served["witnesses"],
                }),
            );

            let policy = TrustPolicy {
                genesis_entry_id: corpus.genesis_entry_id.clone(),
                genesis_key_ids: None,
                adaptor_profiles: BTreeMap::from([(
                    ahl_core::ATL_PROFILE_ID.to_owned(),
                    AdaptorProfile {
                        document: PROFILE_DOCUMENT.to_vec(),
                        capabilities: AdaptorCapabilities {
                            checkpoint_raw: false,
                            consistency_proofs: false,
                        },
                    },
                )]),
                dataset_keys: BTreeMap::new(),
                trusted_witness_keys: BTreeMap::new(),
                limits: Limits::default(),
            };

            let report = verify_receipt_report(&receipt, &policy).expect("the run completes");
            assert_eq!(report.result, Outcome::Verified, "findings: {:?}", report.findings);
        }
    }
}
