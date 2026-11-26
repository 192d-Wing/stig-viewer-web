//! Detached signing for exported artifacts (e.g. `.ckl` files).
//!
//! Enabled by setting `SIGNING_KEY_HEX` to a 32-byte hex-encoded Ed25519
//! seed. When the env var is absent, [`SigningState::from_env`] returns
//! `None` and both endpoints respond 503.
//!
//! Hybrid mode (#66, #67): when `SIGNING_MLDSA87_KEY_B64` (base64 PKCS#8 of an
//! ML-DSA-87 key, see the `gen-mldsa-key` subcommand) is also set, every
//! signature this module (and the archive/backup sealing in `integrity`)
//! produces is made by BOTH keys, and a verifier needs both to accept it.
//! `SIGNING_REQUIRE_HYBRID=true` refuses to start with only an Ed25519 key and
//! makes verifiers refuse classical (Ed25519-only) artifacts where they gate
//! acceptance. Configuration matrix:
//!
//! - neither key: signing disabled;
//! - Ed25519 only: classical, as before (the server logs a warning);
//! - both: hybrid (in a `fips` build this needs `ML-DSA-87` in
//!   `STIG_FIPS_PENDING_ALGS`);
//! - ML-DSA only, a malformed key, or `SIGNING_REQUIRE_HYBRID` without both
//!   keys: startup error.
//! - `SIGNING_PREVIOUS_KEYS_FILE` / `SIGNING_PREVIOUS_KEYS_JSON` (#68, at most
//!   one): public keys of retired key sets that keep verifying after a
//!   rotation. They need `SIGNING_KEY_HEX`, can never sign, and a hybrid set in
//!   a `fips` build needs `ML-DSA-87` in `STIG_FIPS_PENDING_ALGS`. Trust is per
//!   key set: a signed signer list must equal exactly one current or previous
//!   set. Malformed content, both carriers, or a revoked key in use: startup
//!   error. See [`crate::signers::parse_previous`] for the schema.
//!
//! A runtime ML-DSA failure fails the operation; it never falls back to
//! Ed25519-only output.
//!
//! - `GET  /api/signing/pubkey` — public; returns `{algorithm, keyId,
//!   publicKey, keys: [{algorithm, keyId, publicKey}]}` so verifiers can pin a
//!   trusted copy of the keys offline. The top-level fields are the Ed25519
//!   key; `keys` also lists the ML-DSA-87 key (raw FIPS 204 bytes, base64)
//!   when configured.
//! - `POST /api/sign` — authenticated; takes an opaque blob (base64) +
//!   optional `resource` label, hashes the content, wraps the hashes plus
//!   the signer's identity and a timestamp in a canonical JSON "signing
//!   document", and returns signatures over that document.
//!
//! Threat model: the signature attests that the server observed exactly
//! these bytes, at this time, under this authenticated user's session.
//! Replay is prevented by the `signedAt` field in the signing document.
//!
//! Audit trail: each successful sign writes a durable `signing.sign` row to
//! `audit_events` (sha256, key ids, profile, byte count, version, algorithms;
//! `resource` is client free text, so only whether it was present is stored,
//! plus the `stig_id` column when it has a STIG id's shape) and emits a
//! `tracing::info!` line. The row is committed before the signature leaves the
//! server: if it cannot be written the request fails (5xx) and no bundle is
//! returned (fail closed, AU-10).

use axum::{extract::State, http::StatusCode, Extension, Json};
use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::audit_tx;
use crate::api::auth::AuthUser;
use crate::api::checklists::is_valid_stig_id;
use crate::api::request_ctx::RequestCtx;
use crate::crypto;
use crate::fips::{FipsPolicy, PendingAlg};
pub use crate::signers::SignerId;
use crate::signers::{
    self, Algorithm, KeySource, PreviousKeys, Profile, TrustedKeys, VerifyingKey,
};
use crate::AppState;

pub const ED25519_KEY_ENV: &str = "SIGNING_KEY_HEX";
pub const MLDSA_KEY_ENV: &str = "SIGNING_MLDSA87_KEY_B64";
pub const REQUIRE_HYBRID_ENV: &str = "SIGNING_REQUIRE_HYBRID";
/// Path of the previous-keys JSON document (#68). Public keys only.
pub const PREVIOUS_KEYS_FILE_ENV: &str = "SIGNING_PREVIOUS_KEYS_FILE";
/// The same document inline, for env-only deployments.
pub const PREVIOUS_KEYS_JSON_ENV: &str = "SIGNING_PREVIOUS_KEYS_JSON";
const MAX_PREVIOUS_KEYS_BYTES: usize = signers::MAX_PREVIOUS_BYTES;

/// The ML-DSA-87 half of a hybrid configuration.
#[derive(Debug)]
pub struct MlDsaSigner {
    key: crypto::mldsa::SigningKey,
    /// See [`signers::key_id`].
    pub key_id: String,
}

impl MlDsaSigner {
    pub fn new(key: crypto::mldsa::SigningKey) -> Self {
        let key_id = signers::key_id(Algorithm::MlDsa87, &key.public_key());
        Self { key, key_id }
    }
}

/// One signature produced by [`SigningState::sign_all`].
pub struct ProducedSignature {
    pub algorithm: Algorithm,
    pub key_id: String,
    pub signature: Vec<u8>,
}

/// Loaded signing material. Stored on `AppState` as `Option<SigningState>`;
/// `None` makes every endpoint in this module return 503.
#[derive(Clone, Debug)]
pub struct SigningState {
    pub signing_key: Arc<crypto::ed25519::SigningKey>,
    /// Short public-key fingerprint — first 8 bytes of SHA-256 over the raw
    /// verifying-key bytes, hex-encoded. Clients embed this in signed
    /// bundles so a verifier can detect key rotation.
    pub key_id: String,
    /// ML-DSA-87 key; `Some` makes every signature hybrid.
    pub mldsa: Option<Arc<MlDsaSigner>>,
    /// `SIGNING_REQUIRE_HYBRID`: classical artifacts are not acceptable.
    pub require_hybrid: bool,
    /// Retired key sets that still verify (#68). Verify-only: nothing here can
    /// sign, and it is empty unless the previous-keys configuration is set.
    pub previous: Arc<PreviousKeys>,
    /// Serialized `GET /api/signing/pubkey` body, built on first use: the keys
    /// are immutable after startup and the endpoint is unauthenticated.
    pubkey_cache: Arc<std::sync::OnceLock<axum::body::Bytes>>,
}

/// `unset`/blank/`0`/`false` is off, `1`/`true` is on, anything else is an
/// error (a typo must not silently disable the requirement).
fn parse_flag(name: &str, raw: Option<&str>) -> anyhow::Result<bool> {
    let v = raw.unwrap_or("").trim();
    if v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false") {
        Ok(false)
    } else if v == "1" || v.eq_ignore_ascii_case("true") {
        Ok(true)
    } else {
        anyhow::bail!("{name} has invalid value; use true or false")
    }
}

/// Read the previous-keys document from its carrier. Both carriers set is an
/// error; the file read is bounded. Returns the bytes and the carrier name.
fn read_previous_keys(
    file: Option<&str>,
    json: Option<&str>,
) -> anyhow::Result<Option<(Vec<u8>, &'static str)>> {
    use std::io::Read;
    match (nonblank(file), nonblank(json)) {
        (Some(_), Some(_)) => {
            anyhow::bail!("set only one of {PREVIOUS_KEYS_FILE_ENV} and {PREVIOUS_KEYS_JSON_ENV}")
        }
        (Some(path), None) => {
            let f = std::fs::File::open(path.trim()).map_err(|e| {
                anyhow::anyhow!("cannot read {PREVIOUS_KEYS_FILE_ENV}: {}", e.kind())
            })?;
            let mut buf = Vec::new();
            f.take(MAX_PREVIOUS_KEYS_BYTES as u64 + 1)
                .read_to_end(&mut buf)
                .map_err(|e| {
                    anyhow::anyhow!("cannot read {PREVIOUS_KEYS_FILE_ENV}: {}", e.kind())
                })?;
            if buf.len() > MAX_PREVIOUS_KEYS_BYTES {
                anyhow::bail!("{PREVIOUS_KEYS_FILE_ENV} exceeds {MAX_PREVIOUS_KEYS_BYTES} bytes");
            }
            Ok(Some((buf, "file")))
        }
        (None, Some(j)) => {
            if j.len() > MAX_PREVIOUS_KEYS_BYTES {
                anyhow::bail!("{PREVIOUS_KEYS_JSON_ENV} exceeds {MAX_PREVIOUS_KEYS_BYTES} bytes");
            }
            Ok(Some((j.as_bytes().to_vec(), "env")))
        }
        (None, None) => Ok(None),
    }
}

/// One `(algorithm, keyId)` must mean one public key across the current and
/// previous keys: the verifier looks keys up by id.
fn check_no_key_id_collision(
    current: &TrustedKeys,
    previous: &[signers::KeySet],
) -> anyhow::Result<()> {
    for k in previous.iter().flat_map(|s| s.keys.iter()) {
        if current
            .find(k.algorithm, &k.key_id)
            .is_some_and(|c| c.public_key != k.public_key)
        {
            anyhow::bail!("a previous key shares a keyId with a different current public key");
        }
    }
    Ok(())
}

fn nonblank(v: Option<&str>) -> Option<&str> {
    v.filter(|s| !s.trim().is_empty())
}

impl SigningState {
    /// Reads the signing variables from the environment. Returns `Ok(None)`
    /// when no key is set so the server starts cleanly without signing.
    /// See the module docs for the configuration matrix.
    pub fn from_env(policy: &FipsPolicy) -> anyhow::Result<Option<Self>> {
        let previous = read_previous_keys(
            std::env::var(PREVIOUS_KEYS_FILE_ENV).ok().as_deref(),
            std::env::var(PREVIOUS_KEYS_JSON_ENV).ok().as_deref(),
        )?;
        Self::from_vars(
            std::env::var(ED25519_KEY_ENV).ok().as_deref(),
            std::env::var(MLDSA_KEY_ENV).ok().as_deref(),
            std::env::var(REQUIRE_HYBRID_ENV).ok().as_deref(),
            policy,
            previous.as_ref().map(|(b, s)| (b.as_slice(), *s)),
        )
    }

    /// Pure core of [`Self::from_env`]. Errors never contain key material.
    /// `previous` is the previous-keys document and its carrier (`"file"` or
    /// `"env"`), see [`signers::parse_previous`].
    pub fn from_vars(
        hex_str: Option<&str>,
        mldsa_b64: Option<&str>,
        require_hybrid: Option<&str>,
        policy: &FipsPolicy,
        previous: Option<(&[u8], &'static str)>,
    ) -> anyhow::Result<Option<Self>> {
        let require_hybrid = parse_flag(REQUIRE_HYBRID_ENV, require_hybrid)?;
        let mldsa_b64 = nonblank(mldsa_b64);
        let Some(mut state) = Self::from_hex(hex_str)? else {
            if mldsa_b64.is_some() {
                anyhow::bail!("{MLDSA_KEY_ENV} is set but {ED25519_KEY_ENV} is not; hybrid signing needs both keys");
            }
            if require_hybrid {
                anyhow::bail!("{REQUIRE_HYBRID_ENV} is set but no signing key is configured");
            }
            if previous.is_some() {
                anyhow::bail!(
                    "{PREVIOUS_KEYS_FILE_ENV}/{PREVIOUS_KEYS_JSON_ENV} is set but {ED25519_KEY_ENV} is not; previous keys need a configured signing key"
                );
            }
            return Ok(None);
        };
        match mldsa_b64 {
            Some(b64) => {
                policy.require(PendingAlg::MlDsa87)?;
                let der = BASE64
                    .decode(b64.trim())
                    .map_err(|_| anyhow::anyhow!("{MLDSA_KEY_ENV} is not valid base64"))?;
                let key = crypto::mldsa::SigningKey::from_pkcs8(&der)
                    .map_err(|e| anyhow::anyhow!("{MLDSA_KEY_ENV}: {e}"))?;
                state.mldsa = Some(Arc::new(MlDsaSigner::new(key)));
            }
            None if require_hybrid => anyhow::bail!(
                "{REQUIRE_HYBRID_ENV} is set but {MLDSA_KEY_ENV} is not; refusing to start with classical-only signing"
            ),
            None => {}
        }
        state.require_hybrid = require_hybrid;
        if let Some((bytes, source)) = previous {
            state.previous = Arc::new(state.accept_previous(bytes, source, policy)?);
        }
        Ok(Some(state))
    }

    /// Parse the previous-keys document and check it against the current keys:
    /// a revoked current key is an error, a hybrid previous set needs the
    /// ML-DSA-87 pending algorithm in a FIPS build, and entries equal to the
    /// current keys are dropped (their labels are kept in `ignored`).
    fn accept_previous(
        &self,
        bytes: &[u8],
        source: &'static str,
        policy: &FipsPolicy,
    ) -> anyhow::Result<PreviousKeys> {
        let mut prev = signers::parse_previous(bytes, source)?;
        check_no_key_id_collision(&self.trusted(), &prev.sets)?;
        let current: Vec<signers::SignerId> = self.signers();
        let classical = &current[..1];
        for r in &prev.revoked {
            if current
                .iter()
                .any(|c| c.algorithm == r.algorithm.wire() && c.key_id == r.key_id)
            {
                anyhow::bail!("previous-keys document revokes a key that is currently in use");
            }
        }
        if prev.sets.iter().any(|s| s.profile == Profile::Hybrid) {
            policy.require(PendingAlg::MlDsa87)?;
        }
        let (keep, drop): (Vec<_>, Vec<_>) =
            std::mem::take(&mut prev.sets).into_iter().partition(|s| {
                let ids = s.signer_ids();
                ids != current && ids != classical
            });
        prev.sets = keep;
        prev.ignored = drop.into_iter().filter_map(|s| s.label).collect();
        Ok(prev)
    }

    /// Ed25519-only state from `SIGNING_KEY_HEX`: `None` or blank means
    /// disabled, a malformed value is an error.
    pub fn from_hex(value: Option<&str>) -> anyhow::Result<Option<Self>> {
        let Some(hex_str) = nonblank(value) else {
            return Ok(None);
        };
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| anyhow::anyhow!("SIGNING_KEY_HEX is not valid hex: {e}"))?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "SIGNING_KEY_HEX must decode to exactly 32 bytes (got {})",
                bytes.len()
            );
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        let signing_key = crypto::ed25519::SigningKey::from_seed(&seed)?;
        let key_id = compute_key_id(&signing_key.public_key());
        Ok(Some(Self {
            signing_key: Arc::new(signing_key),
            key_id,
            mldsa: None,
            require_hybrid: false,
            previous: Arc::default(),
            pubkey_cache: Arc::default(),
        }))
    }

    pub fn profile(&self) -> Profile {
        if self.mldsa.is_some() {
            Profile::Hybrid
        } else {
            Profile::Classical
        }
    }

    /// The signer list embedded in signed payloads: Ed25519, then ML-DSA-87.
    pub fn signers(&self) -> Vec<SignerId> {
        let mut v = vec![SignerId {
            algorithm: ALGORITHM.into(),
            key_id: self.key_id.clone(),
        }];
        if let Some(m) = &self.mldsa {
            v.push(SignerId {
                algorithm: signers::ML_DSA_87.into(),
                key_id: m.key_id.clone(),
            });
        }
        v
    }

    /// Sign `input` with every configured key, in [`Self::signers`] order. An
    /// ML-DSA failure fails the whole call; there is no classical fallback.
    pub fn sign_all(&self, input: &[u8]) -> anyhow::Result<Vec<ProducedSignature>> {
        let mut out = vec![ProducedSignature {
            algorithm: Algorithm::Ed25519,
            key_id: self.key_id.clone(),
            signature: self.signing_key.sign(input).to_vec(),
        }];
        if let Some(m) = &self.mldsa {
            out.push(ProducedSignature {
                algorithm: Algorithm::MlDsa87,
                key_id: m.key_id.clone(),
                signature: m.key.sign(input)?,
            });
        }
        Ok(out)
    }

    /// The key sets this server will accept signatures from: its current
    /// sets, then the previous sets (#68).
    pub fn trusted(&self) -> TrustedKeys {
        let ed = VerifyingKey {
            algorithm: Algorithm::Ed25519,
            key_id: self.key_id.clone(),
            public_key: self.signing_key.public_key().to_vec(),
        };
        let ml = self.mldsa.as_ref().map(|m| VerifyingKey {
            algorithm: Algorithm::MlDsa87,
            key_id: m.key_id.clone(),
            public_key: m.key.public_key(),
        });
        let mut sets = signers::current_sets(ed, ml);
        sets.extend(self.previous.sets.iter().cloned());
        TrustedKeys::from_sets(sets, self.previous.revoked.clone())
    }

    /// Key ids of every signer, for logs and audit rows.
    pub fn key_ids(&self) -> Vec<String> {
        self.signers().into_iter().map(|s| s.key_id).collect()
    }
}

fn compute_key_id(vk: &[u8; 32]) -> String {
    signers::key_id(Algorithm::Ed25519, vk)
}

const ALGORITHM: &str = signers::ED25519;
/// Envelope / document format version.
pub const ENVELOPE_VERSION: u32 = 2;
/// Domain-separation prefix. Every signature's input is
/// `SIGN_DOMAIN || payload_bytes`, so a signature made here can never be
/// replayed as a signature over some other protocol's message.
pub const SIGN_DOMAIN: &[u8] = b"stig-viewer/sign/v2\0";

// ── Startup record of the trusted key sets (#68) ────────────────────────────

/// Audit action written once per start when signing is enabled.
pub const SIGNING_KEYS_ACTION: &str = "system.signing_keys";
/// Bound on the startup audit write; a slow database must not hold up startup.
const SIGNING_KEYS_EVENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Detail of `system.signing_keys`: the key ids in force and the previous-keys
/// configuration (public data only). A change to the trust list shows up as a
/// changed `previousKeysSha384`.
pub fn signing_keys_detail(s: &SigningState) -> serde_json::Value {
    let prev = &s.previous;
    serde_json::json!({
        "profile": s.profile().as_str(),
        "requireHybrid": s.require_hybrid,
        "currentKeyIds": s.key_ids(),
        "previous": prev.sets.iter().map(|set| serde_json::json!({
            "label": set.label,
            "profile": set.profile.as_str(),
            "keyIds": set.key_ids(),
            "retiredAt": set.retired_at,
        })).collect::<Vec<_>>(),
        "revoked": prev.revoked.iter().map(|r| serde_json::json!({
            "algorithm": r.algorithm.wire(),
            "keyId": r.key_id,
            "revokedAt": r.revoked_at,
            "reason": r.reason,
        })).collect::<Vec<_>>(),
        "previousKeysSource": if prev.source.is_empty() { "none" } else { prev.source },
        "previousKeysSha384": if prev.sha384.is_empty() { None } else { Some(prev.sha384.as_str()) },
    })
}

/// Record `system.signing_keys` for this start. Failure or timeout is logged
/// and startup continues, like the FIPS policy event.
pub async fn record_signing_keys_event(pool: &sqlx::PgPool, s: &SigningState) {
    let ev = crate::db_audit::NewSystemEvent {
        action: SIGNING_KEYS_ACTION,
        outcome: "ok",
        stig_id: None,
        detail: signing_keys_detail(s),
    };
    let res = tokio::time::timeout(
        SIGNING_KEYS_EVENT_TIMEOUT,
        crate::db_audit::record_system_now(pool, ev),
    )
    .await;
    let err = match res {
        Ok(Ok(())) => return,
        Ok(Err(e)) => format!("{e:#}"),
        Err(_) => "timed out".to_string(),
    };
    tracing::error!(
        target: "audit",
        action = SIGNING_KEYS_ACTION,
        outcome = "failure",
        profile = s.profile().as_str(),
        key_ids = %s.key_ids().join(","),
        previous_sets = s.previous.sets.len(),
        "audit write failed: {err}"
    );
}

// ── GET /api/signing/pubkey ─────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PubkeyResponse {
    pub algorithm: &'static str,
    pub key_id: String,
    /// Raw Ed25519 public key bytes, base64-standard (not URL-safe) encoded.
    pub public_key: String,
    /// Algorithm-tagged key list (envelope v2): the Ed25519 key (identical to
    /// the top-level fields) and, in hybrid mode, the ML-DSA-87 key (raw
    /// FIPS 204 bytes, base64-standard).
    pub keys: Vec<PubkeyEntry>,
    /// Retired key sets this server still verifies (#68). Public data;
    /// absent when none are configured. Verifiers must still pin out of band.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub previous_keys: Vec<PreviousKeySetEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviousKeySetEntry {
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<String>,
    pub keys: Vec<PubkeyEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PubkeyEntry {
    pub algorithm: &'static str,
    pub key_id: String,
    pub public_key: String,
}

fn pubkey_response(sk: &SigningState) -> PubkeyResponse {
    let public_key = BASE64.encode(sk.signing_key.public_key());
    let mut keys = vec![PubkeyEntry {
        algorithm: ALGORITHM,
        key_id: sk.key_id.clone(),
        public_key: public_key.clone(),
    }];
    if let Some(m) = &sk.mldsa {
        keys.push(PubkeyEntry {
            algorithm: signers::ML_DSA_87,
            key_id: m.key_id.clone(),
            public_key: BASE64.encode(m.key.public_key()),
        });
    }
    PubkeyResponse {
        algorithm: ALGORITHM,
        key_id: sk.key_id.clone(),
        public_key,
        keys,
        previous_keys: sk
            .previous
            .sets
            .iter()
            .map(|set| PreviousKeySetEntry {
                label: set.label.clone().unwrap_or_default(),
                retired_at: set.retired_at.clone(),
                keys: set
                    .keys
                    .iter()
                    .map(|k| PubkeyEntry {
                        algorithm: k.algorithm.wire(),
                        key_id: k.key_id.clone(),
                        public_key: BASE64.encode(&k.public_key),
                    })
                    .collect(),
            })
            .collect(),
    }
}

/// 503 unless a signing key is configured.
fn require_signing(
    signing: &Option<SigningState>,
) -> Result<&SigningState, (StatusCode, &'static str)> {
    signing
        .as_ref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "signing is not configured"))
}

pub async fn pubkey_handler(
    State(state): State<AppState>,
) -> Result<impl axum::response::IntoResponse, (StatusCode, &'static str)> {
    let sk = require_signing(&state.signing)?;
    let body = match sk.pubkey_cache.get() {
        Some(b) => b.clone(),
        None => {
            let bytes = serde_json::to_vec(&pubkey_response(sk)).map_err(|e| {
                tracing::error!("pubkey response: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            })?;
            sk.pubkey_cache.get_or_init(|| bytes.into()).clone()
        }
    };
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    ))
}

// ── POST /api/sign ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SignRequest {
    /// Base64-standard encoded bytes to sign. Clients that would rather
    /// not round-trip the whole payload may hash it client-side and send
    /// just the raw hash bytes here instead — the server hashes whatever
    /// it receives either way.
    pub content: String,
    /// Optional free-text label baked into the signing document (e.g. the
    /// STIG id). Shown back to verifiers so auditors can trace a signature
    /// to its source resource.
    #[serde(default)]
    pub resource: Option<String>,
}

/// Signing document. Serde preserves struct field order on serialisation.
///
/// The signed bytes (the envelope's `payload`) are `serde_json::to_vec` of
/// this struct: compact JSON, fields in declaration order (`version`,
/// `algorithm`, `keyId`, `signers`, `sha256`, `sha512`, `signedAt`,
/// `signedBy`, `signedByName`, then `resource` only when present), UTF-8.
/// Verifiers never rebuild these bytes: they decode `payload`, verify, then
/// parse it.
///
/// `algorithm` and `keyId` are kept for compatibility and equal `signers[0]`
/// (the Ed25519 signer).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningDocument {
    pub version: u32,
    pub algorithm: &'static str,
    pub key_id: String,
    /// Every signer that must have signed these bytes.
    pub signers: Vec<SignerId>,
    pub sha256: String,
    pub sha512: String,
    pub signed_at: String,
    pub signed_by: String,
    pub signed_by_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedBundle {
    /// Convenience copy of the signed document. NOT authenticated: only
    /// `payload` is. Verifiers must read fields from the verified payload.
    pub document: SigningDocument,
    /// base64url (no padding) of the exact bytes that were signed
    /// (before the domain prefix).
    pub payload: String,
    /// Legacy field, classical profile only: the base64-standard Ed25519
    /// signature, equal to `signatures[0].signature`. Omitted in hybrid output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Legacy field, classical profile only; equals `signatures[0].key_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Envelope version (2).
    pub version: u32,
    /// Algorithm-tagged signatures over `SIGN_DOMAIN || payload`, one per
    /// signed signer, in signer order.
    pub signatures: Vec<BundleSignature>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleSignature {
    pub algorithm: &'static str,
    pub key_id: String,
    pub signature: String,
}

/// Canonical signed bytes for a document.
fn document_bytes(document: &SigningDocument) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(document)
}

fn signing_input(payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGN_DOMAIN.len() + payload.len());
    input.extend_from_slice(SIGN_DOMAIN);
    input.extend_from_slice(payload);
    input
}

fn build_bundle(sk: &SigningState, document: SigningDocument) -> anyhow::Result<SignedBundle> {
    let payload = document_bytes(&document)?;
    let signatures: Vec<BundleSignature> = sk
        .sign_all(&signing_input(&payload))?
        .into_iter()
        .map(|p| BundleSignature {
            algorithm: p.algorithm.wire(),
            key_id: p.key_id,
            signature: BASE64.encode(p.signature),
        })
        .collect();
    let classical = sk.profile() == Profile::Classical;
    Ok(SignedBundle {
        document,
        payload: URL_SAFE_NO_PAD.encode(&payload),
        signature: classical.then(|| signatures[0].signature.clone()),
        key_id: classical.then(|| sk.key_id.clone()),
        version: ENVELOPE_VERSION,
        signatures,
    })
}

// ── Reference verifier ──────────────────────────────────────────────────────

/// Fields of the signed document, parsed from the verified payload.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // reference verifier: exercised by tests, no in-tree caller
pub struct VerifiedDocument {
    pub version: Option<u32>,
    pub algorithm: String,
    pub key_id: String,
    pub signers: Vec<SignerId>,
    pub sha256: String,
    /// Absent in bundles signed before #67.
    #[serde(default)]
    pub sha512: Option<String>,
    pub signed_at: String,
    pub signed_by: String,
    pub signed_by_name: String,
    #[serde(default)]
    pub resource: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)] // reference verifier: exercised by tests, no in-tree caller
pub enum VerifyError {
    /// Envelope is not JSON of the expected shape, or has no `payload`/`signatures` (e.g. v1).
    MalformedEnvelope,
    BadPayloadEncoding,
    /// Payload is not a signing document.
    MalformedDocument,
    /// Signed document has no `version`, or it is not 2 (v1 documents).
    UnsupportedVersion,
    /// A signer uses an algorithm this verifier cannot check.
    UnsupportedAlgorithm(String),
    /// `signers` is not exactly `[ed25519]` or `[ed25519, ml-dsa-87]`, or
    /// `algorithm`/`keyId` disagree with `signers[0]`.
    BadSignerSet,
    /// The bundle is classical and the caller does not accept that.
    ClassicalNotAllowed,
    /// A signer has no matching entry in `signatures`.
    MissingSignature,
    /// `signatures` has an entry that is not in the signed `signers`, or a duplicate.
    UnexpectedSignature,
    BadSignatureEncoding,
    SignatureInvalid,
    /// A signer's keyId is not a trusted key's fingerprint, or the signer list
    /// is not exactly one trusted key set (halves of two generations, or a
    /// hybrid half presented as classical).
    KeyIdMismatch,
    /// A signer is on the revoked list.
    KeyRevoked,
    ArtifactHashMismatch,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bundle verification failed: {self:?}")
    }
}

impl std::error::Error for VerifyError {}

#[derive(Deserialize)]
#[allow(dead_code)] // reference verifier: exercised by tests, no in-tree caller
struct EnvelopeIn {
    payload: String,
    signatures: Vec<SignatureIn>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // reference verifier: exercised by tests, no in-tree caller
struct SignatureIn {
    algorithm: String,
    key_id: String,
    signature: String,
}

/// Maximum number of entries accepted in `signers`.
const MAX_SIGNERS: usize = 8;

/// Reference verifier for the v2 envelope. Only `payload` and `signatures`
/// are read from the envelope; `document`, `signature`, `keyId` and `version`
/// at the top level are unauthenticated and ignored.
///
/// Steps: decode `payload` (strict base64url, no padding); parse it (duplicate
/// keys and trailing bytes are errors); require signed `version == 2`; require
/// a non-empty `signers` list of at most 8 entries whose first entry equals the
/// signed `algorithm`/`keyId`; reject any unsupported signer algorithm; require
/// the signer list to equal exactly one trusted key set (current or previous,
/// #68) and none to be revoked; require the signer set to
/// be exactly `[ed25519]` (only when `allow_classical`) or
/// `[ed25519, ml-dsa-87]`; require the `signatures` set to equal the `signers`
/// set; verify every signature over `SIGN_DOMAIN || payload`; and require the
/// signed `sha256` to equal `artifact_sha256`. The hash comparison is
/// case-insensitive (hex), and the hash is mandatory so a valid bundle for a
/// different artifact cannot be accepted.
#[allow(dead_code)] // reference verifier: exercised by tests, no in-tree caller
pub fn verify_bundle(
    bundle_json: &[u8],
    trusted: &TrustedKeys,
    allow_classical: bool,
    artifact_sha256: &str,
) -> Result<VerifiedDocument, VerifyError> {
    verify_inner(bundle_json, trusted, allow_classical, Some(artifact_sha256)).map(|(d, _)| d)
}

/// [`verify_bundle`] that also reports whether a current or a previous key set
/// verified the bundle.
#[cfg(test)]
pub fn verify_bundle_with_source(
    bundle_json: &[u8],
    trusted: &TrustedKeys,
    allow_classical: bool,
    artifact_sha256: &str,
) -> Result<(VerifiedDocument, KeySource), VerifyError> {
    verify_inner(bundle_json, trusted, allow_classical, Some(artifact_sha256))
}

/// Same checks as [`verify_bundle`] but without an artifact hash: it proves
/// the trusted keys signed the document and does NOT bind any artifact.
/// Callers must compare `sha256` against their artifact themselves.
#[allow(dead_code)] // reference verifier: exercised by tests, no in-tree caller
pub fn verify_bundle_document_only(
    bundle_json: &[u8],
    trusted: &TrustedKeys,
    allow_classical: bool,
) -> Result<VerifiedDocument, VerifyError> {
    verify_inner(bundle_json, trusted, allow_classical, None).map(|(d, _)| d)
}

fn verify_inner(
    bundle_json: &[u8],
    trusted: &TrustedKeys,
    allow_classical: bool,
    artifact_sha256: Option<&str>,
) -> Result<(VerifiedDocument, KeySource), VerifyError> {
    let env: EnvelopeIn =
        serde_json::from_slice(bundle_json).map_err(|_| VerifyError::MalformedEnvelope)?;
    let payload = URL_SAFE_NO_PAD
        .decode(env.payload.as_bytes())
        .map_err(|_| VerifyError::BadPayloadEncoding)?;
    let doc: VerifiedDocument =
        serde_json::from_slice(&payload).map_err(|_| VerifyError::MalformedDocument)?;

    if doc.version != Some(ENVELOPE_VERSION) {
        return Err(VerifyError::UnsupportedVersion);
    }
    let first = doc.signers.first().ok_or(VerifyError::BadSignerSet)?;
    if first.algorithm != doc.algorithm || first.key_id != doc.key_id {
        return Err(VerifyError::BadSignerSet);
    }
    if doc.signers.len() > MAX_SIGNERS {
        return Err(VerifyError::BadSignerSet);
    }
    for s in &doc.signers {
        let alg = Algorithm::from_wire(&s.algorithm)
            .ok_or_else(|| VerifyError::UnsupportedAlgorithm(s.algorithm.clone()))?;
        if trusted.revoked(alg, &s.key_id).is_some() {
            return Err(VerifyError::KeyRevoked);
        }
        if trusted.find(alg, &s.key_id).is_none() {
            return Err(VerifyError::KeyIdMismatch);
        }
    }
    let profile = signers::classify(doc.signers.iter().map(|s| s.algorithm.as_str())).map_err(
        |e| match e {
            signers::ClassifyError::UnsupportedAlgorithm(a) => VerifyError::UnsupportedAlgorithm(a),
            signers::ClassifyError::BadSet => VerifyError::BadSignerSet,
        },
    )?;
    if profile == Profile::Classical && !allow_classical {
        return Err(VerifyError::ClassicalNotAllowed);
    }
    // Trust is per key set: the signed signer list must be exactly one trusted
    // set, so halves of two generations never combine and a previous hybrid
    // half is never accepted as a classical signer.
    let source = trusted
        .resolve(&doc.signers)
        .ok_or(VerifyError::KeyIdMismatch)?
        .source;

    for (i, sig) in env.signatures.iter().enumerate() {
        let known = doc
            .signers
            .iter()
            .any(|s| s.algorithm == sig.algorithm && s.key_id == sig.key_id);
        let duplicate = env.signatures[..i]
            .iter()
            .any(|o| o.algorithm == sig.algorithm && o.key_id == sig.key_id);
        if !known || duplicate {
            return Err(VerifyError::UnexpectedSignature);
        }
    }
    let input = signing_input(&payload);
    for signer in &doc.signers {
        let sig = env
            .signatures
            .iter()
            .find(|s| s.algorithm == signer.algorithm && s.key_id == signer.key_id)
            .ok_or(VerifyError::MissingSignature)?;
        let raw = BASE64
            .decode(sig.signature.as_bytes())
            .map_err(|_| VerifyError::BadSignatureEncoding)?;
        // Both lookups succeeded in the loop above.
        let alg = Algorithm::from_wire(&signer.algorithm)
            .ok_or_else(|| VerifyError::UnsupportedAlgorithm(signer.algorithm.clone()))?;
        let key = trusted
            .find(alg, &signer.key_id)
            .ok_or(VerifyError::KeyIdMismatch)?;
        signers::verify_sig(alg, &key.public_key, &input, &raw).map_err(|e| match e {
            signers::SigError::BadLength => VerifyError::BadSignatureEncoding,
            signers::SigError::Invalid => VerifyError::SignatureInvalid,
        })?;
    }

    if let Some(expected) = artifact_sha256 {
        if !expected.eq_ignore_ascii_case(&doc.sha256) {
            return Err(VerifyError::ArtifactHashMismatch);
        }
    }
    Ok((doc, source))
}

/// Cap signed payloads at 100 MiB. Larger inputs should be hashed
/// client-side; the server only cares about the hashes in the document.
const MAX_SIGN_BYTES: usize = 100 * 1024 * 1024;

/// Validates the request and builds the signed bundle. Returns the bundle and
/// the content length.
fn sign_request(
    sk: &SigningState,
    user: &AuthUser,
    body: &SignRequest,
) -> Result<(SignedBundle, usize), (StatusCode, String)> {
    let content = BASE64.decode(body.content.trim()).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("content must be base64: {e}"),
        )
    })?;
    if content.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "content must not be empty".into()));
    }
    if content.len() > MAX_SIGN_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("content exceeds {} bytes", MAX_SIGN_BYTES),
        ));
    }

    let document = SigningDocument {
        version: ENVELOPE_VERSION,
        algorithm: ALGORITHM,
        key_id: sk.key_id.clone(),
        signers: sk.signers(),
        sha256: crypto::digest::sha256_hex(&content),
        sha512: crypto::digest::sha512_hex(&content),
        signed_at: chrono::Utc::now().to_rfc3339(),
        signed_by: user.id.clone(),
        signed_by_name: user.display_name.clone(),
        resource: body.resource.clone().filter(|s| !s.is_empty()),
    };

    let bundle = build_bundle(sk, document).map_err(|e| {
        tracing::error!("sign document: {e:#}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "signing failed".to_string(),
        )
    })?;
    Ok((bundle, content.len()))
}

pub async fn sign_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(ctx): Extension<RequestCtx>,
    Json(body): Json<SignRequest>,
) -> Result<Json<SignedBundle>, (StatusCode, String)> {
    let sk = require_signing(&state.signing).map_err(|(c, m)| (c, m.to_string()))?;

    // ML-DSA signing is CPU-bound (and the content may be up to 100 MiB to
    // hash), so it runs off the async workers. The audit row below is still
    // written before the bundle is returned.
    let (signer, signing_user) = (sk.clone(), user.clone());
    let (bundle, bytes) =
        tokio::task::spawn_blocking(move || sign_request(&signer, &signing_user, &body))
            .await
            .map_err(|e| {
                tracing::error!("sign task failed: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "signing failed".to_string(),
                )
            })??;

    let algorithms = bundle
        .signatures
        .iter()
        .map(|s| s.algorithm)
        .collect::<Vec<_>>()
        .join(",");
    let key_ids = sk.key_ids();
    let profile = sk.profile().as_str();
    // No mutation exists, so the row is its own one-statement transaction,
    // committed before the signature is returned.
    let resource = bundle.document.resource.as_deref();
    let mut ev = audit_tx::ok_event(
        &user,
        &ctx,
        "signing.sign",
        serde_json::json!({
            "sha256": bundle.document.sha256,
            "keyId": sk.key_id,
            "keyIds": key_ids,
            "profile": profile,
            "bytes": bytes,
            "version": bundle.version,
            "algorithms": algorithms,
            "resourcePresent": resource.is_some(),
        }),
    );
    ev.stig_id = resource.filter(|r| is_valid_stig_id(r));
    let unavailable = |e: anyhow::Error| (audit_tx::failed(e), "signing unavailable".to_string());
    let mut tx = crate::db::begin_bounded(state.pool.as_ref())
        .await
        .map_err(unavailable)?;
    audit_tx::record(&mut tx, &ev).await.map_err(unavailable)?;
    tx.commit().await.map_err(|e| unavailable(e.into()))?;

    tracing::info!(
        user = %user.id,
        sha256 = %bundle.document.sha256,
        key_id = %sk.key_id,
        key_ids = %key_ids.join(","),
        profile,
        version = bundle.version,
        algorithms = %algorithms,
        bytes,
        resource = %bundle.document.resource.as_deref().unwrap_or(""),
        "signing.sign"
    );

    Ok(Json(bundle))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// Classical state with a per-process random key (no key material in source).
    fn test_state() -> SigningState {
        crate::integrity::test_key(100)
    }

    /// Hybrid state: the same Ed25519 key as [`test_state`] plus an ML-DSA-87 key.
    fn hybrid_state() -> SigningState {
        crate::integrity::test_hybrid_key(100)
    }

    fn other_key() -> TrustedKeys {
        TrustedKeys::from_ed25519(&crate::integrity::test_key(101).signing_key.public_key())
    }

    fn sample_doc(st: &SigningState, sha256: String) -> SigningDocument {
        SigningDocument {
            version: ENVELOPE_VERSION,
            algorithm: ALGORITHM,
            key_id: st.key_id.clone(),
            signers: st.signers(),
            sha256,
            sha512: "cd".repeat(64),
            signed_at: "2026-01-01T00:00:00Z".into(),
            signed_by: "u1".into(),
            signed_by_name: "User One".into(),
            resource: Some("windows-11".into()),
        }
    }

    fn sample_bundle(st: &SigningState) -> SignedBundle {
        build_bundle(st, sample_doc(st, "ab".repeat(32))).unwrap()
    }

    fn wire(st: &SigningState) -> Value {
        serde_json::to_value(sample_bundle(st)).unwrap()
    }

    fn verify(
        v: &Value,
        st: &SigningState,
        hash: Option<&str>,
    ) -> Result<VerifiedDocument, VerifyError> {
        let bytes = serde_json::to_vec(v).unwrap();
        let trusted = st.trusted();
        match hash {
            Some(h) => verify_bundle(&bytes, &trusted, true, h),
            None => verify_bundle_document_only(&bytes, &trusted, true),
        }
    }

    /// Re-signs an arbitrary payload value with the test key, returning a wire envelope.
    fn resign(st: &SigningState, payload: &Value) -> Value {
        let bytes = serde_json::to_vec(payload).unwrap();
        resign_raw(st, &bytes)
    }

    /// A wire envelope signing `bytes` with every key of `st`.
    fn resign_raw(st: &SigningState, bytes: &[u8]) -> Value {
        let sigs: Vec<Value> = st
            .sign_all(&signing_input(bytes))
            .unwrap()
            .into_iter()
            .map(|p| {
                json!({
                    "algorithm": p.algorithm.wire(),
                    "keyId": p.key_id,
                    "signature": BASE64.encode(p.signature)
                })
            })
            .collect();
        json!({"payload": URL_SAFE_NO_PAD.encode(bytes), "signatures": sigs})
    }

    fn payload_value(v: &Value) -> Value {
        let b = URL_SAFE_NO_PAD
            .decode(v["payload"].as_str().unwrap())
            .unwrap();
        serde_json::from_slice(&b).unwrap()
    }

    #[test]
    fn legacy_fields_equal_first_signature() {
        let b = sample_bundle(&test_state());
        assert_eq!(b.version, 2);
        assert_eq!(b.signatures.len(), 1);
        assert_eq!(b.signature.as_ref(), Some(&b.signatures[0].signature));
        assert_eq!(b.key_id.as_ref(), Some(&b.signatures[0].key_id));
        assert_eq!(b.signatures[0].algorithm, "ed25519");
        assert_eq!(b.document.signers[0].key_id, b.document.key_id);
    }

    #[test]
    fn payload_is_exactly_the_signed_document_bytes() {
        let st = test_state();
        let b = sample_bundle(&st);
        let bytes = URL_SAFE_NO_PAD.decode(&b.payload).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&b.document).unwrap());
        assert!(!b.payload.contains('=') && !b.payload.contains('+') && !b.payload.contains('/'));
        assert!(bytes.starts_with(br#"{"version":2,"algorithm":"ed25519","keyId":""#));
    }

    #[test]
    fn happy_path_verifies_via_payload() {
        let st = test_state();
        let doc = verify(&wire(&st), &st, Some(&"AB".repeat(32))).unwrap();
        assert_eq!(doc.version, Some(2));
        assert_eq!(doc.sha256, "ab".repeat(32));
        assert_eq!(doc.signed_by, "u1");
        assert_eq!(doc.resource.as_deref(), Some("windows-11"));
        assert!(verify(&wire(&st), &st, None).is_ok());
    }

    #[test]
    fn tampered_payload_rejected() {
        let st = test_state();
        let mut v = wire(&st);
        let mut b = URL_SAFE_NO_PAD
            .decode(v["payload"].as_str().unwrap())
            .unwrap();
        let n = b.len() - 3;
        b[n] ^= 1;
        v["payload"] = URL_SAFE_NO_PAD.encode(&b).into();
        assert!(verify(&v, &st, None).is_err());
        v["payload"] = "!!!not base64".into();
        assert_eq!(verify(&v, &st, None), Err(VerifyError::BadPayloadEncoding));
    }

    #[test]
    fn unsigned_envelope_document_and_legacy_fields_are_ignored() {
        let st = test_state();
        let mut v = wire(&st);
        v["document"]["sha256"] = "00".repeat(32).into();
        v["document"]["signedBy"] = "attacker".into();
        v["signature"] = "garbage".into();
        v["keyId"] = "ffffffffffffffff".into();
        v["version"] = 1.into();
        let doc = verify(&v, &st, None).unwrap();
        assert_eq!(doc.sha256, "ab".repeat(32));
        assert_eq!(doc.signed_by, "u1");
    }

    #[test]
    fn stripped_signature_rejected() {
        let st = test_state();
        let mut v = wire(&st);
        v["signatures"] = json!([]);
        assert_eq!(verify(&v, &st, None), Err(VerifyError::MissingSignature));
    }

    #[test]
    fn extra_unsigned_signature_rejected() {
        let st = test_state();
        let mut v = wire(&st);
        let first = v["signatures"][0].clone();
        v["signatures"].as_array_mut().unwrap().push(json!({
            "algorithm": "ml-dsa-65", "keyId": st.key_id, "signature": first["signature"]
        }));
        assert_eq!(verify(&v, &st, None), Err(VerifyError::UnexpectedSignature));
        let mut v = wire(&st);
        v["signatures"].as_array_mut().unwrap().push(first);
        assert_eq!(verify(&v, &st, None), Err(VerifyError::UnexpectedSignature));
    }

    #[test]
    fn unknown_algorithm_in_signers_rejected_not_skipped() {
        let st = test_state();
        let mut p = payload_value(&wire(&st));
        p["signers"]
            .as_array_mut()
            .unwrap()
            .push(json!({"algorithm": "ml-dsa-65", "keyId": "0011223344556677"}));
        let mut v = resign(&st, &p);
        assert_eq!(
            verify(&v, &st, None),
            Err(VerifyError::UnsupportedAlgorithm("ml-dsa-65".into()))
        );
        v["signatures"].as_array_mut().unwrap().push(json!({
            "algorithm": "ml-dsa-65", "keyId": "0011223344556677", "signature": "AAAA"
        }));
        assert!(matches!(
            verify(&v, &st, None),
            Err(VerifyError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn wrong_pinned_key_rejected() {
        let st = test_state();
        let r = verify_bundle_document_only(
            &serde_json::to_vec(&wire(&st)).unwrap(),
            &other_key(),
            true,
        );
        assert_eq!(r, Err(VerifyError::KeyIdMismatch));
    }

    #[test]
    fn wrong_artifact_hash_rejected() {
        let st = test_state();
        let r = verify(&wire(&st), &st, Some(&"cd".repeat(32)));
        assert_eq!(r, Err(VerifyError::ArtifactHashMismatch));
    }

    #[test]
    fn missing_version_v1_rejected() {
        let st = test_state();
        // v1 envelope: no payload at all.
        let v1 =
            json!({"document": {"algorithm": "ed25519"}, "signature": "x", "keyId": st.key_id});
        assert_eq!(verify(&v1, &st, None), Err(VerifyError::MalformedEnvelope));
        // Signed payload without `version`.
        let mut p = payload_value(&wire(&st));
        p.as_object_mut().unwrap().remove("version");
        assert_eq!(
            verify(&resign(&st, &p), &st, None),
            Err(VerifyError::UnsupportedVersion)
        );
        p["version"] = 1.into();
        assert_eq!(
            verify(&resign(&st, &p), &st, None),
            Err(VerifyError::UnsupportedVersion)
        );
    }

    #[test]
    fn signature_without_domain_prefix_rejected() {
        let st = test_state();
        let mut v = wire(&st);
        let bytes = URL_SAFE_NO_PAD
            .decode(v["payload"].as_str().unwrap())
            .unwrap();
        let bare = BASE64.encode(st.signing_key.sign(&bytes));
        v["signatures"][0]["signature"] = bare.into();
        assert_eq!(verify(&v, &st, None), Err(VerifyError::SignatureInvalid));
    }

    #[test]
    fn signer_list_must_match_signed_algorithm_and_key_id() {
        let st = test_state();
        let mut p = payload_value(&wire(&st));
        p["signers"][0]["keyId"] = "0000000000000000".into();
        assert_eq!(
            verify(&resign(&st, &p), &st, None),
            Err(VerifyError::BadSignerSet)
        );
        p["signers"] = json!([]);
        assert_eq!(
            verify(&resign(&st, &p), &st, None),
            Err(VerifyError::BadSignerSet)
        );
    }

    #[test]
    fn duplicate_signers_rejected() {
        let st = test_state();
        let mut p = payload_value(&wire(&st));
        let a = p["signers"][0].clone();
        p["signers"] = json!([a, a]);
        assert_eq!(
            verify(&resign(&st, &p), &st, None),
            Err(VerifyError::BadSignerSet)
        );
    }

    #[test]
    fn too_many_signers_rejected() {
        let st = test_state();
        let mut p = payload_value(&wire(&st));
        let a = p["signers"][0].clone();
        p["signers"] = json!(vec![a; MAX_SIGNERS + 1]);
        assert_eq!(
            verify(&resign(&st, &p), &st, None),
            Err(VerifyError::BadSignerSet)
        );
    }

    #[test]
    fn wrong_pinned_key_is_reported_before_duplicates() {
        let st = test_state();
        let mut p = payload_value(&wire(&st));
        let a = p["signers"][0].clone();
        p["signers"] = json!([a, a]);
        let bytes = serde_json::to_vec(&resign(&st, &p)).unwrap();
        assert_eq!(
            verify_bundle_document_only(&bytes, &other_key(), true),
            Err(VerifyError::KeyIdMismatch)
        );
    }

    #[test]
    fn duplicate_signatures_rejected() {
        let st = test_state();
        let mut v = wire(&st);
        let first = v["signatures"][0].clone();
        v["signatures"].as_array_mut().unwrap().push(first);
        assert_eq!(verify(&v, &st, None), Err(VerifyError::UnexpectedSignature));
    }

    #[test]
    fn padded_standard_alphabet_and_noncanonical_payload_rejected() {
        let st = test_state();
        // Padded: try three resource lengths so every padding amount is covered.
        let mut padded_cases = 0;
        let mut bits_cases = 0;
        for extra in ["", "a", "aa"] {
            let mut p = payload_value(&wire(&st));
            p["resource"] = format!("windows-11{extra}").into();
            let raw = serde_json::to_vec(&p).unwrap();
            let v = resign_raw(&st, &raw);
            assert!(verify(&v, &st, None).is_ok());
            let good = v["payload"].as_str().unwrap().to_string();
            let mut padded = good.clone();
            while !padded.len().is_multiple_of(4) {
                padded.push('=');
            }
            if padded != good {
                padded_cases += 1;
                let mut bad = v.clone();
                bad["payload"] = padded.into();
                assert_eq!(
                    verify(&bad, &st, None),
                    Err(VerifyError::BadPayloadEncoding)
                );
                // Non-canonical trailing bits: same length, last char differs in the
                // unused low bits.
                let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                let mut chars: Vec<char> = good.chars().collect();
                let last = chars.len() - 1;
                let idx = alphabet.find(chars[last]).unwrap();
                chars[last] = alphabet.chars().nth(idx ^ 1).unwrap();
                let mut bad = v.clone();
                bad["payload"] = chars.into_iter().collect::<String>().into();
                assert_eq!(
                    verify(&bad, &st, None),
                    Err(VerifyError::BadPayloadEncoding)
                );
                bits_cases += 1;
            }
        }
        assert!(padded_cases >= 1 && bits_cases >= 1);
        // Standard alphabet: find bytes whose encoding uses '-' or '_'.
        let mut payload = payload_value(&wire(&st));
        payload["resource"] = "???>>>~~~".into();
        let raw = serde_json::to_vec(&payload).unwrap();
        let url = URL_SAFE_NO_PAD.encode(&raw);
        let std_alpha = BASE64.encode(&raw).trim_end_matches('=').to_string();
        assert_ne!(url, std_alpha, "fixture must exercise - and _");
        let mut v = resign_raw(&st, &raw);
        assert!(verify(&v, &st, None).is_ok());
        v["payload"] = std_alpha.into();
        assert_eq!(verify(&v, &st, None), Err(VerifyError::BadPayloadEncoding));
    }

    #[test]
    fn trailing_bytes_after_payload_json_rejected() {
        let st = test_state();
        let mut raw = serde_json::to_vec(&payload_value(&wire(&st))).unwrap();
        raw.extend_from_slice(b" ");
        assert!(verify(&resign_raw(&st, &raw), &st, None).is_ok());
        raw.extend_from_slice(b"x");
        assert_eq!(
            verify(&resign_raw(&st, &raw), &st, None),
            Err(VerifyError::MalformedDocument)
        );
    }

    #[test]
    fn duplicate_key_in_payload_json_rejected() {
        let st = test_state();
        let mut raw = serde_json::to_vec(&payload_value(&wire(&st))).unwrap();
        raw.pop();
        raw.extend_from_slice(br#","sha256":"00"}"#);
        assert_eq!(
            verify(&resign_raw(&st, &raw), &st, None),
            Err(VerifyError::MalformedDocument)
        );
    }

    #[test]
    fn invalid_signature_encoding_rejected() {
        let st = test_state();
        let mut v = wire(&st);
        let sig = v["signatures"][0]["signature"]
            .as_str()
            .unwrap()
            .to_string();
        v["signatures"][0]["signature"] = format!("!{}", &sig[1..]).into();
        assert_eq!(
            verify(&v, &st, None),
            Err(VerifyError::BadSignatureEncoding)
        );
        v["signatures"][0]["signature"] = sig[..10].into();
        assert_eq!(
            verify(&v, &st, None),
            Err(VerifyError::BadSignatureEncoding)
        );
    }

    #[test]
    fn artifact_hash_is_mandatory_in_verify_bundle() {
        let st = test_state();
        let bytes = serde_json::to_vec(&wire(&st)).unwrap();
        let vk = st.trusted();
        assert!(verify_bundle(&bytes, &vk, true, &"AB".repeat(32)).is_ok());
        assert_eq!(
            verify_bundle(&bytes, &vk, true, ""),
            Err(VerifyError::ArtifactHashMismatch)
        );
    }

    #[test]
    fn missing_signing_key_is_503() {
        let err = require_signing(&None).err().unwrap();
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
        assert!(require_signing(&Some(test_state())).is_ok());
    }

    #[test]
    fn envelope_json_shape_snapshot() {
        let st = test_state();
        let mut v = wire(&st);
        let sig = v["signature"].as_str().unwrap().to_string();
        assert_eq!(v["signatures"][0]["signature"], sig.as_str());
        let payload = v["payload"].as_str().unwrap().to_string();
        v["signature"] = "SIG".into();
        v["signatures"][0]["signature"] = "SIG".into();
        v["payload"] = "PAYLOAD".into();
        let signer = json!({"algorithm": "ed25519", "keyId": st.key_id});
        let expected = json!({
            "document": {
                "version": 2, "algorithm": "ed25519", "keyId": st.key_id,
                "signers": [signer],
                "sha256": "ab".repeat(32), "sha512": "cd".repeat(64), "signedAt": "2026-01-01T00:00:00Z",
                "signedBy": "u1", "signedByName": "User One", "resource": "windows-11"
            },
            "payload": "PAYLOAD",
            "signature": "SIG", "keyId": st.key_id, "version": 2,
            "signatures": [{"algorithm": "ed25519", "keyId": st.key_id, "signature": "SIG"}]
        });
        assert_eq!(v, expected);
        assert_eq!(v.as_object().unwrap().len(), 6);
        assert_eq!(
            payload_value(&json!({"payload": payload}))["signers"][0],
            signer
        );
    }

    #[test]
    fn pubkey_json_shape_snapshot() {
        let st = test_state();
        let v = serde_json::to_value(pubkey_response(&st)).unwrap();
        let pk = BASE64.encode(st.signing_key.public_key());
        assert_eq!(
            v,
            json!({
                "algorithm": "ed25519", "keyId": st.key_id, "publicKey": pk,
                "keys": [{"algorithm": "ed25519", "keyId": st.key_id, "publicKey": pk}]
            })
        );
    }

    fn user() -> AuthUser {
        AuthUser {
            id: "u1".into(),
            display_name: "User One".into(),
            email: "u1@example.test".into(),
            role: "user".into(),
        }
    }

    fn request(content: &str, resource: Option<&str>) -> SignRequest {
        SignRequest {
            content: content.into(),
            resource: resource.map(String::from),
        }
    }

    #[test]
    fn resource_none_is_absent_and_empty_becomes_none() {
        let st = test_state();
        let content = BASE64.encode(b"hello");
        for res in [None, Some("")] {
            let (b, n) = sign_request(&st, &user(), &request(&content, res)).unwrap();
            assert_eq!(n, 5);
            assert!(b.document.resource.is_none());
            let bytes = URL_SAFE_NO_PAD.decode(&b.payload).unwrap();
            assert!(!String::from_utf8(bytes).unwrap().contains("resource"));
        }
        let (b, _) = sign_request(&st, &user(), &request(&content, Some("r1"))).unwrap();
        assert_eq!(b.document.resource.as_deref(), Some("r1"));
        let wire = serde_json::to_vec(&b).unwrap();
        let doc = verify_bundle(
            &wire,
            &st.trusted(),
            true,
            &crypto::digest::sha256_hex(b"hello"),
        )
        .unwrap();
        assert_eq!(doc.signed_by, "u1");
    }

    #[test]
    fn sign_request_rejects_bad_input() {
        let st = test_state();
        let bad = sign_request(&st, &user(), &request("***", None))
            .err()
            .unwrap();
        assert_eq!(bad.0, StatusCode::BAD_REQUEST);
        let empty = sign_request(&st, &user(), &request("", None))
            .err()
            .unwrap();
        assert_eq!(empty.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn from_hex_returns_none_when_unset_or_blank() {
        assert!(SigningState::from_hex(None).unwrap().is_none());
        assert!(SigningState::from_hex(Some("  ")).unwrap().is_none());
    }

    #[test]
    fn from_hex_rejects_short_key() {
        let err = SigningState::from_hex(Some("deadbeef")).unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
        assert!(SigningState::from_hex(Some("zz")).is_err());
        assert!(SigningState::from_hex(Some(&"ab".repeat(32)))
            .unwrap()
            .is_some());
    }

    #[test]
    fn key_id_is_deterministic_and_short() {
        let a = test_state();
        let b = test_state();
        assert_eq!(a.key_id, b.key_id);
        // 8 bytes → 16 hex chars.
        assert_eq!(a.key_id.len(), 16);
    }

    // ── Hybrid (#66, #67) ──────────────────────────────────────────────────

    fn hybrid_wire(st: &SigningState) -> Value {
        serde_json::to_value(sample_bundle(st)).unwrap()
    }

    fn verify_strict(v: &Value, st: &SigningState) -> Result<VerifiedDocument, VerifyError> {
        verify_bundle_document_only(&serde_json::to_vec(v).unwrap(), &st.trusted(), false)
    }

    #[test]
    fn hybrid_bundle_shape_and_verification() {
        let st = hybrid_state();
        assert_eq!(st.profile(), Profile::Hybrid);
        let v = hybrid_wire(&st);
        // Legacy top-level signature/keyId are classical-only.
        assert!(v.get("signature").is_none() && v.get("keyId").is_none());
        assert_eq!(v["version"], 2);
        let sigs = v["signatures"].as_array().unwrap();
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0]["algorithm"], "ed25519");
        assert_eq!(sigs[0]["keyId"].as_str().unwrap().len(), 16);
        assert_eq!(sigs[1]["algorithm"], "ml-dsa-87");
        assert_eq!(sigs[1]["keyId"].as_str().unwrap().len(), 32);
        let ml = BASE64
            .decode(sigs[1]["signature"].as_str().unwrap())
            .unwrap();
        assert_eq!(ml.len(), crypto::mldsa::SIGNATURE_LEN);
        let p = payload_value(&v);
        assert_eq!(p["signers"].as_array().unwrap().len(), 2);
        assert_eq!(p["sha512"], "cd".repeat(64).as_str());
        assert_eq!(p["algorithm"], "ed25519");
        let doc = verify_strict(&v, &st).unwrap();
        assert_eq!(doc.sha512.as_deref(), Some("cd".repeat(64).as_str()));
        assert!(verify_bundle(
            &serde_json::to_vec(&v).unwrap(),
            &st.trusted(),
            false,
            &"AB".repeat(32)
        )
        .is_ok());
    }

    #[test]
    fn hybrid_each_signature_is_required() {
        let st = hybrid_state();
        let mut v = hybrid_wire(&st);
        v["signatures"].as_array_mut().unwrap().remove(1);
        assert_eq!(verify_strict(&v, &st), Err(VerifyError::MissingSignature));
        let mut v = hybrid_wire(&st);
        v["signatures"].as_array_mut().unwrap().remove(0);
        assert_eq!(verify_strict(&v, &st), Err(VerifyError::MissingSignature));
        let mut v = hybrid_wire(&st);
        v["signatures"] = json!([]);
        assert_eq!(verify_strict(&v, &st), Err(VerifyError::MissingSignature));
    }

    #[test]
    fn hybrid_swapped_duplicated_and_flipped_signatures_rejected() {
        let st = hybrid_state();
        let v = hybrid_wire(&st);
        // Signature bytes swapped between the two entries.
        let mut sw = v.clone();
        let (a, b) = (
            v["signatures"][0]["signature"].clone(),
            v["signatures"][1]["signature"].clone(),
        );
        sw["signatures"][0]["signature"] = b;
        sw["signatures"][1]["signature"] = a;
        assert_eq!(
            verify_strict(&sw, &st),
            Err(VerifyError::BadSignatureEncoding)
        );
        // Duplicate entry.
        let mut dup = v.clone();
        let ml = v["signatures"][1].clone();
        dup["signatures"].as_array_mut().unwrap().push(ml);
        assert_eq!(
            verify_strict(&dup, &st),
            Err(VerifyError::UnexpectedSignature)
        );
        // One flipped byte in the ML-DSA signature.
        let mut bad = v.clone();
        let mut raw = BASE64
            .decode(v["signatures"][1]["signature"].as_str().unwrap())
            .unwrap();
        raw[50] ^= 1;
        bad["signatures"][1]["signature"] = BASE64.encode(&raw).into();
        assert_eq!(verify_strict(&bad, &st), Err(VerifyError::SignatureInvalid));
        // Truncated ML-DSA signature.
        raw.truncate(100);
        bad["signatures"][1]["signature"] = BASE64.encode(&raw).into();
        assert_eq!(
            verify_strict(&bad, &st),
            Err(VerifyError::BadSignatureEncoding)
        );
        // Flipped Ed25519 signature while the ML-DSA one is good.
        let mut bad = v.clone();
        let mut raw = BASE64
            .decode(v["signatures"][0]["signature"].as_str().unwrap())
            .unwrap();
        raw[3] ^= 1;
        bad["signatures"][0]["signature"] = BASE64.encode(&raw).into();
        assert_eq!(verify_strict(&bad, &st), Err(VerifyError::SignatureInvalid));
    }

    #[test]
    fn hybrid_downgrade_by_editing_signers_breaks_the_signature() {
        let st = hybrid_state();
        let v = hybrid_wire(&st);
        // Attacker drops the ML-DSA signer from the signed payload and the
        // signature: the Ed25519 signature no longer covers the new bytes.
        let mut p = payload_value(&v);
        p["signers"].as_array_mut().unwrap().pop();
        let mut forged = json!({
            "payload": URL_SAFE_NO_PAD.encode(serde_json::to_vec(&p).unwrap()),
            "signatures": [v["signatures"][0].clone()],
        });
        assert_eq!(
            verify_bundle_document_only(&serde_json::to_vec(&forged).unwrap(), &st.trusted(), true),
            Err(VerifyError::SignatureInvalid)
        );
        forged["signatures"] = v["signatures"].clone();
        assert_eq!(
            verify_bundle_document_only(&serde_json::to_vec(&forged).unwrap(), &st.trusted(), true),
            Err(VerifyError::UnexpectedSignature)
        );
    }

    #[test]
    fn only_the_two_profiles_are_accepted() {
        let st = hybrid_state();
        let base = payload_value(&hybrid_wire(&st));
        let ed = base["signers"][0].clone();
        let ml = base["signers"][1].clone();
        let mut cases = vec![];
        // Wrong order: signers[0] no longer matches algorithm/keyId.
        cases.push((json!([ml, ed]), VerifyError::BadSignerSet));
        cases.push((json!([ed, ml, ml]), VerifyError::BadSignerSet));
        cases.push((json!([ed, ml, ed]), VerifyError::BadSignerSet));
        for (signers, want) in cases {
            let mut p = base.clone();
            p["signers"] = signers.clone();
            assert_eq!(verify_strict(&resign(&st, &p), &st), Err(want), "{signers}");
        }
    }

    #[test]
    fn classical_bundle_is_refused_only_when_classical_is_not_allowed() {
        let st = test_state();
        let bytes = serde_json::to_vec(&wire(&st)).unwrap();
        assert!(verify_bundle_document_only(&bytes, &st.trusted(), true).is_ok());
        assert_eq!(
            verify_bundle_document_only(&bytes, &st.trusted(), false),
            Err(VerifyError::ClassicalNotAllowed)
        );
    }

    #[test]
    fn hybrid_bundle_needs_the_ml_dsa_key_to_be_trusted() {
        let st = hybrid_state();
        let bytes = serde_json::to_vec(&hybrid_wire(&st)).unwrap();
        // A verifier that only knows the Ed25519 key.
        let ed_only = test_state().trusted();
        assert_eq!(
            verify_bundle_document_only(&bytes, &ed_only, true),
            Err(VerifyError::KeyIdMismatch)
        );
        // A different ML-DSA key with the same Ed25519 key.
        let mut other = crate::integrity::test_hybrid_key(101);
        other.signing_key = st.signing_key.clone();
        other.key_id = st.key_id.clone();
        assert_eq!(
            verify_bundle_document_only(&bytes, &other.trusted(), true),
            Err(VerifyError::KeyIdMismatch)
        );
    }

    #[test]
    fn sign_domain_is_enforced_for_both_algorithms() {
        let st = hybrid_state();
        let v = hybrid_wire(&st);
        let payload = URL_SAFE_NO_PAD
            .decode(v["payload"].as_str().unwrap())
            .unwrap();
        // Signatures made for another domain (the archive one) over the same bytes.
        let mut input = crate::integrity::ARCHIVE_DOMAIN.to_vec();
        input.extend_from_slice(&payload);
        let mut replay = v.clone();
        for (i, p) in st.sign_all(&input).unwrap().into_iter().enumerate() {
            replay["signatures"][i]["signature"] = BASE64.encode(p.signature).into();
        }
        assert_eq!(
            verify_strict(&replay, &st),
            Err(VerifyError::SignatureInvalid)
        );
        // ML-DSA alone with the right domain but Ed25519 from the wrong one.
        let mut mixed = v.clone();
        mixed["signatures"][0]["signature"] = replay["signatures"][0]["signature"].clone();
        assert_eq!(
            verify_strict(&mixed, &st),
            Err(VerifyError::SignatureInvalid)
        );
        let mut mixed = v.clone();
        mixed["signatures"][1]["signature"] = replay["signatures"][1]["signature"].clone();
        assert_eq!(
            verify_strict(&mixed, &st),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn hybrid_pubkey_lists_both_keys_and_top_level_stays_ed25519() {
        let st = hybrid_state();
        let v = serde_json::to_value(pubkey_response(&st)).unwrap();
        assert_eq!(v["algorithm"], "ed25519");
        assert_eq!(v["keyId"], st.key_id.as_str());
        let keys = v["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0]["publicKey"], v["publicKey"]);
        assert_eq!(keys[1]["algorithm"], "ml-dsa-87");
        let m = st.mldsa.as_ref().unwrap();
        assert_eq!(keys[1]["keyId"], m.key_id.as_str());
        let raw = BASE64
            .decode(keys[1]["publicKey"].as_str().unwrap())
            .unwrap();
        assert_eq!(raw.len(), crypto::mldsa::PUBLIC_KEY_LEN);
        assert_eq!(signers::key_id(Algorithm::MlDsa87, &raw), m.key_id);
    }

    #[test]
    fn hybrid_sign_request_binds_both_hashes() {
        let st = hybrid_state();
        let content = BASE64.encode(b"hello");
        let (b, n) = sign_request(&st, &user(), &request(&content, Some("r1"))).unwrap();
        assert_eq!(n, 5);
        assert_eq!(b.signatures.len(), 2);
        assert!(b.signature.is_none() && b.key_id.is_none());
        assert_eq!(b.document.sha512, crypto::digest::sha512_hex(b"hello"));
        let wire = serde_json::to_vec(&b).unwrap();
        let doc = verify_bundle(
            &wire,
            &st.trusted(),
            false,
            &crypto::digest::sha256_hex(b"hello"),
        )
        .unwrap();
        assert_eq!(doc.sha512.unwrap(), crypto::digest::sha512_hex(b"hello"));
        assert_eq!(doc.signers.len(), 2);
    }

    // ── Configuration matrix ───────────────────────────────────────────────

    fn ed_hex() -> String {
        let mut s = [0u8; 32];
        crypto::rand::fill(&mut s).unwrap();
        hex::encode(s)
    }

    fn ml_b64() -> String {
        BASE64.encode(
            crypto::mldsa::SigningKey::generate()
                .unwrap()
                .to_pkcs8()
                .unwrap(),
        )
    }

    fn open_policy() -> FipsPolicy {
        FipsPolicy::from_vars(false, None).unwrap()
    }

    #[test]
    fn from_vars_matrix() {
        let (ed, ml) = (ed_hex(), ml_b64());
        let pol = open_policy();
        // Neither: disabled (blank counts as unset).
        assert!(SigningState::from_vars(None, None, None, &pol, None)
            .unwrap()
            .is_none());
        assert!(
            SigningState::from_vars(Some(" "), Some(" "), Some(""), &pol, None)
                .unwrap()
                .is_none()
        );
        // Ed25519 only: classical.
        let st = SigningState::from_vars(Some(&ed), None, None, &pol, None)
            .unwrap()
            .unwrap();
        assert_eq!(st.profile(), Profile::Classical);
        assert!(!st.require_hybrid);
        // Both: hybrid.
        let st = SigningState::from_vars(Some(&ed), Some(&ml), Some("true"), &pol, None)
            .unwrap()
            .unwrap();
        assert_eq!(st.profile(), Profile::Hybrid);
        assert!(st.require_hybrid);
        assert_eq!(st.signers().len(), 2);
        assert_eq!(st.key_ids().len(), 2);
        // ML-DSA only, malformed, or require_hybrid without both: errors.
        assert!(SigningState::from_vars(None, Some(&ml), None, &pol, None).is_err());
        assert!(
            SigningState::from_vars(Some(&ed), Some("!!!not base64"), None, &pol, None).is_err()
        );
        assert!(SigningState::from_vars(
            Some(&ed),
            Some(&BASE64.encode(b"garbage")),
            None,
            &pol,
            None
        )
        .is_err());
        assert!(SigningState::from_vars(Some(&ed), None, Some("1"), &pol, None).is_err());
        assert!(SigningState::from_vars(None, None, Some("true"), &pol, None).is_err());
        assert!(SigningState::from_vars(Some(&ed), Some(&ml), Some("maybe"), &pol, None).is_err());
    }

    #[test]
    fn from_vars_errors_do_not_echo_key_material() {
        let ed = ed_hex();
        let bad = format!("{}A", ml_b64());
        let e = SigningState::from_vars(Some(&ed), Some(&bad), None, &open_policy(), None)
            .unwrap_err()
            .to_string();
        assert!(!e.contains(&bad[..40]), "{e}");
    }

    #[test]
    fn ml_dsa_in_an_enforced_policy_needs_the_pending_alg_listed() {
        let (ed, ml) = (ed_hex(), ml_b64());
        let enforced = FipsPolicy::from_vars(true, None).unwrap();
        let err = SigningState::from_vars(Some(&ed), Some(&ml), None, &enforced, None).unwrap_err();
        assert!(err.to_string().contains("ML-DSA-87"), "{err}");
        let listed = FipsPolicy::from_vars(true, Some("ML-DSA-87")).unwrap();
        assert!(SigningState::from_vars(Some(&ed), Some(&ml), None, &listed, None).is_ok());
        // Ed25519-only is unaffected by the pending list.
        assert!(SigningState::from_vars(Some(&ed), None, None, &enforced, None).is_ok());
    }

    // ── Key rotation: previous keys (#68) ───────────────────────────────────

    fn prev_entry(label: &str, st: &SigningState) -> Value {
        let r = serde_json::to_value(pubkey_response(st)).unwrap();
        json!({"label": label, "retiredAt": "2026-11-30", "keys": r["keys"]})
    }

    fn prev_bytes(entries: Vec<Value>, revoked: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({"version": 1, "previous": entries, "revoked": revoked})).unwrap()
    }

    fn load(
        ed: &str,
        ml: Option<&str>,
        require_hybrid: Option<&str>,
        policy: &FipsPolicy,
        prev: Option<Vec<u8>>,
    ) -> anyhow::Result<Option<SigningState>> {
        SigningState::from_vars(
            Some(ed),
            ml,
            require_hybrid,
            policy,
            prev.as_deref().map(|b| (b, "file")),
        )
    }

    /// A server on new keys trusting `old` as previous key sets.
    fn rotated_server(old: &[&SigningState]) -> SigningState {
        crate::integrity::with_previous(
            crate::integrity::test_hybrid_key(121),
            crate::integrity::test_previous(old),
        )
    }

    #[test]
    fn previous_keys_need_the_current_signing_key() {
        let old = crate::integrity::test_hybrid_key(120);
        let doc = prev_bytes(vec![prev_entry("old", &old)], vec![]);
        let e = SigningState::from_vars(None, None, None, &open_policy(), Some((&doc, "file")))
            .unwrap_err();
        assert!(e.to_string().contains(ED25519_KEY_ENV), "{e}");
        // No previous keys and no signing key still starts cleanly.
        assert!(
            SigningState::from_vars(None, None, None, &open_policy(), None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn previous_keys_load_and_are_verify_only() {
        let old = crate::integrity::test_hybrid_key(120);
        let doc = prev_bytes(vec![prev_entry("old", &old)], vec![]);
        let st = load(&ed_hex(), None, None, &open_policy(), Some(doc.clone()))
            .unwrap()
            .unwrap();
        // The current server is still classical and signs with its own key only.
        assert_eq!(st.profile(), Profile::Classical);
        assert_eq!(st.signers().len(), 1);
        assert_eq!(st.previous.sets.len(), 1);
        assert_eq!(st.previous.source, "file");
        assert!(st.trusted().resolve(&old.signers()).is_some());
        let produced = st.sign_all(b"x").unwrap();
        assert!(produced.iter().all(|p| p.key_id == st.key_id));
        // A bundle signed by the old hybrid keys verifies on the new server.
        let wire = serde_json::to_vec(&vector_bundle(&old)).unwrap();
        assert!(verify_bundle_document_only(&wire, &st.trusted(), false).is_ok());
        // Malformed documents are startup errors.
        assert!(load(&ed_hex(), None, None, &open_policy(), Some(b"{}".to_vec())).is_err());
    }

    #[test]
    fn hybrid_previous_sets_need_the_ml_dsa_pending_alg_in_a_fips_policy() {
        let old = crate::integrity::test_hybrid_key(120);
        let hybrid_doc = prev_bytes(vec![prev_entry("old", &old)], vec![]);
        let classical_doc = prev_bytes(
            vec![prev_entry("old", &crate::integrity::test_key(120))],
            vec![],
        );
        let enforced = FipsPolicy::from_vars(true, None).unwrap();
        let listed = FipsPolicy::from_vars(true, Some("ML-DSA-87")).unwrap();
        let ed = ed_hex();
        let e = load(&ed, None, None, &enforced, Some(hybrid_doc.clone())).unwrap_err();
        assert!(e.to_string().contains("ML-DSA-87"), "{e}");
        assert!(load(&ed, None, None, &listed, Some(hybrid_doc)).is_ok());
        assert!(load(&ed, None, None, &enforced, Some(classical_doc)).is_ok());
    }

    #[test]
    fn entries_equal_to_the_current_keys_are_dropped_and_a_revoked_current_key_is_an_error() {
        let (ed, ml) = (ed_hex(), ml_b64());
        let pol = open_policy();
        let cur = load(&ed, Some(&ml), None, &pol, None).unwrap().unwrap();
        let classical_cur = load(&ed, None, None, &pol, None).unwrap().unwrap();
        let doc = prev_bytes(
            vec![
                prev_entry("same-hybrid", &cur),
                prev_entry("same-classical", &classical_cur),
            ],
            vec![],
        );
        let st = load(&ed, Some(&ml), None, &pol, Some(doc))
            .unwrap()
            .unwrap();
        assert!(st.previous.sets.is_empty());
        assert_eq!(st.previous.ignored, ["same-hybrid", "same-classical"]);
        // Revoking a key that is in use is refused.
        let revoked = json!({"algorithm": "ed25519", "keyId": cur.key_id});
        let doc = prev_bytes(vec![], vec![revoked]);
        assert!(load(&ed, Some(&ml), None, &pol, Some(doc)).is_err());
        let revoked =
            json!({"algorithm": "ml-dsa-87", "keyId": cur.mldsa.as_ref().unwrap().key_id});
        let doc = prev_bytes(vec![], vec![revoked]);
        assert!(load(&ed, Some(&ml), None, &pol, Some(doc)).is_err());
    }

    #[test]
    fn a_classical_previous_set_loads_under_require_hybrid() {
        let doc = prev_bytes(
            vec![prev_entry("old", &crate::integrity::test_key(120))],
            vec![],
        );
        let st = load(
            &ed_hex(),
            Some(&ml_b64()),
            Some("true"),
            &open_policy(),
            Some(doc),
        )
        .unwrap()
        .unwrap();
        assert!(st.require_hybrid);
        assert_eq!(st.previous.sets.len(), 1);
        assert_eq!(st.previous.sets[0].profile, Profile::Classical);
    }

    #[test]
    fn the_previous_keys_carriers_are_exclusive_and_bounded() {
        assert!(read_previous_keys(None, None).unwrap().is_none());
        assert!(read_previous_keys(Some(" "), Some("")).unwrap().is_none());
        assert!(read_previous_keys(Some("/x"), Some("{}")).is_err());
        let (b, src) = read_previous_keys(None, Some(r#"{"version":1}"#))
            .unwrap()
            .unwrap();
        assert_eq!((b.as_slice(), src), (br#"{"version":1}"#.as_slice(), "env"));
        let big = "x".repeat(MAX_PREVIOUS_KEYS_BYTES + 1);
        assert!(read_previous_keys(None, Some(&big)).is_err());

        let mut name = [0u8; 8];
        crypto::rand::fill(&mut name).unwrap();
        let path = std::env::temp_dir().join(format!("stig-prev-keys-{}", hex::encode(name)));
        std::fs::write(&path, br#"{"version":1}"#).unwrap();
        let p = path.to_str().unwrap();
        let (b, src) = read_previous_keys(Some(p), None).unwrap().unwrap();
        assert_eq!(
            (b.as_slice(), src),
            (br#"{"version":1}"#.as_slice(), "file")
        );
        std::fs::write(&path, vec![b' '; MAX_PREVIOUS_KEYS_BYTES + 1]).unwrap();
        assert!(read_previous_keys(Some(p), None).is_err());
        std::fs::remove_file(&path).unwrap();
        let e = read_previous_keys(Some(p), None).unwrap_err().to_string();
        assert!(!e.contains(p), "{e}");
    }

    #[test]
    fn bundles_signed_by_previous_sets_verify_with_the_right_source() {
        let (old_hybrid, old_classical) = (
            crate::integrity::test_hybrid_key(120),
            crate::integrity::test_key(122),
        );
        let cur = rotated_server(&[&old_hybrid, &old_classical]);
        let trusted = cur.trusted();
        let wire = |st: &SigningState| serde_json::to_vec(&vector_bundle(st)).unwrap();
        let sha = crypto::digest::sha256_hex(VECTOR_ARTIFACT);

        let (_, src) =
            verify_bundle_with_source(&wire(&old_hybrid), &trusted, false, &sha).unwrap();
        assert_eq!(src, KeySource::Previous);
        let (_, src) = verify_bundle_with_source(&wire(&cur), &trusted, false, &sha).unwrap();
        assert_eq!(src, KeySource::Current);
        // The previous classical bundle needs allow_classical.
        assert_eq!(
            verify_bundle(&wire(&old_classical), &trusted, false, &sha),
            Err(VerifyError::ClassicalNotAllowed)
        );
        let (_, src) =
            verify_bundle_with_source(&wire(&old_classical), &trusted, true, &sha).unwrap();
        assert_eq!(src, KeySource::Previous);
        // The old hybrid pair's Ed25519 key alone (no classical entry): refused.
        assert_eq!(
            verify_bundle(
                &wire(&crate::integrity::test_key(120)),
                &trusted,
                true,
                &sha
            ),
            Err(VerifyError::KeyIdMismatch)
        );
        // Halves of two generations.
        let mut mixed = crate::integrity::test_key(120);
        mixed.mldsa = cur.mldsa.clone();
        assert_eq!(
            verify_bundle(&wire(&mixed), &trusted, false, &sha),
            Err(VerifyError::KeyIdMismatch)
        );
        // Entry removed.
        let gone = rotated_server(&[]);
        assert_eq!(
            verify_bundle(&wire(&old_hybrid), &gone.trusted(), false, &sha),
            Err(VerifyError::KeyIdMismatch)
        );
        // Revoked.
        let revoked = signers::PreviousKeys {
            revoked: vec![signers::RevokedKey {
                algorithm: Algorithm::Ed25519,
                key_id: old_hybrid.key_id.clone(),
                revoked_at: None,
                reason: None,
            }],
            ..Default::default()
        };
        let cur = crate::integrity::with_previous(crate::integrity::test_hybrid_key(121), revoked);
        assert_eq!(
            verify_bundle(&wire(&old_hybrid), &cur.trusted(), false, &sha),
            Err(VerifyError::KeyRevoked)
        );
    }

    #[test]
    fn a_previous_key_sharing_a_current_key_id_with_another_public_key_is_refused() {
        let cur =
            TrustedKeys::from_ed25519(&crate::integrity::test_key(130).signing_key.public_key());
        let same = cur.sets()[0].keys[0].clone();
        let set = |k: VerifyingKey| {
            signers::KeySet::new(vec![k], KeySource::Previous, Some("x".into())).unwrap()
        };
        assert!(check_no_key_id_collision(&cur, &[set(same.clone())]).is_ok());
        let forged = VerifyingKey {
            public_key: vec![9; 32],
            ..same
        };
        let e = check_no_key_id_collision(&cur, &[set(forged)]).unwrap_err();
        assert!(e.to_string().contains("keyId"), "{e}");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_pubkey_endpoint_serves_the_cached_response(pool: sqlx::PgPool) {
        use axum::response::IntoResponse;
        let (mut state, _dir) = crate::test_fixtures::app_state(pool);
        let old = crate::integrity::test_hybrid_key(120);
        let cur = rotated_server(&[&old]);
        state.signing = Some(cur.clone());
        let want = serde_json::to_vec(&pubkey_response(&cur)).unwrap();
        for _ in 0..2 {
            let resp = pubkey_handler(State(state.clone()))
                .await
                .unwrap()
                .into_response();
            assert_eq!(resp.headers()["content-type"], "application/json");
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(body.as_ref(), want.as_slice());
        }
    }

    #[test]
    fn pubkey_lists_previous_sets_only_when_configured() {
        let none = serde_json::to_value(pubkey_response(&hybrid_state())).unwrap();
        assert!(none.get("previousKeys").is_none());
        let old = crate::integrity::test_hybrid_key(120);
        let cur = rotated_server(&[&old, &crate::integrity::test_key(122)]);
        let v = serde_json::to_value(pubkey_response(&cur)).unwrap();
        // Current keys are unchanged.
        assert_eq!(v["keyId"], cur.key_id.as_str());
        assert_eq!(v["keys"].as_array().unwrap().len(), 2);
        let prev = v["previousKeys"].as_array().unwrap();
        assert_eq!(prev.len(), 2);
        assert_eq!(prev[0]["label"], "old-0");
        assert_eq!(prev[0]["retiredAt"], "2026-01-01");
        assert_eq!(prev[0]["keys"], keys_json(&old));
        assert_eq!(prev[1]["keys"].as_array().unwrap().len(), 1);
        // Public data only: no seed or private key material appears.
        let text = v.to_string();
        assert!(
            !text.contains("privateKey") && !text.contains("seed"),
            "{text}"
        );
    }

    #[test]
    fn the_startup_event_detail_names_key_ids_and_the_config_hash_only() {
        let old = crate::integrity::test_hybrid_key(120);
        let mut prev = crate::integrity::test_previous(&[&old]);
        prev.source = "env";
        prev.sha384 = "ab".repeat(48);
        prev.revoked.push(signers::RevokedKey {
            algorithm: Algorithm::Ed25519,
            key_id: "0123456789abcdef".into(),
            revoked_at: Some("2026-12-01".into()),
            reason: Some("seed exposed".into()),
        });
        let cur = crate::integrity::with_previous(crate::integrity::test_hybrid_key(121), prev);
        let d = signing_keys_detail(&cur);
        assert_eq!(d["profile"], "hybrid");
        assert_eq!(d["requireHybrid"], false);
        assert_eq!(d["currentKeyIds"], json!(cur.key_ids()));
        assert_eq!(d["previous"][0]["label"], "old-0");
        assert_eq!(d["previous"][0]["profile"], "hybrid");
        assert_eq!(d["previous"][0]["keyIds"], json!(old.key_ids()));
        assert_eq!(d["revoked"][0]["reason"], "seed exposed");
        assert_eq!(d["previousKeysSource"], "env");
        assert_eq!(d["previousKeysSha384"], "ab".repeat(48));
        // Without a previous-keys document.
        let d = signing_keys_detail(&test_state());
        assert_eq!(d["previousKeysSource"], "none");
        assert!(d["previousKeysSha384"].is_null());
        assert_eq!(d["previous"], json!([]));
    }

    // ── Cross-implementation test vector (#69) ─────────────────────────────

    const VECTOR_LABEL: &str = "TEST VECTOR ONLY: public keys and signatures; the private keys were generated at runtime and discarded. Never trust these keys.";
    const VECTOR_ARTIFACT: &[u8] = b"TEST VECTOR ONLY artifact\n";

    fn keys_json(st: &SigningState) -> Value {
        serde_json::to_value(pubkey_response(st).keys).unwrap()
    }

    fn verifying_key(k: &Value) -> VerifyingKey {
        let algorithm = Algorithm::from_wire(k["algorithm"].as_str().unwrap()).unwrap();
        let public_key = BASE64.decode(k["publicKey"].as_str().unwrap()).unwrap();
        let key_id = k["keyId"].as_str().unwrap().to_string();
        assert_eq!(key_id, signers::key_id(algorithm, &public_key));
        VerifyingKey {
            algorithm,
            key_id,
            public_key,
        }
    }

    fn verifying_keys(v: &Value) -> Vec<VerifyingKey> {
        v.as_array().unwrap().iter().map(verifying_key).collect()
    }

    /// Trust the `keys` array of a pubkey response as the current keys.
    fn trusted_from(v: &Value) -> TrustedKeys {
        trusted_with(v, &json!([]), &json!([]))
    }

    /// Current keys (a pubkey response's `keys`), previous sets (its
    /// `previousKeys`) and a revoked list, the way an independent verifier
    /// pins them.
    fn trusted_with(current: &Value, previous: &Value, revoked: &Value) -> TrustedKeys {
        let keys = verifying_keys(current);
        let ed = keys
            .iter()
            .find(|k| k.algorithm == Algorithm::Ed25519)
            .cloned()
            .unwrap();
        let ml = keys
            .iter()
            .find(|k| k.algorithm == Algorithm::MlDsa87)
            .cloned();
        let mut sets = signers::current_sets(ed, ml);
        for p in previous.as_array().unwrap() {
            let mut set = signers::KeySet::new(
                verifying_keys(&p["keys"]),
                KeySource::Previous,
                Some(p["label"].as_str().unwrap().to_string()),
            )
            .unwrap();
            set.retired_at = p["retiredAt"].as_str().map(str::to_string);
            sets.push(set);
        }
        let revoked = revoked
            .as_array()
            .unwrap()
            .iter()
            .map(|r| signers::RevokedKey {
                algorithm: Algorithm::from_wire(r["algorithm"].as_str().unwrap()).unwrap(),
                key_id: r["keyId"].as_str().unwrap().to_string(),
                revoked_at: None,
                reason: None,
            })
            .collect();
        TrustedKeys::from_sets(sets, revoked)
    }

    fn variant(e: &VerifyError) -> String {
        format!("{e:?}")
            .split('(')
            .next()
            .unwrap_or_default()
            .to_string()
    }

    /// Verify one vector entry the way an independent verifier would.
    fn check_entry(
        bundle: &Value,
        trusted: &Value,
        artifact: &[u8],
        allow_classical: bool,
    ) -> Result<VerifiedDocument, VerifyError> {
        verify_bundle(
            &serde_json::to_vec(bundle).unwrap(),
            &trusted_from(trusted),
            allow_classical,
            &crypto::digest::sha256_hex(artifact),
        )
    }

    fn vector_bundle(st: &SigningState) -> Value {
        let content = BASE64.encode(VECTOR_ARTIFACT);
        let (b, _) = sign_request(st, &user(), &request(&content, Some("vector"))).unwrap();
        serde_json::to_value(b).unwrap()
    }

    fn mutate_sig(v: &mut Value, idx: usize, byte: usize) {
        let mut raw = BASE64
            .decode(v["signatures"][idx]["signature"].as_str().unwrap())
            .unwrap();
        raw[byte] ^= 1;
        v["signatures"][idx]["signature"] = BASE64.encode(raw).into();
    }

    fn build_vector() -> Value {
        let st = hybrid_state();
        let classical = test_state();
        let good = vector_bundle(&st);
        let ed_only_keys = json!([keys_json(&st)[0].clone()]);
        let case = |name: &str, bundle: Value, expect: &str| json!({"name": name, "bundle": bundle, "expect": expect});
        let mut negative = vec![];

        let mut b = good.clone();
        b["signatures"].as_array_mut().unwrap().remove(1);
        negative.push(case("strip_ml_dsa_signature", b, "MissingSignature"));
        let mut b = good.clone();
        b["signatures"].as_array_mut().unwrap().remove(0);
        negative.push(case("strip_ed25519_signature", b, "MissingSignature"));
        let mut b = good.clone();
        mutate_sig(&mut b, 1, 100);
        negative.push(case("flip_ml_dsa_signature_byte", b, "SignatureInvalid"));
        let mut b = good.clone();
        mutate_sig(&mut b, 0, 3);
        negative.push(case("flip_ed25519_signature_byte", b, "SignatureInvalid"));
        let mut b = good.clone();
        let (x, y) = (
            good["signatures"][0]["signature"].clone(),
            good["signatures"][1]["signature"].clone(),
        );
        b["signatures"][0]["signature"] = y;
        b["signatures"][1]["signature"] = x;
        negative.push(case("swap_signatures", b, "BadSignatureEncoding"));
        let mut b = good.clone();
        let dup = good["signatures"][1].clone();
        b["signatures"].as_array_mut().unwrap().push(dup);
        negative.push(case("duplicate_ml_dsa_signature", b, "UnexpectedSignature"));
        let mut b = good.clone();
        b["signatures"].as_array_mut().unwrap().push(json!({
            "algorithm": "ml-dsa-65", "keyId": "00", "signature": "AAAA"
        }));
        negative.push(case("unlisted_extra_signature", b, "UnexpectedSignature"));

        // Edited payload (signedBy), same signatures.
        let mut p = payload_value(&good);
        p["signedBy"] = "attacker".into();
        let mut b = good.clone();
        b["payload"] = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&p).unwrap())
            .into();
        negative.push(case("edited_payload", b, "SignatureInvalid"));
        // Downgrade: ML-DSA signer and signature removed, signers edited.
        let mut p = payload_value(&good);
        p["signers"].as_array_mut().unwrap().pop();
        let mut b = good.clone();
        b["payload"] = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&p).unwrap())
            .into();
        b["signatures"].as_array_mut().unwrap().pop();
        negative.push(case("downgrade_to_classical", b, "ClassicalNotAllowed"));
        // Signatures over another domain (archive), valid for the right payload.
        let payload = URL_SAFE_NO_PAD
            .decode(good["payload"].as_str().unwrap())
            .unwrap();
        let mut input = crate::integrity::ARCHIVE_DOMAIN.to_vec();
        input.extend_from_slice(&payload);
        let mut b = good.clone();
        for (i, p) in st.sign_all(&input).unwrap().into_iter().enumerate() {
            b["signatures"][i]["signature"] = BASE64.encode(p.signature).into();
        }
        negative.push(case("wrong_domain", b, "SignatureInvalid"));
        // Not an envelope (pre-#50 shape).
        negative.push(case(
            "legacy_without_payload",
            json!({"document": {"algorithm": "ed25519"}, "signature": "x", "keyId": "y"}),
            "MalformedEnvelope",
        ));
        // Verifier that does not trust the ML-DSA key.
        let mut c = case("ml_dsa_key_not_trusted", good.clone(), "KeyIdMismatch");
        c["trustedKeys"] = ed_only_keys;
        negative.push(c);
        // Right bundle, different artifact.
        let mut c = case("wrong_artifact", good.clone(), "ArtifactHashMismatch");
        c["artifactBase64"] = BASE64.encode(b"something else").into();
        negative.push(c);
        // A genuine classical bundle where classical is not acceptable.
        negative.push(case(
            "classical_bundle_not_allowed",
            vector_bundle(&classical),
            "ClassicalNotAllowed",
        ));

        let rotation = build_rotation();
        json!({
            "label": VECTOR_LABEL,
            "format": 1,
            "domain": "stig-viewer/sign/v2 followed by a NUL byte, then the decoded payload bytes",
            "generator": "backend (aws-lc-rs ML-DSA-87 and Ed25519)",
            "trustedKeys": keys_json(&st),
            "artifactBase64": BASE64.encode(VECTOR_ARTIFACT),
            "bundle": good,
            "classical": {
                "trustedKeys": json!([keys_json(&st)[0].clone()]),
                "bundle": vector_bundle(&classical),
            },
            "negative": negative,
            "rotation": rotation,
        })
    }

    /// Key rotation (#68) cases: a server on new keys that still trusts one
    /// previous hybrid set and one previous classical set. Runtime keys only.
    fn build_rotation() -> Value {
        let old_hybrid = crate::integrity::test_hybrid_key(110);
        let old_classical = test_key_n(111);
        let current = crate::integrity::with_previous(
            crate::integrity::test_hybrid_key(112),
            crate::integrity::test_previous(&[&old_hybrid, &old_classical]),
        );
        let resp = serde_json::to_value(pubkey_response(&current)).unwrap();
        let (trusted, previous) = (resp["keys"].clone(), resp["previousKeys"].clone());
        let positive = vec![
            json!({"name": "previous_hybrid_set", "bundle": vector_bundle(&old_hybrid),
                   "allowClassical": false, "expectSource": "previous", "expectLabel": "old-0"}),
            json!({"name": "previous_classical_set", "bundle": vector_bundle(&old_classical),
                   "allowClassical": true, "expectSource": "previous", "expectLabel": "old-1"}),
            json!({"name": "current_hybrid_set", "bundle": vector_bundle(&current),
                   "allowClassical": false, "expectSource": "current"}),
        ];
        let case = |name: &str, bundle: Value, expect: &str| json!({"name": name, "bundle": bundle, "expect": expect});
        let mut negative = vec![];
        // Previous classical set without allowClassical.
        negative.push(case(
            "previous_classical_not_allowed",
            vector_bundle(&old_classical),
            "ClassicalNotAllowed",
        ));
        // Ed25519 half of the previous hybrid pair + the current ML-DSA key, both
        // validly signed: two generations never combine.
        let mut mixed = test_key_n(110);
        mixed.mldsa = current.mldsa.clone();
        let mut c = case(
            "mixed_generation_halves",
            vector_bundle(&mixed),
            "KeyIdMismatch",
        );
        c["allowClassical"] = true.into();
        negative.push(c);
        // The previous hybrid pair's Ed25519 key alone is not a classical signer.
        let mut c = case(
            "previous_hybrid_half_as_classical",
            vector_bundle(&test_key_n(110)),
            "KeyIdMismatch",
        );
        c["allowClassical"] = true.into();
        negative.push(c);
        // Entry removed from the previous list.
        let mut c = case(
            "previous_set_removed",
            vector_bundle(&old_hybrid),
            "KeyIdMismatch",
        );
        c["previousKeySets"] = json!([]);
        negative.push(c);
        // Revoked key (and not listed as previous).
        let mut c = case(
            "previous_key_revoked",
            vector_bundle(&old_classical),
            "KeyRevoked",
        );
        c["previousKeySets"] = json!([previous[0].clone()]);
        c["revoked"] = json!([{"algorithm": "ed25519", "keyId": old_classical.key_id}]);
        c["allowClassical"] = true.into();
        negative.push(c);
        // A bad signature under a previous key is still an error.
        let mut b = vector_bundle(&old_hybrid);
        mutate_sig(&mut b, 1, 100);
        negative.push(case("previous_key_bad_signature", b, "SignatureInvalid"));
        json!({
            "trustedKeys": trusted,
            "previousKeySets": previous,
            "positive": positive,
            "negative": negative,
        })
    }

    /// Classical state for `n` (the same Ed25519 key as the hybrid state `n`).
    fn test_key_n(n: u8) -> SigningState {
        crate::integrity::test_key(n)
    }

    /// `STIG_WRITE_TEST_VECTOR=<path>` writes a fresh vector with runtime keys
    /// (used by CI to cross-check against `scripts/verify-bundle.mjs`). Not
    /// `#[ignore]`: that marker means "needs Postgres" in this crate.
    #[test]
    fn write_test_vector_when_requested() {
        let Some(path) = std::env::var_os("STIG_WRITE_TEST_VECTOR") else {
            return;
        };
        let v = build_vector();
        std::fs::write(path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    }

    #[test]
    fn a_fresh_vector_verifies_and_every_negative_fails_as_labelled() {
        verify_vector(&build_vector());
    }

    #[test]
    fn the_downgrade_vector_case_fails_on_the_signature_when_classical_is_allowed() {
        let v = build_vector();
        let n = v["negative"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["name"] == "downgrade_to_classical")
            .unwrap();
        let artifact = BASE64
            .decode(v["artifactBase64"].as_str().unwrap())
            .unwrap();
        let err = check_entry(&n["bundle"], &v["trustedKeys"], &artifact, true).unwrap_err();
        assert_eq!(err, VerifyError::SignatureInvalid);
    }

    fn verify_vector(v: &Value) {
        assert!(v["label"].as_str().unwrap().starts_with("TEST VECTOR ONLY"));
        let artifact = BASE64
            .decode(v["artifactBase64"].as_str().unwrap())
            .unwrap();
        let doc = check_entry(&v["bundle"], &v["trustedKeys"], &artifact, false).unwrap();
        assert_eq!(doc.signers.len(), 2);
        assert_eq!(doc.sha512, Some(crypto::digest::sha512_hex(&artifact)));
        let c = &v["classical"];
        assert!(check_entry(&c["bundle"], &c["trustedKeys"], &artifact, true).is_ok());
        for n in v["negative"].as_array().unwrap() {
            let keys = n.get("trustedKeys").unwrap_or(&v["trustedKeys"]);
            let art = n
                .get("artifactBase64")
                .map(|a| BASE64.decode(a.as_str().unwrap()).unwrap())
                .unwrap_or_else(|| artifact.clone());
            let err = check_entry(&n["bundle"], keys, &art, false).unwrap_err();
            assert_eq!(
                variant(&err),
                n["expect"].as_str().unwrap(),
                "{}",
                n["name"]
            );
        }
        if let Some(r) = v.get("rotation") {
            verify_rotation(r, &artifact);
        }
        // Signed by another implementation (node:crypto / OpenSSL), if present.
        if let Some(f) = v.get("foreign") {
            let art = BASE64
                .decode(f["artifactBase64"].as_str().unwrap())
                .unwrap();
            let doc = check_entry(&f["bundle"], &f["trustedKeys"], &art, false).unwrap();
            assert_eq!(doc.signers.len(), 2);
        }
    }

    fn verify_rotation(r: &Value, artifact: &[u8]) {
        let sha = crypto::digest::sha256_hex(artifact);
        let none = json!([]);
        for p in r["positive"].as_array().unwrap() {
            let trusted = trusted_with(&r["trustedKeys"], &r["previousKeySets"], &none);
            let (_, source) = verify_bundle_with_source(
                &serde_json::to_vec(&p["bundle"]).unwrap(),
                &trusted,
                p["allowClassical"].as_bool().unwrap(),
                &sha,
            )
            .unwrap_or_else(|e| panic!("{}: {e}", p["name"]));
            assert_eq!(
                source.as_str(),
                p["expectSource"].as_str().unwrap(),
                "{}",
                p["name"]
            );
        }
        for n in r["negative"].as_array().unwrap() {
            let trusted = trusted_with(
                &r["trustedKeys"],
                n.get("previousKeySets").unwrap_or(&r["previousKeySets"]),
                n.get("revoked").unwrap_or(&none),
            );
            let err = verify_bundle(
                &serde_json::to_vec(&n["bundle"]).unwrap(),
                &trusted,
                n.get("allowClassical")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                &sha,
            )
            .unwrap_err();
            assert_eq!(
                variant(&err),
                n["expect"].as_str().unwrap(),
                "{}",
                n["name"]
            );
        }
    }

    #[test]
    fn the_checked_in_vector_verifies_including_the_openssl_signed_bundle() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../testdata/signing/v2-hybrid-bundle.json");
        let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(
            v.get("foreign").is_some(),
            "run scripts/make-foreign-vector.mjs on the vector"
        );
        verify_vector(&v);
    }

    #[test]
    fn startup_errors_through_a_real_policy_match_from_env_inputs() {
        // `from_env` only reads the three variables and calls `from_vars`
        // with the startup policy, so this exercises it without touching the
        // process environment.
        let ed = ed_hex();
        let policy = FipsPolicy::from_vars(true, None).unwrap();
        let e = SigningState::from_vars(Some(&ed), None, Some("true"), &policy, None).unwrap_err();
        assert!(e.to_string().contains(REQUIRE_HYBRID_ENV), "{e}");
        let e =
            SigningState::from_vars(Some(&ed), Some(&ml_b64()), None, &policy, None).unwrap_err();
        assert!(e.to_string().contains("ML-DSA-87"), "{e}");
    }

    // ── Audit rows (#151) ──────────────────────────────────────────────────

    async fn sign(
        pool: &sqlx::PgPool,
        resource: Option<&str>,
    ) -> Result<Json<SignedBundle>, (StatusCode, String)> {
        let (mut state, _dir) = crate::test_fixtures::app_state(pool.clone());
        state.signing = Some(test_state());
        sign_handler(
            State(state),
            Extension(crate::test_fixtures::auth("u1", "author")),
            Extension(crate::test_fixtures::ctx()),
            Json(request(&BASE64.encode(b"hello"), resource)),
        )
        .await
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn startup_records_the_trusted_key_sets_in_a_system_event(pool: sqlx::PgPool) {
        let old = crate::integrity::test_hybrid_key(120);
        let cur = rotated_server(&[&old]);
        record_signing_keys_event(&pool, &cur).await;
        let rows = crate::test_fixtures::audit_rows(&pool, SIGNING_KEYS_ACTION).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outcome, "ok");
        assert_eq!(rows[0].detail["currentKeyIds"], json!(cur.key_ids()));
        assert_eq!(
            rows[0].detail["previous"][0]["keyIds"],
            json!(old.key_ids())
        );
        assert_eq!(rows[0].detail["previous"][0]["label"], "old-0");
        let text: String = sqlx::query_scalar(
            "SELECT detail::text FROM audit_events WHERE action = 'system.signing_keys'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!text.contains("publicKey"), "{text}");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn signing_sign_is_recorded_with_hash_and_key_but_not_the_resource_text(
        pool: sqlx::PgPool,
    ) {
        crate::test_fixtures::seed_user(&pool, "u1").await;
        let free_text = "customer secret label";
        let Json(bundle) = sign(&pool, Some(free_text)).await.unwrap();
        let rows = crate::test_fixtures::audit_rows(&pool, "signing.sign").await;
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.outcome, "ok");
        assert_eq!(r.user_id.as_deref(), Some("u1"));
        assert_eq!(r.stig_id, None, "free text is not a STIG id");
        assert_eq!(
            r.detail_keys(),
            [
                "algorithms",
                "bytes",
                "keyId",
                "keyIds",
                "profile",
                "resourcePresent",
                "sha256",
                "version"
            ]
        );
        assert_eq!(r.detail["sha256"], bundle.document.sha256.as_str());
        assert_eq!(r.detail["keyId"], test_state().key_id.as_str());
        assert_eq!(r.detail["bytes"], 5);
        assert_eq!(r.detail["resourcePresent"], true);
        assert_eq!(r.request_id.as_deref(), Some("test-request"));
        assert_eq!(r.source_ip.as_deref(), Some("198.51.100.4"));
        let text: String = sqlx::query_scalar(
            "SELECT detail::text FROM audit_events WHERE action = 'signing.sign'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!text.contains(free_text), "{text}");

        // A STIG-shaped resource lands in the stig_id column.
        let _ = sign(&pool, Some("TEST-STIG")).await.unwrap();
        let rows = crate::test_fixtures::audit_rows(&pool, "signing.sign").await;
        assert_eq!(rows[1].stig_id.as_deref(), Some("TEST-STIG"));
        // No resource: resourcePresent is false.
        let _ = sign(&pool, None).await.unwrap();
        let rows = crate::test_fixtures::audit_rows(&pool, "signing.sign").await;
        assert_eq!(rows[2].detail["resourcePresent"], false);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_hybrid_sign_records_the_profile_and_both_key_ids(pool: sqlx::PgPool) {
        crate::test_fixtures::seed_user(&pool, "u1").await;
        let (mut state, _dir) = crate::test_fixtures::app_state(pool.clone());
        let st = hybrid_state();
        state.signing = Some(st.clone());
        let Json(bundle) = sign_handler(
            State(state),
            Extension(crate::test_fixtures::auth("u1", "author")),
            Extension(crate::test_fixtures::ctx()),
            Json(request(&BASE64.encode(b"hello"), None)),
        )
        .await
        .unwrap();
        assert_eq!(bundle.signatures.len(), 2);
        let rows = crate::test_fixtures::audit_rows(&pool, "signing.sign").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].detail["profile"], "hybrid");
        assert_eq!(rows[0].detail["algorithms"], "ed25519,ml-dsa-87");
        assert_eq!(rows[0].detail["keyIds"], json!(st.key_ids()));
        let text: String = sqlx::query_scalar(
            "SELECT detail::text FROM audit_events WHERE action = 'signing.sign'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!text.contains(&bundle.payload) && !text.contains(&bundle.signatures[1].signature));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn signing_sign_fails_closed_and_returns_no_bundle_when_the_row_cannot_be_written(
        pool: sqlx::PgPool,
    ) {
        crate::test_fixtures::seed_user(&pool, "u1").await;
        crate::test_fixtures::fail_audit_inserts(&pool, &["signing.sign"]).await;
        let res = sign(&pool, None).await;
        let Err((code, msg)) = res else {
            panic!("a signature must not be released without its record");
        };
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(msg, "signing unavailable");
        assert!(crate::test_fixtures::audit_rows(&pool, "signing.sign")
            .await
            .is_empty());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn refused_sign_requests_write_no_audit_row(pool: sqlx::PgPool) {
        crate::test_fixtures::seed_user(&pool, "u1").await;
        let bad = sign_with(&pool, "***").await;
        assert_eq!(bad.err().map(|e| e.0), Some(StatusCode::BAD_REQUEST));
        let empty = sign_with(&pool, "").await;
        assert_eq!(empty.err().map(|e| e.0), Some(StatusCode::BAD_REQUEST));
        // No key configured.
        let (state, _dir) = crate::test_fixtures::app_state(pool.clone());
        let off = sign_handler(
            State(state),
            Extension(crate::test_fixtures::auth("u1", "author")),
            Extension(crate::test_fixtures::ctx()),
            Json(request(&BASE64.encode(b"hello"), None)),
        )
        .await;
        assert_eq!(
            off.err().map(|e| e.0),
            Some(StatusCode::SERVICE_UNAVAILABLE)
        );
        assert!(crate::test_fixtures::audit_rows(&pool, "signing.sign")
            .await
            .is_empty());
    }

    async fn sign_with(
        pool: &sqlx::PgPool,
        content: &str,
    ) -> Result<Json<SignedBundle>, (StatusCode, String)> {
        let (mut state, _dir) = crate::test_fixtures::app_state(pool.clone());
        state.signing = Some(test_state());
        sign_handler(
            State(state),
            Extension(crate::test_fixtures::auth("u1", "author")),
            Extension(crate::test_fixtures::ctx()),
            Json(request(content, None)),
        )
        .await
    }
}
