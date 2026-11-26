//! Signer identities, key ids and the accepted signer profiles, shared by the
//! `/api/sign` bundle verifier (`api::signing`) and the archive/backup
//! verifier (`integrity`).
//!
//! A signed signer set is a *profile*: `[ed25519]` (classical) or
//! `[ed25519, ml-dsa-87]` (hybrid, in that order). Any other set is rejected,
//! and every listed signer must verify (AND semantics), so stripping the
//! ML-DSA signature from a hybrid artifact cannot downgrade it unless the
//! signed signer list is also rewritten (which needs an Ed25519 forgery).
//!
//! Key rotation (#68): trust is per key *set*, not per key. The verifier
//! resolves an artifact's signed signer list to exactly one trusted
//! [`KeySet`] (the current keys, or a retired set from the previous-keys
//! configuration, see [`parse_previous`]); the halves of two generations never
//! combine and a previous hybrid half never verifies as a classical signer.
//! Previous keys are public keys only and cannot sign.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::crypto;

/// Wire name of the Ed25519 algorithm.
pub const ED25519: &str = "ed25519";
/// Wire name of the ML-DSA-87 algorithm.
pub const ML_DSA_87: &str = "ml-dsa-87";

/// One entry of a signed signer list.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct SignerId {
    pub algorithm: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Ed25519,
    MlDsa87,
}

impl Algorithm {
    pub fn wire(self) -> &'static str {
        match self {
            Self::Ed25519 => ED25519,
            Self::MlDsa87 => ML_DSA_87,
        }
    }

    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            ED25519 => Some(Self::Ed25519),
            ML_DSA_87 => Some(Self::MlDsa87),
            _ => None,
        }
    }
}

/// Key id: Ed25519 is the first 8 bytes of SHA-256 over the raw public key
/// (16 hex); ML-DSA-87 is the first 16 bytes of
/// SHA-384(`"ml-dsa-87" || 0x00 || raw public key`) (32 hex).
pub fn key_id(alg: Algorithm, public: &[u8]) -> String {
    match alg {
        Algorithm::Ed25519 => hex::encode(&crypto::digest::sha256(public)[..8]),
        Algorithm::MlDsa87 => {
            let mut input = Vec::with_capacity(ML_DSA_87.len() + 1 + public.len());
            input.extend_from_slice(ML_DSA_87.as_bytes());
            input.push(0);
            input.extend_from_slice(public);
            hex::encode(&crypto::digest::sha384(&input)[..16])
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Ed25519 only.
    Classical,
    /// Ed25519 and ML-DSA-87.
    Hybrid,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Classical => "classical",
            Self::Hybrid => "hybrid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassifyError {
    /// A signer names an algorithm this build cannot verify.
    UnsupportedAlgorithm(String),
    /// Not exactly `[ed25519]` or `[ed25519, ml-dsa-87]`.
    BadSet,
}

/// Map a signed signer list's algorithms to a profile.
///
/// The accepted sets are deliberately fixed. Key rotation (#68) does not add
/// profiles: it adds more trusted key sets ([`KeySet`]) of these same two
/// profiles. A future profile (ML-DSA only, SLH-DSA) must be added here
/// explicitly, together with its tests. Relaxing this to "any set of
/// supported algorithms" would open a downgrade path: an attacker who can
/// forge one supported signature could drop the others from the signer list. Unknown algorithms are
/// rejected, never skipped.
pub fn classify<'a>(
    algorithms: impl IntoIterator<Item = &'a str>,
) -> Result<Profile, ClassifyError> {
    let mut algs = Vec::new();
    for a in algorithms {
        match Algorithm::from_wire(a) {
            Some(alg) => algs.push(alg),
            None => return Err(ClassifyError::UnsupportedAlgorithm(a.to_string())),
        }
    }
    match algs.as_slice() {
        [Algorithm::Ed25519] => Ok(Profile::Classical),
        [Algorithm::Ed25519, Algorithm::MlDsa87] => Ok(Profile::Hybrid),
        _ => Err(ClassifyError::BadSet),
    }
}

/// A public key a verifier holds. There is no private half anywhere in this
/// module: previous keys (#68) can verify and can never sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    pub algorithm: Algorithm,
    pub key_id: String,
    /// Raw public key bytes.
    pub public_key: Vec<u8>,
}

/// Where a trusted key set comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// The key(s) this server signs with.
    Current,
    /// A retired key set listed in the previous-keys configuration.
    Previous,
}

impl KeySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Previous => "previous",
        }
    }
}

/// One trusted signer set: the keys of exactly one profile, bound together.
/// An artifact verifies against a set only when its signed signer list equals
/// the set's `(algorithm, keyId)` list, in order, so halves of two key
/// generations never combine and a hybrid half never verifies as classical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySet {
    pub keys: Vec<VerifyingKey>,
    pub profile: Profile,
    pub source: KeySource,
    pub label: Option<String>,
    pub retired_at: Option<String>,
}

impl KeySet {
    /// `keys` must be `[ed25519]` or `[ed25519, ml-dsa-87]` (see [`classify`]).
    pub fn new(
        keys: Vec<VerifyingKey>,
        source: KeySource,
        label: Option<String>,
    ) -> Result<Self, ClassifyError> {
        let profile = classify(keys.iter().map(|k| k.algorithm.wire()))?;
        Ok(Self {
            keys,
            profile,
            source,
            label,
            retired_at: None,
        })
    }

    pub fn signer_ids(&self) -> Vec<SignerId> {
        self.keys
            .iter()
            .map(|k| SignerId {
                algorithm: k.algorithm.wire().into(),
                key_id: k.key_id.clone(),
            })
            .collect()
    }

    pub fn key_ids(&self) -> Vec<String> {
        self.keys.iter().map(|k| k.key_id.clone()).collect()
    }

    fn matches(&self, signers: &[SignerId]) -> bool {
        self.keys.len() == signers.len()
            && self
                .keys
                .iter()
                .zip(signers)
                .all(|(k, s)| k.algorithm.wire() == s.algorithm && k.key_id == s.key_id)
    }
}

/// The sets a server with these current keys always trusts: the classical set
/// `[ed25519]` (so a classical artifact still verifies after hybrid signing is
/// enabled) and, when an ML-DSA-87 key is configured, the hybrid set.
pub fn current_sets(ed25519: VerifyingKey, ml_dsa: Option<VerifyingKey>) -> Vec<KeySet> {
    let mut out: Vec<KeySet> = KeySet::new(vec![ed25519.clone()], KeySource::Current, None)
        .into_iter()
        .collect();
    if let Some(ml) = ml_dsa {
        out.extend(KeySet::new(vec![ed25519, ml], KeySource::Current, None));
    }
    out
}

/// A key the operator declared compromised or withdrawn. Informational beyond
/// the id: an artifact signed by it is never `Verified`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedKey {
    pub algorithm: Algorithm,
    pub key_id: String,
    pub revoked_at: Option<String>,
    pub reason: Option<String>,
}

/// Key sets a verifier trusts. A signer list is resolved to one set by exact
/// match ([`Self::resolve`]); [`Self::find`] is only the id lookup used to pick
/// the public key for a signature check and never decides trust on its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedKeys {
    sets: Vec<KeySet>,
    revoked: Vec<RevokedKey>,
}

impl TrustedKeys {
    pub fn from_sets(sets: Vec<KeySet>, revoked: Vec<RevokedKey>) -> Self {
        Self { sets, revoked }
    }

    /// One current classical set holding `public`.
    pub fn from_ed25519(public: &[u8; 32]) -> Self {
        let keys = vec![VerifyingKey {
            algorithm: Algorithm::Ed25519,
            key_id: key_id(Algorithm::Ed25519, public),
            public_key: public.to_vec(),
        }];
        Self {
            sets: KeySet::new(keys, KeySource::Current, None)
                .into_iter()
                .collect(),
            revoked: Vec::new(),
        }
    }

    pub fn sets(&self) -> &[KeySet] {
        &self.sets
    }

    /// The set whose `(algorithm, keyId)` list equals `signers` exactly (same
    /// entries, same order), if any.
    pub fn resolve(&self, signers: &[SignerId]) -> Option<&KeySet> {
        self.sets.iter().find(|s| s.matches(signers))
    }

    /// Flat lookup by `(algorithm, keyId)` across every set.
    pub fn find(&self, alg: Algorithm, key_id: &str) -> Option<&VerifyingKey> {
        self.sets
            .iter()
            .flat_map(|s| s.keys.iter())
            .find(|k| k.algorithm == alg && k.key_id == key_id)
    }

    pub fn revoked(&self, alg: Algorithm, key_id: &str) -> Option<&RevokedKey> {
        self.revoked
            .iter()
            .find(|r| r.algorithm == alg && r.key_id == key_id)
    }
}

// ── Previous-keys configuration (#68) ───────────────────────────────────────

/// Upper bounds on the operator-supplied document.
pub const MAX_PREVIOUS_SETS: usize = 32;
pub const MAX_REVOKED_KEYS: usize = 64;
pub const MAX_PREVIOUS_BYTES: usize = 1 << 20;
const MAX_REASON_CHARS: usize = 200;
const ED25519_PUBLIC_LEN: usize = 32;

/// Parsed, validated previous-keys configuration. Holds public keys only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreviousKeys {
    pub sets: Vec<KeySet>,
    pub revoked: Vec<RevokedKey>,
    /// Where the document came from: `"file"` or `"env"`; `"none"` when empty.
    pub source: &'static str,
    /// Lowercase hex SHA-384 of the document bytes, so a trust change shows up
    /// in the startup audit event.
    pub sha384: String,
    /// Labels of entries dropped because they equal the current keys.
    pub ignored: Vec<String>,
}

impl PreviousKeys {
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty() && self.revoked.is_empty()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreviousFile {
    version: u32,
    #[serde(default)]
    previous: Vec<PreviousEntry>,
    #[serde(default)]
    revoked: Vec<RevokedEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreviousEntry {
    label: String,
    #[serde(default)]
    retired_at: Option<String>,
    keys: Vec<KeyEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyEntry {
    algorithm: String,
    key_id: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevokedEntry {
    algorithm: String,
    key_id: String,
    #[serde(default)]
    revoked_at: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

fn valid_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_date(s: &str) -> bool {
    s.len() == 10 && chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
}

fn valid_key_id(alg: Algorithm, s: &str) -> bool {
    let want = match alg {
        Algorithm::Ed25519 => 16,
        Algorithm::MlDsa87 => 32,
    };
    s.len() == want && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parse the document and check its version and size bounds.
fn parse_file(json: &[u8]) -> anyhow::Result<PreviousFile> {
    use anyhow::bail;
    if json.len() > MAX_PREVIOUS_BYTES {
        bail!("previous-keys document exceeds {MAX_PREVIOUS_BYTES} bytes");
    }
    // serde_json's own messages can quote the offending value, so only the
    // position is reported.
    let file: PreviousFile = serde_json::from_slice(json).map_err(|e| {
        anyhow::anyhow!(
            "previous-keys document is invalid (line {}, column {}, {:?})",
            e.line(),
            e.column(),
            e.classify()
        )
    })?;
    if file.version != 1 {
        bail!("previous-keys document: unsupported version (expected 1)");
    }
    if file.previous.len() > MAX_PREVIOUS_SETS {
        bail!("previous-keys document: more than {MAX_PREVIOUS_SETS} previous key sets");
    }
    if file.revoked.len() > MAX_REVOKED_KEYS {
        bail!("previous-keys document: more than {MAX_REVOKED_KEYS} revoked keys");
    }
    Ok(file)
}

/// Validate one `keys[j]` entry of a previous set; `at` names the set.
fn parse_key_entry(at: &str, j: usize, k: &KeyEntry) -> anyhow::Result<VerifyingKey> {
    use anyhow::bail;
    let Some(alg) = Algorithm::from_wire(&k.algorithm) else {
        bail!("{at}: keys[{j}] has an unsupported algorithm");
    };
    if !valid_key_id(alg, &k.key_id) {
        bail!("{at}: keys[{j}] keyId is not lowercase hex of the expected length");
    }
    let public = BASE64
        .decode(k.public_key.trim().as_bytes())
        .map_err(|_| anyhow::anyhow!("{at}: keys[{j}] publicKey is not valid base64"))?;
    let want = match alg {
        Algorithm::Ed25519 => ED25519_PUBLIC_LEN,
        Algorithm::MlDsa87 => crypto::mldsa::PUBLIC_KEY_LEN,
    };
    if public.len() != want {
        bail!(
            "{at}: keys[{j}] publicKey has the wrong length for {}",
            k.algorithm
        );
    }
    if key_id(alg, &public) != k.key_id {
        bail!("{at}: keys[{j}] keyId does not match publicKey (is a private key pasted here?)");
    }
    Ok(VerifyingKey {
        algorithm: alg,
        key_id: k.key_id.clone(),
        public_key: public,
    })
}

/// Validate one `previous[i]` entry against the sets accepted before it.
fn parse_set(i: usize, entry: &PreviousEntry, earlier: &[KeySet]) -> anyhow::Result<KeySet> {
    use anyhow::bail;
    let at = format!("previous[{i}] ({})", entry.label.escape_default());
    if !valid_label(&entry.label) {
        bail!("previous[{i}]: label must match [A-Za-z0-9._-]{{1,64}}");
    }
    if earlier
        .iter()
        .any(|s| s.label.as_deref() == Some(&entry.label))
    {
        bail!("{at}: duplicate label");
    }
    if entry.retired_at.as_deref().is_some_and(|d| !valid_date(d)) {
        bail!("{at}: retiredAt must be YYYY-MM-DD");
    }
    if entry.keys.is_empty() || entry.keys.len() > 2 {
        bail!("{at}: keys must be [ed25519] or [ed25519, ml-dsa-87]");
    }
    let keys = entry
        .keys
        .iter()
        .enumerate()
        .map(|(j, k)| parse_key_entry(&at, j, k))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut set =
        KeySet::new(keys, KeySource::Previous, Some(entry.label.clone())).map_err(|_| {
            anyhow::anyhow!("{at}: keys must be [ed25519] or [ed25519, ml-dsa-87], in that order")
        })?;
    set.retired_at = entry.retired_at.clone();
    if earlier.iter().any(|s| s.signer_ids() == set.signer_ids()) {
        bail!("{at}: duplicate key set");
    }
    Ok(set)
}

/// One (algorithm, keyId) must always mean one public key.
fn check_key_id_collisions(sets: &[KeySet]) -> anyhow::Result<()> {
    let all: Vec<&VerifyingKey> = sets.iter().flat_map(|s| s.keys.iter()).collect();
    for (a, ka) in all.iter().enumerate() {
        if all[a + 1..].iter().any(|kb| {
            kb.algorithm == ka.algorithm && kb.key_id == ka.key_id && kb.public_key != ka.public_key
        }) {
            anyhow::bail!("two different public keys share one keyId");
        }
    }
    Ok(())
}

/// Validate one `revoked[i]` entry against the previous sets and the revoked
/// entries accepted before it.
fn parse_revoked(
    i: usize,
    r: &RevokedEntry,
    sets: &[KeySet],
    earlier: &[RevokedKey],
) -> anyhow::Result<RevokedKey> {
    use anyhow::bail;
    let at = format!("revoked[{i}]");
    let Some(alg) = Algorithm::from_wire(&r.algorithm) else {
        bail!("{at}: unsupported algorithm");
    };
    if !valid_key_id(alg, &r.key_id) {
        bail!("{at}: keyId is not lowercase hex of the expected length");
    }
    if r.revoked_at.as_deref().is_some_and(|d| !valid_date(d)) {
        bail!("{at}: revokedAt must be YYYY-MM-DD");
    }
    if r.reason
        .as_deref()
        .is_some_and(|x| x.chars().count() > MAX_REASON_CHARS || x.chars().any(char::is_control))
    {
        bail!(
            "{at}: reason must be at most {MAX_REASON_CHARS} characters without control characters"
        );
    }
    if sets.iter().any(|s| {
        s.keys
            .iter()
            .any(|k| k.algorithm == alg && k.key_id == r.key_id)
    }) {
        bail!("{at}: a revoked key is also listed in previous");
    }
    if earlier
        .iter()
        .any(|o| o.algorithm == alg && o.key_id == r.key_id)
    {
        bail!("{at}: duplicate revoked key");
    }
    Ok(RevokedKey {
        algorithm: alg,
        key_id: r.key_id.clone(),
        revoked_at: r.revoked_at.clone(),
        reason: r.reason.clone(),
    })
}

/// Parse and validate the previous-keys document (schema version 1). Every
/// rejection is a startup error. Messages name the entry (index and label) and
/// never echo a value from the document: an entry may hold a mis-pasted seed.
pub fn parse_previous(json: &[u8], source: &'static str) -> anyhow::Result<PreviousKeys> {
    let file = parse_file(json)?;
    let mut sets: Vec<KeySet> = Vec::new();
    for (i, entry) in file.previous.iter().enumerate() {
        let set = parse_set(i, entry, &sets)?;
        sets.push(set);
    }
    check_key_id_collisions(&sets)?;
    let mut revoked: Vec<RevokedKey> = Vec::new();
    for (i, r) in file.revoked.iter().enumerate() {
        let k = parse_revoked(i, r, &sets, &revoked)?;
        revoked.push(k);
    }
    Ok(PreviousKeys {
        sets,
        revoked,
        source,
        sha384: hex::encode(crypto::digest::sha384(json)),
        ignored: Vec::new(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigError {
    BadLength,
    Invalid,
}

/// Verify one signature of either algorithm over `input` (domain || payload).
pub fn verify_sig(alg: Algorithm, public: &[u8], input: &[u8], sig: &[u8]) -> Result<(), SigError> {
    match alg {
        Algorithm::Ed25519 => {
            let pk: &[u8; 32] = public.try_into().map_err(|_| SigError::Invalid)?;
            crypto::ed25519::verify(pk, input, sig).map_err(|e| match e {
                crypto::ed25519::VerifyError::BadLength => SigError::BadLength,
                crypto::ed25519::VerifyError::Invalid => SigError::Invalid,
            })
        }
        Algorithm::MlDsa87 => crypto::mldsa::verify(public, input, sig).map_err(|e| match e {
            crypto::mldsa::VerifyError::BadLength => SigError::BadLength,
            crypto::mldsa::VerifyError::Invalid => SigError::Invalid,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_accepts_only_the_two_profiles() {
        assert_eq!(classify([ED25519]), Ok(Profile::Classical));
        assert_eq!(classify([ED25519, ML_DSA_87]), Ok(Profile::Hybrid));
        for bad in [
            vec![],
            vec![ML_DSA_87],
            vec![ML_DSA_87, ED25519],
            vec![ED25519, ED25519],
            vec![ED25519, ML_DSA_87, ML_DSA_87],
            vec![ED25519, ML_DSA_87, ED25519],
        ] {
            assert_eq!(classify(bad.clone()), Err(ClassifyError::BadSet), "{bad:?}");
        }
        assert_eq!(
            classify([ED25519, "ml-dsa-65"]),
            Err(ClassifyError::UnsupportedAlgorithm("ml-dsa-65".into()))
        );
    }

    #[test]
    fn key_ids_have_the_documented_shape_and_differ_by_algorithm() {
        let pk = [7u8; 32];
        let ed = key_id(Algorithm::Ed25519, &pk);
        assert_eq!(ed.len(), 16);
        assert_eq!(ed, hex::encode(&crypto::digest::sha256(&pk)[..8]));
        let ml = key_id(Algorithm::MlDsa87, &pk);
        assert_eq!(ml.len(), 32);
        let mut input = b"ml-dsa-87\0".to_vec();
        input.extend_from_slice(&pk);
        assert_eq!(ml, hex::encode(&crypto::digest::sha384(&input)[..16]));
    }

    #[test]
    fn trusted_lookup_is_by_algorithm_and_key_id() {
        let pk = [9u8; 32];
        let t = TrustedKeys::from_ed25519(&pk);
        let id = key_id(Algorithm::Ed25519, &pk);
        assert!(t.find(Algorithm::Ed25519, &id).is_some());
        assert!(t.find(Algorithm::MlDsa87, &id).is_none());
        assert!(t.find(Algorithm::Ed25519, "nope").is_none());
    }

    // ── Key sets and previous keys (#68) ───────────────────────────────────

    use serde_json::{json, Value};

    fn ed_key() -> VerifyingKey {
        let mut seed = [0u8; 32];
        crypto::rand::fill(&mut seed).unwrap();
        let public = crypto::ed25519::SigningKey::from_seed(&seed)
            .unwrap()
            .public_key()
            .to_vec();
        VerifyingKey {
            algorithm: Algorithm::Ed25519,
            key_id: key_id(Algorithm::Ed25519, &public),
            public_key: public,
        }
    }

    fn ml_key() -> VerifyingKey {
        let public = crypto::mldsa::SigningKey::generate().unwrap().public_key();
        VerifyingKey {
            algorithm: Algorithm::MlDsa87,
            key_id: key_id(Algorithm::MlDsa87, &public),
            public_key: public,
        }
    }

    fn key_json(k: &VerifyingKey) -> Value {
        json!({
            "algorithm": k.algorithm.wire(),
            "keyId": k.key_id,
            "publicKey": BASE64.encode(&k.public_key),
        })
    }

    fn entry(label: &str, keys: &[&VerifyingKey]) -> Value {
        json!({"label": label, "retiredAt": "2026-11-30",
               "keys": keys.iter().map(|k| key_json(k)).collect::<Vec<_>>()})
    }

    fn doc(previous: Vec<Value>, revoked: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({"version": 1, "previous": previous, "revoked": revoked}))
            .unwrap()
    }

    fn ids(keys: &[&VerifyingKey]) -> Vec<SignerId> {
        keys.iter()
            .map(|k| SignerId {
                algorithm: k.algorithm.wire().into(),
                key_id: k.key_id.clone(),
            })
            .collect()
    }

    fn set(keys: Vec<VerifyingKey>) -> KeySet {
        KeySet::new(keys, KeySource::Current, None).unwrap()
    }

    #[test]
    fn resolve_requires_the_exact_ordered_signer_list_of_one_set() {
        let (ed_a, ml_a) = (ed_key(), ml_key());
        let (ed_b, ml_b) = (ed_key(), ml_key());
        let t = TrustedKeys::from_sets(
            vec![
                set(vec![ed_a.clone()]),
                set(vec![ed_a.clone(), ml_a.clone()]),
                set(vec![ed_b.clone(), ml_b.clone()]),
            ],
            vec![],
        );
        assert_eq!(
            t.resolve(&ids(&[&ed_a])).unwrap().profile,
            Profile::Classical
        );
        assert_eq!(
            t.resolve(&ids(&[&ed_a, &ml_a])).unwrap().profile,
            Profile::Hybrid
        );
        assert!(t.resolve(&ids(&[&ed_b, &ml_b])).is_some());
        // Halves of two generations, a lone half of a hybrid pair, wrong order,
        // an extra signer and the empty list never resolve.
        assert!(t.resolve(&ids(&[&ed_a, &ml_b])).is_none());
        assert!(t.resolve(&ids(&[&ed_b, &ml_a])).is_none());
        assert!(t.resolve(&ids(&[&ed_b])).is_none());
        assert!(t.resolve(&ids(&[&ml_a, &ed_a])).is_none());
        assert!(t.resolve(&ids(&[&ed_a, &ml_a, &ml_a])).is_none());
        assert!(t.resolve(&[]).is_none());
        // `find` stays a flat id lookup across every set.
        assert!(t.find(Algorithm::Ed25519, &ed_b.key_id).is_some());
        assert!(t.find(Algorithm::MlDsa87, &ml_b.key_id).is_some());
        assert!(t.find(Algorithm::Ed25519, &ml_b.key_id).is_none());
    }

    #[test]
    fn parse_previous_accepts_both_profiles_and_records_the_document_hash() {
        let (ed_a, ml_a, ed_c) = (ed_key(), ml_key(), ed_key());
        let bytes = doc(
            vec![
                entry("prod-2026a", &[&ed_a, &ml_a]),
                entry("prod-classic", &[&ed_c]),
            ],
            vec![json!({"algorithm": "ed25519", "keyId": "0123456789abcdef",
                        "revokedAt": "2026-12-01", "reason": "seed exposed"})],
        );
        let p = parse_previous(&bytes, "file").unwrap();
        assert_eq!(p.sets.len(), 2);
        assert_eq!(p.sets[0].profile, Profile::Hybrid);
        assert_eq!(p.sets[0].label.as_deref(), Some("prod-2026a"));
        assert_eq!(p.sets[0].retired_at.as_deref(), Some("2026-11-30"));
        assert_eq!(p.sets[0].source, KeySource::Previous);
        assert_eq!(p.sets[1].profile, Profile::Classical);
        assert_eq!(p.revoked.len(), 1);
        assert_eq!(p.source, "file");
        assert_eq!(p.sha384, hex::encode(crypto::digest::sha384(&bytes)));
        // Nothing about a hybrid entry implies a classical one.
        let t = TrustedKeys::from_sets(p.sets.clone(), p.revoked.clone());
        assert!(t.resolve(&ids(&[&ed_a])).is_none());
        assert!(t.resolve(&ids(&[&ed_c])).is_some());
        // An empty list is a valid document.
        let empty = parse_previous(br#"{"version":1}"#, "env").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn parse_previous_rejects_each_malformed_document() {
        let (ed_a, ml_a, ed_b) = (ed_key(), ml_key(), ed_key());
        let ok = entry("a", &[&ed_a, &ml_a]);
        let bad = |bytes: Vec<u8>| parse_previous(&bytes, "file").unwrap_err().to_string();
        let one = |e: Value| bad(doc(vec![e], vec![]));

        assert!(parse_previous(b"not json", "file").is_err());
        assert!(parse_previous(br#"{"version":1,"extra":1}"#, "file").is_err());
        assert!(parse_previous(br#"{"version":2}"#, "file").is_err());
        assert!(parse_previous(br#"{"previous":[]}"#, "file").is_err());
        // Unknown field inside an entry and inside a key.
        let mut e = ok.clone();
        e["privateKey"] = "x".into();
        assert!(one(e).contains("invalid"));
        let mut e = ok.clone();
        e["keys"][0]["seed"] = "x".into();
        assert!(one(e).contains("invalid"));
        // Bad base64, wrong length, keyId mismatch.
        let mut e = ok.clone();
        e["keys"][0]["publicKey"] = "!!!".into();
        assert!(one(e).contains("base64"));
        let mut e = ok.clone();
        e["keys"][0]["publicKey"] = BASE64.encode([1u8; 31]).into();
        assert!(one(e).contains("length"));
        let mut e = ok.clone();
        e["keys"][1]["publicKey"] = BASE64.encode([1u8; 100]).into();
        assert!(one(e).contains("length"));
        let mut e = ok.clone();
        e["keys"][0]["keyId"] = ed_b.key_id.clone().into();
        assert!(one(e).contains("does not match"));
        let mut e = ok.clone();
        e["keys"][0]["keyId"] = "ABCDEF".into();
        assert!(one(e).contains("keyId"));
        // Profile: ML-DSA only, wrong order, three keys, none, unknown algorithm.
        assert!(one(entry("a", &[&ml_a])).contains("ed25519"));
        assert!(one(entry("a", &[&ml_a, &ed_a])).contains("ed25519"));
        assert!(one(entry("a", &[&ed_a, &ed_b])).contains("ed25519"));
        assert!(one(entry("a", &[&ed_a, &ml_a, &ml_a])).contains("keys must be"));
        assert!(one(entry("a", &[])).contains("keys must be"));
        let mut e = ok.clone();
        e["keys"][1]["algorithm"] = "ml-dsa-65".into();
        assert!(one(e).contains("unsupported"));
        // Duplicates.
        assert!(
            bad(doc(vec![ok.clone(), entry("b", &[&ed_a, &ml_a])], vec![]))
                .contains("duplicate key set")
        );
        assert!(
            bad(doc(vec![ok.clone(), entry("a", &[&ed_b])], vec![])).contains("duplicate label")
        );
        // Label and dates.
        for l in ["", "has space", "x/y", &"a".repeat(65)] {
            assert!(one(entry(l, &[&ed_a])).contains("label"), "{l:?}");
        }
        let mut e = ok.clone();
        e["retiredAt"] = "2026-13-01".into();
        assert!(one(e).contains("retiredAt"));
        let mut e = ok.clone();
        e["retiredAt"] = "20261101".into();
        assert!(one(e).contains("retiredAt"));
        // Bounds.
        let many: Vec<Value> = (0..=MAX_PREVIOUS_SETS)
            .map(|i| entry(&format!("s{i}"), &[&ed_a]))
            .collect();
        assert!(bad(doc(many, vec![])).contains("more than"));
        let rev = |id: &str| json!({"algorithm": "ed25519", "keyId": id});
        let many: Vec<Value> = (0..=MAX_REVOKED_KEYS)
            .map(|i| rev(&format!("{i:016x}")))
            .collect();
        assert!(bad(doc(vec![], many)).contains("more than"));
        assert!(parse_previous(&vec![b' '; MAX_PREVIOUS_BYTES + 1], "file").is_err());
        // Revoked: bad id, bad date, long or control-character reason, overlap, duplicate.
        assert!(bad(doc(vec![], vec![rev("zz")])).contains("keyId"));
        let mut r = rev("0123456789abcdef");
        r["revokedAt"] = "yesterday".into();
        assert!(bad(doc(vec![], vec![r])).contains("revokedAt"));
        let mut r = rev("0123456789abcdef");
        r["reason"] = "x".repeat(201).into();
        assert!(bad(doc(vec![], vec![r])).contains("reason"));
        let mut r = rev("0123456789abcdef");
        r["reason"] = "line\nbreak".into();
        assert!(bad(doc(vec![], vec![r])).contains("reason"));
        assert!(
            bad(doc(vec![entry("a", &[&ed_a])], vec![rev(&ed_a.key_id)])).contains("also listed")
        );
        assert!(bad(doc(
            vec![],
            vec![rev("0123456789abcdef"), rev("0123456789abcdef")]
        ))
        .contains("duplicate"));
    }

    #[test]
    fn parse_previous_errors_never_echo_a_pasted_private_seed() {
        // A 32-byte seed has the length of an Ed25519 public key; the id check
        // must catch it and the message must not contain it.
        let mut seed = [0u8; 32];
        crypto::rand::fill(&mut seed).unwrap();
        let seed_b64 = BASE64.encode(seed);
        let seed_hex = hex::encode(seed);
        // The real public key's id with the seed pasted as the key.
        let real = ed_key();
        let bytes = doc(
            vec![json!({"label": "oops", "keys": [{
                "algorithm": "ed25519",
                "keyId": real.key_id,
                "publicKey": seed_b64,
            }]})],
            vec![],
        );
        let e = parse_previous(&bytes, "file").unwrap_err().to_string();
        assert!(e.contains("does not match"), "{e}");
        assert!(!e.contains(&seed_b64) && !e.contains(&seed_hex), "{e}");
        // A syntax error quotes no value either.
        let e = parse_previous(format!(r#"{{"version": "{seed_b64}"}}"#).as_bytes(), "file")
            .unwrap_err()
            .to_string();
        assert!(!e.contains(&seed_b64), "{e}");
    }
}
