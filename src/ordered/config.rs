// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configuration and the hooks the application supplies.
//!
//! Values come from two places. The application protocol fixes what both
//! sides have to agree on ([`AppProtocolProfile`], MLS-TLS "Parameters"),
//! and the two sides agree on the protocol in the handshake. Everything
//! else is local ([`EngineConfig`]).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use zeroize::Zeroizing;

use super::buf::TAG_LEN;
use super::wire::MAX_PLAINTEXT;

/// The binding a session uses. Fixed when the session is created. A session
/// never moves to the other binding, so changing transport means a new
/// session (D3). A device may hold one session per binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Binding {
    /// The ordered binding over TCP (MLS-TLS).
    Stream,
    /// The unordered binding over UDP. Waits for MLS-DTLS.
    Datagram,
}

/// The cipher suites of a session. Provisioned, never negotiated: the
/// initiator knows the server's suites in advance (profile "Negotiation").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionSuite {
    /// One MLS group.
    Single(u16),
    /// The amortized PQ combiner (profile "Use with the amortized PQ
    /// combiner"): a T group with a traditional suite and a PQ group with a
    /// post-quantum one. Record keys and the binding's values come from the
    /// T group. Provisioning this variant returns [`ConfigError::UnsupportedApq`].
    Apq { t: u16, pq: u16, mode: ApqMode },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ApqMode {
    /// The PQ group's KEM is post-quantum, its signatures are not.
    Confidentiality,
    /// The PQ group also signs with a post-quantum signature algorithm.
    ConfidentialityAndAuthenticity,
}

pub struct EngineConfig {
    /// This side's signing keys. The first set signs new sessions. More can
    /// be added during a key rollover, see [`crate::Engine::add_signer`].
    pub signers: Vec<SignerSet>,
    /// Application protocols this side speaks, in order of preference.
    pub app_protocols: Vec<AppProtocolProfile>,
    /// Responder: the pre-handshake configurations it offers.
    pub pre_handshake: ServerPreHandshake,
    pub limits: Limits,
    pub timeouts: LocalTimeouts,
    pub padding: PaddingPolicy,
    /// How often the engine writes its last-alive time, and with it the
    /// start of every interruption since the previous write. Restore
    /// counts an interruption with no stored start from the last write
    /// before the crash, so the error shortens a session's time bound by at
    /// most this interval and never lengthens it.
    pub last_alive_interval: Duration,
}

/// The signing keys of this side for one credential.
pub struct SignerSet {
    /// Signs in the session's group, the T group with APQ.
    pub signer: Arc<dyn Signer>,
    /// Signs in the PQ group of an APQ session. Required when the PQ
    /// suite's signature scheme differs from `signer`'s, as in
    /// [`ApqMode::ConfidentialityAndAuthenticity`].
    pub pq_signer: Option<Arc<dyn Signer>>,
}

/// Bounds on work and state before the peer is authenticated.
pub struct Limits {
    /// First messages the engine works on at once, counted from the moment
    /// a ClientStart or a ClientHello without pre-handshake is complete. An
    /// hpke ClientStart costs a decapsulation before the server can tell
    /// whether it is valid, so it counts. A ClientStart in the session mode
    /// costs one or two AEAD operations and doesn't count. Beyond the limit
    /// a new first message is refused with
    /// [`crate::InterruptCause::Overloaded`].
    pub max_pending_handshakes: usize,
    /// Candidate connections a responder keeps per session.
    pub max_candidates_per_session: usize,
}

/// Times that only this side needs to know.
pub struct LocalTimeouts {
    /// How long the engine waits for [`crate::Engine::authorize`]. Shorter
    /// than the protocol's `commit_confirmation`, which the engine checks.
    /// For a staged Commit, no answer in time interrupts the connection and
    /// discards the Commit (profile "Invalid messages and fatal errors").
    pub authorization: Duration,
    /// A responder connection that sends no complete first message.
    pub first_message: Duration,
}

/// What a client knows about a server, from provisioning.
pub struct ServerProvisioning {
    pub suite: SessionSuite,
    pub pre_handshake: ClientPreHandshake,
}

/// How a client protects its ClientHello (MLS-TLS "Pre-handshake").
/// Reconnects always use the session mode, which needs no configuration.
/// A client configured for a mode never falls back to another one or to no
/// pre-handshake after a failed attempt.
pub enum ClientPreHandshake {
    /// The serialized PreHandshakeConfigs of the server's hpke mode. The
    /// client picks one.
    Hpke(Vec<Vec<u8>>),
    /// A psk configuration and the deployment's key. Everyone who holds
    /// the key can read ClientHellos sent under it.
    Psk { config: Vec<u8>, psk: Secret },
    /// The credential is visible to every observer.
    None,
}

/// The pre-handshake configurations a server offers. Several at once
/// during a rotation, told apart by `config_id`.
pub struct ServerPreHandshake {
    pub configs: Vec<ServerPreHandshakeConfig>,
    /// Whether a ClientHello without pre-handshake is accepted.
    pub accept_clear: bool,
}

pub enum ServerPreHandshakeConfig {
    Hpke {
        config_id: u8,
        kem_id: u16,
        public_key: Vec<u8>,
        private_key: Secret,
        /// (KDF, AEAD) pairs.
        cipher_suites: Vec<(u16, u16)>,
    },
    Psk {
        config_id: u8,
        cipher_suite: (u16, u16),
        psk: Secret,
    },
}

/// Key material. Zeroized on drop, no `Debug`, no `Clone`.
pub struct Secret {
    _bytes: Zeroizing<Vec<u8>>,
}

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            _bytes: Zeroizing::new(bytes),
        }
    }
}

pub enum PaddingPolicy {
    None,
    /// Pad protected record plaintext to this size when the content fits.
    AllTo(usize),
}

/// An application protocol identifier, from the ALPN registry or private.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AppProtocol(pub Vec<u8>);

/// An application protocol and its shared deployment parameters.
pub struct AppProtocolProfile {
    pub id: AppProtocol,
    pub early_data: EarlyData,
    pub times: ProtocolTimes,
    pub rekey: RekeyPolicy,
    pub liveness: Liveness,
}

/// The times the profile and MLS-TLS leave to the application protocol.
/// Sessions are meant to last, and starting a new one loses security, so
/// the session bounds are long.
pub struct ProtocolTimes {
    /// How long a session may stay interrupted before the initiator deletes
    /// it. The time starts once and only adoption stops it (profile
    /// "Reconnection").
    pub initiator_session_bound: Duration,
    /// The responder's interruption bound. Provision it to cover the
    /// initiator's detection and retry budget.
    pub responder_session_bound: Duration,
    /// How long a responder keeps the reset state of a deleted session.
    pub reset_state_lifetime: Duration,
    /// Initiator: ClientHello to ServerHello.
    pub initiator_handshake: Duration,
    /// Responder: ServerHello to the confirmation of epoch 1.
    pub responder_handshake: Duration,
    /// A Commit neither confirmed nor dropped interrupts its connection.
    pub commit_confirmation: Duration,
    /// A Reconnect answered by neither a Challenge nor a Reset.
    pub reconnect_answer: Duration,
    /// A ChallengeResponse answered by no Adopted.
    pub adopted: Duration,
    /// A candidate connection that gets no ChallengeResponse.
    pub candidate: Duration,
}

/// When keys change. Each party updates its own leaf, so each side has its
/// own deadline. The responder takes its turn after the initiator's Commit
/// is confirmed, so that the two rarely commit at once.
pub struct RekeyPolicy {
    /// This side commits an update of its own leaf once its leaf is this
    /// old.
    pub own_leaf_max_age: Duration,
    /// This side commits after sending this many bytes under one key. The
    /// AEAD limit applies independently and can't be raised.
    pub max_bytes_per_key: u64,
    /// A peer whose leaf is older than this has its session closed with
    /// [`crate::CloseReason::PolicyViolation`]. The age counts only time
    /// during which the session has a current connection, because a peer
    /// can't commit while the session is interrupted.
    pub peer_leaf_max_age: Duration,
    /// With APQ: each party sends a FULL Commit at least this often. The
    /// initiator's first FULL Commit has to be confirmed before it may send
    /// a PARTIAL one at the limit.
    pub full_commit_max_interval: Option<Duration>,
}

pub struct Liveness {
    /// Send a keepalive, an empty data record, after this much time
    /// without sending.
    pub keepalive_interval: Duration,
    /// Treat the connection as interrupted after this much time without
    /// receiving.
    pub idle_timeout: Duration,
}

/// Early data on reconnection (MLS-TLS "Early Data"), per direction. The
/// responder sends early data only after accepting the initiator's, so a
/// `responder` limit needs an `initiator` one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EarlyData {
    pub initiator: Option<EarlyLimit>,
    pub responder: Option<EarlyLimit>,
}

impl EarlyData {
    pub const OFF: EarlyData = EarlyData {
        initiator: None,
        responder: None,
    };
}

/// The limit on early data in one direction, per binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EarlyLimit {
    /// The sum of the `length` fields of all early data records,
    /// including the one with the EndOfEarlyData, padding, and AEAD
    /// expansion. At least the length of that last record.
    pub stream_bytes: u32,
}

/// Signs with one long-term key of this side. The key can stay in a
/// platform key store. Called from job threads, see [`crate::Job`].
pub trait Signer: Send + Sync {
    fn public_key(&self) -> &[u8];
    fn signature_scheme(&self) -> u16;
    fn credential(&self) -> &[u8];
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError>;
}

#[derive(Debug, Error)]
#[error("signing failed")]
pub struct SignError;

/// A configuration the engine refuses.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("configuration limit {0} must be positive")]
    ZeroLimit(&'static str),
    #[error("duration {0} is outside the microsecond clock range")]
    InvalidDuration(&'static str),
    #[error("the application protocol list is empty")]
    NoApplicationProtocols,
    #[error("an application protocol identifier must contain 1 to 255 bytes")]
    InvalidApplicationProtocol,
    #[error("an application protocol identifier appears more than once")]
    DuplicateApplicationProtocol,
    #[error("the padding target is outside the record plaintext bound")]
    InvalidPadding,
    /// `commit_confirmation` isn't longer than the authorization wait.
    #[error("the authorization wait must be shorter than the Commit-confirmation wait")]
    CommitBeforeAuthorization,
    /// `reset_state_lifetime` isn't longer than the responder's bound.
    #[error("the reset-state lifetime must exceed the responder session bound")]
    ResetStateTooShort,
    /// The responder's bound doesn't cover the initiator's idle timeout and
    /// reconnection waits.
    #[error("the responder session bound must exceed the idle timeout and reconnection waits")]
    ResponderBoundTooShort,
    #[error("no signing keys were configured")]
    NoSigner,
    #[error("APQ session configurations are unsupported")]
    UnsupportedApq,
    /// An APQ suite whose PQ signature scheme has no `pq_signer`.
    #[error("the APQ suite needs a separate PQ signer")]
    MissingPqSigner,
    /// The library's crypto backend can't run this suite. Checked for
    /// creating, joining, and updating a group, not just for primitives.
    #[error("MLS suite {0:#06x} is unsupported")]
    UnsupportedSuite(u16),
    /// A pre-handshake KEM or (KDF, AEAD) the backend can't run.
    #[error("pre-handshake configuration {config_id} is unsupported")]
    UnsupportedPreHandshake { config_id: u8 },
    #[error("pre-handshake configuration ID {0} appears more than once")]
    DuplicateConfigId(u8),
    /// A responder early data limit without an initiator one.
    #[error("responder early data requires an initiator limit")]
    ResponderEarlyDataAlone,
    /// An early data limit below one record with an EndOfEarlyData.
    #[error("the early data limit must fit an EndOfEarlyData record")]
    EarlyLimitTooSmall,
}

impl EngineConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        if self.signers.is_empty() {
            return Err(ConfigError::NoSigner);
        }
        if self.app_protocols.is_empty() {
            return Err(ConfigError::NoApplicationProtocols);
        }
        for (name, limit) in [
            ("max_pending_handshakes", self.limits.max_pending_handshakes),
            (
                "max_candidates_per_session",
                self.limits.max_candidates_per_session,
            ),
        ] {
            if limit == 0 {
                return Err(ConfigError::ZeroLimit(name));
            }
        }

        validate_duration("authorization", self.timeouts.authorization)?;
        validate_duration("first_message", self.timeouts.first_message)?;
        validate_duration("last_alive_interval", self.last_alive_interval)?;
        if let PaddingPolicy::AllTo(size) = self.padding {
            if !(1..=MAX_PLAINTEXT).contains(&size) {
                return Err(ConfigError::InvalidPadding);
            }
        }

        let mut protocol_ids = HashSet::new();
        for profile in &self.app_protocols {
            if !protocol_ids.insert(&profile.id) {
                return Err(ConfigError::DuplicateApplicationProtocol);
            }
            profile.validate(self.timeouts.authorization)?;
        }

        let mut config_ids = HashSet::new();
        for config in &self.pre_handshake.configs {
            let (ServerPreHandshakeConfig::Hpke { config_id, .. }
            | ServerPreHandshakeConfig::Psk { config_id, .. }) = config;
            if !config_ids.insert(*config_id) {
                return Err(ConfigError::DuplicateConfigId(*config_id));
            }
        }
        if let Some(config_id) = config_ids.into_iter().min() {
            return Err(ConfigError::UnsupportedPreHandshake { config_id });
        }
        Ok(())
    }
}

impl AppProtocolProfile {
    fn validate(&self, authorization: Duration) -> Result<(), ConfigError> {
        if !(1..=255).contains(&self.id.0.len()) {
            return Err(ConfigError::InvalidApplicationProtocol);
        }
        let times = &self.times;
        let rekey = &self.rekey;
        let liveness = &self.liveness;
        for (name, duration) in [
            ("initiator_session_bound", times.initiator_session_bound),
            ("responder_session_bound", times.responder_session_bound),
            ("reset_state_lifetime", times.reset_state_lifetime),
            ("initiator_handshake", times.initiator_handshake),
            ("responder_handshake", times.responder_handshake),
            ("commit_confirmation", times.commit_confirmation),
            ("reconnect_answer", times.reconnect_answer),
            ("adopted", times.adopted),
            ("candidate", times.candidate),
            ("own_leaf_max_age", rekey.own_leaf_max_age),
            ("peer_leaf_max_age", rekey.peer_leaf_max_age),
            ("keepalive_interval", liveness.keepalive_interval),
            ("idle_timeout", liveness.idle_timeout),
        ] {
            validate_duration(name, duration)?;
        }
        if let Some(interval) = rekey.full_commit_max_interval {
            validate_duration("full_commit_max_interval", interval)?;
        }
        if rekey.max_bytes_per_key == 0 {
            return Err(ConfigError::ZeroLimit("max_bytes_per_key"));
        }

        if times.commit_confirmation <= authorization {
            return Err(ConfigError::CommitBeforeAuthorization);
        }
        if times.reset_state_lifetime <= times.responder_session_bound {
            return Err(ConfigError::ResetStateTooShort);
        }
        let reconnect_wait = liveness
            .idle_timeout
            .saturating_add(times.reconnect_answer)
            .saturating_add(times.adopted);
        if times.responder_session_bound <= reconnect_wait {
            return Err(ConfigError::ResponderBoundTooShort);
        }

        if self.early_data.responder.is_some() && self.early_data.initiator.is_none() {
            return Err(ConfigError::ResponderEarlyDataAlone);
        }
        const END_OF_EARLY_DATA_RECORD_LEN: u32 = 4 + 1 + TAG_LEN as u32;
        for limit in [self.early_data.initiator, self.early_data.responder]
            .into_iter()
            .flatten()
        {
            if limit.stream_bytes < END_OF_EARLY_DATA_RECORD_LEN {
                return Err(ConfigError::EarlyLimitTooSmall);
            }
        }
        Ok(())
    }
}

fn validate_duration(name: &'static str, duration: Duration) -> Result<(), ConfigError> {
    let micros = duration.as_micros();
    if micros == 0 || u64::try_from(micros).is_err() {
        return Err(ConfigError::InvalidDuration(name));
    }
    Ok(())
}
