// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

mod support;

use std::fmt::Debug;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use mls_tls_protocol::*;
use static_assertions::{assert_impl_all, assert_not_impl_any};
use support::{Endpoint, Pair, TestStore};

assert_impl_all!(Engine: Send);
assert_impl_all!(Admission: Send, Sync);
assert_impl_all!(Job: Send);
assert_impl_all!(JobResult: Send);
assert_impl_all!(ToEngine: Send);
assert_impl_all!(ToConnection: Send);
assert_impl_all!(StreamConnection: Send);
assert_not_impl_any!(Engine: Sync, Clone);
assert_not_impl_any!(StreamConnection: Sync, Clone);
assert_not_impl_any!(Job: Clone, Debug);
assert_not_impl_any!(Secret: Clone, Debug);
assert_not_impl_any!(EpochRecord: Clone, Debug);
assert_not_impl_any!(ResetRecord: Clone, Debug);
assert_not_impl_any!(ToConnection: Clone, Debug);

struct TestSigner;

impl Signer for TestSigner {
    fn public_key(&self) -> &[u8] {
        b"test key"
    }

    fn signature_scheme(&self) -> u16 {
        0x0807
    }

    fn credential(&self) -> &[u8] {
        b"test peer"
    }

    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, SignError> {
        Err(SignError)
    }
}

fn test_config() -> EngineConfig {
    let short = Duration::from_secs(1);
    let medium = Duration::from_secs(10);
    let long = Duration::from_secs(60);
    EngineConfig {
        signers: vec![SignerSet {
            signer: Arc::new(TestSigner),
            pq_signer: None,
        }],
        app_protocols: vec![AppProtocolProfile {
            id: AppProtocol(b"test/1".to_vec()),
            early_data: EarlyData::OFF,
            times: ProtocolTimes {
                initiator_session_bound: long,
                responder_session_bound: long,
                reset_state_lifetime: long * 2,
                initiator_handshake: medium,
                responder_handshake: medium,
                commit_confirmation: medium,
                reconnect_answer: short,
                adopted: short,
                candidate: short,
            },
            rekey: RekeyPolicy {
                own_leaf_max_age: long,
                peer_leaf_max_age: long * 2,
                max_bytes_per_key: 16,
                full_commit_max_interval: None,
            },
            liveness: Liveness {
                keepalive_interval: short,
                idle_timeout: medium,
            },
        }],
        pre_handshake: ServerPreHandshake {
            configs: Vec::new(),
            accept_clear: true,
        },
        limits: Limits {
            max_pending_handshakes: 1,
            max_candidates_per_session: 1,
        },
        timeouts: LocalTimeouts {
            authorization: short,
            first_message: short,
        },
        padding: PaddingPolicy::None,
        last_alive_interval: short,
    }
}

#[test]
fn unimplemented_endpoints_refuse_to_start_and_emit_nothing() -> Result<(), ConfigError> {
    let mut pair = Pair {
        initiator: Endpoint::new(Engine::new(test_config())?),
        responder: Endpoint::new(Engine::new(test_config())?),
        now: Instant::from_micros(0),
        wall_now: WallTime(100),
    };
    let server = ServerProvisioning {
        suite: SessionSuite::Single(1),
        pre_handshake: ClientPreHandshake::None,
    };
    assert_eq!(
        pair.initiator
            .engine
            .connect(Binding::Stream, &server, pair.now),
        Err(EngineError::UnsupportedSuite(1))
    );
    let path = Path {
        local: SocketAddr::from((Ipv4Addr::LOCALHOST, 443)),
        remote: SocketAddr::from((Ipv4Addr::LOCALHOST, 10000)),
    };
    assert!(matches!(
        pair.responder
            .engine
            .admission()
            .accept_stream(path, pair.now),
        Err(EngineError::Unavailable)
    ));

    pair.advance(Duration::from_secs(10));
    for endpoint in [&mut pair.initiator, &mut pair.responder] {
        let (result, outputs) = endpoint.tick(pair.now, pair.wall_now);
        assert_eq!(result, Err(EngineError::Unavailable));
        assert!(outputs.is_empty());
        assert_eq!(endpoint.store.commit_next(), None);
        assert_eq!(endpoint.engine.sessions().count(), 0);
    }
    Ok(())
}

#[test]
fn configuration_rejects_unsupported_suites_and_pre_handshakes() -> Result<(), ConfigError> {
    let mut engine = Engine::new(test_config())?;
    for suite in [
        SessionSuite::Single(u16::MAX),
        SessionSuite::Apq {
            t: u16::MAX,
            pq: 1,
            mode: ApqMode::Confidentiality,
        },
        SessionSuite::Apq {
            t: u16::MAX,
            pq: 1,
            mode: ApqMode::ConfidentialityAndAuthenticity,
        },
    ] {
        let server = ServerProvisioning {
            suite,
            pre_handshake: ClientPreHandshake::None,
        };
        assert_eq!(
            engine.connect(Binding::Stream, &server, Instant::from_micros(0)),
            Err(EngineError::UnsupportedSuite(u16::MAX))
        );
    }

    let mut config = test_config();
    config
        .pre_handshake
        .configs
        .push(ServerPreHandshakeConfig::Hpke {
            config_id: 7,
            kem_id: u16::MAX,
            public_key: vec![0; 32],
            private_key: Secret::new(vec![0; 32]),
            cipher_suites: vec![(1, 1)],
        });
    assert!(matches!(
        Engine::new(config),
        Err(ConfigError::UnsupportedPreHandshake { config_id: 7 })
    ));
    Ok(())
}

#[test]
fn validates_application_protocol_timing_and_limits() {
    let mut config = test_config();
    config.timeouts.authorization = config.app_protocols[0].times.commit_confirmation;
    assert!(matches!(
        Engine::new(config),
        Err(ConfigError::CommitBeforeAuthorization)
    ));

    let mut config = test_config();
    config.app_protocols[0].early_data.initiator = Some(EarlyLimit { stream_bytes: 20 });
    assert!(matches!(
        Engine::new(config),
        Err(ConfigError::EarlyLimitTooSmall)
    ));

    let mut config = test_config();
    config.timeouts.first_message = Duration::MAX;
    assert!(matches!(
        Engine::new(config),
        Err(ConfigError::InvalidDuration("first_message"))
    ));
}

#[test]
fn packet_range_errors_leave_the_buffer_intact() -> Result<(), InvalidPayloadRange> {
    let mut bytes = [0, 1, 2, 3];
    assert!(PacketBuf::new(&mut bytes, 3, 1).is_err());
    assert!(PacketBuf::new(&mut bytes, 0, 5).is_err());
    let mut packet = PacketBuf::new(&mut bytes, 1, 3)?;
    assert_eq!(packet.bytes(), [1, 2]);
    assert_eq!((packet.headroom(), packet.tailroom()), (1, 1));
    packet.bytes_mut()[0] = 9;
    assert_eq!(bytes, [0, 9, 2, 3]);
    Ok(())
}

#[test]
fn deadlines_never_wrap() {
    let time = Instant::from_micros(u64::MAX - 1);
    assert_eq!(time.checked_add(Duration::from_micros(2)), None);
    assert_eq!(time.checked_add(Duration::MAX), None);
    assert_eq!(time + Duration::MAX, Instant::from_micros(u64::MAX));
}

#[test]
fn crashing_after_a_failed_write_preserves_the_previous_state() {
    let session = SessionId(1);
    let mut store = TestStore::default();
    store.stage(StoreWrite::Session {
        txn: TxnId(1),
        session,
        ops: vec![
            StoreOp::PutEpochs(EpochRecord::from_bytes(vec![1])),
            StoreOp::PutCounters(CounterRecord::from_bytes(vec![2])),
        ],
    });
    assert_eq!(store.commit_next(), Some(TxnId(1)));
    store.stage(StoreWrite::Session {
        txn: TxnId(2),
        session,
        ops: vec![
            StoreOp::DeleteSession,
            StoreOp::PutReset {
                record: ResetRecord::from_bytes(vec![3]),
                expires: WallTime(200),
            },
        ],
    });
    assert_eq!(store.fail_next(), Some(TxnId(2)));
    store.stage(StoreWrite::Session {
        txn: TxnId(3),
        session,
        ops: vec![StoreOp::PutCounters(CounterRecord::from_bytes(vec![4]))],
    });
    let stored = store.crash();
    assert_eq!(stored.sessions.len(), 1);
    assert_eq!(stored.sessions[0].epochs.as_bytes(), [1]);
    assert_eq!(stored.sessions[0].counters.as_bytes(), [2]);
    assert!(stored.resets.is_empty());
}

#[test]
fn unavailable_restore_returns_the_supplied_records() {
    let stored = StoredState {
        engine: Some(EngineRecord::from_bytes(vec![1, 2])),
        sessions: Vec::new(),
        resets: Vec::new(),
    };
    let result = Engine::restore(
        test_config(),
        stored,
        RestoreOrigin::Latest,
        ClockBehind::Refuse,
        WallTime(100),
        Instant::from_micros(0),
    );
    assert!(matches!(result, Err(RestoreError::Unavailable(StoredState {
        engine: Some(record), sessions, resets
    })) if sessions.is_empty() && resets.is_empty() && record.as_bytes() == [1, 2]));
}
