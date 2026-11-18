// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::component::{GroupInfo, LeafInfo};
use super::handshake::{
    append_clear_record, clear_record, Handshake, HandshakeType, Protection, Reassembly,
};
use super::pre_handshake::{
    open_payload, server_start, CipherSuite, ClientStart, ClientStartPrefix, Config,
    SessionReferences,
};
use super::profile::{
    ChallengeContent, MlsMessage, Reconnect, ReconnectContent, TwoPartyMessage, MAX_MLS_MESSAGE_LEN,
};
use super::*;

type Result<T = (), E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

fn handshake(kind: HandshakeType, body: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut bytes = Vec::new();
    Handshake { kind, body }.encode(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn clear_record_checks_the_header_first_and_opens_one_frame_at_a_time() -> Result {
    let payload = vec![0x7a; MAX_PLAINTEXT];
    let mut bytes = Vec::new();
    append_clear_record(&payload, &mut bytes)?;
    append_clear_record(b"other", &mut bytes)?;
    assert_eq!(&bytes[..HEADER_LEN], &[22, 3, 3, 0x40, 0]);
    for fragment in 0..HEADER_LEN + MAX_PLAINTEXT {
        assert_eq!(clear_record(&bytes[..fragment]), Ok(None));
    }
    assert_eq!(clear_record(&bytes)?, Some(payload.as_slice()));
    assert_eq!(
        clear_record(&bytes[HEADER_LEN + MAX_PLAINTEXT..])?,
        Some(b"other".as_slice())
    );
    assert_eq!(clear_record(&[22, 3, 3, 0x40, 1]), Err(WireError::TooLong));
    assert_eq!(clear_record(&[22, 3, 1, 0, 1]), Err(WireError::Version));
    assert_eq!(clear_record(&[20, 3, 3, 0, 1]), Err(WireError::Type));
    assert_eq!(clear_record(&[21, 3, 3, 0, 2]), Err(WireError::Type));
    assert_eq!(clear_record(&[23, 3, 3, 0, 1]), Err(WireError::Type));
    assert_eq!(clear_record(&[22, 3, 3, 0, 0]), Err(WireError::Invalid));
    assert_eq!(
        RecordHeader::decode(&[23, 3, 3, 0x41, 0], true),
        Ok(RecordHeader {
            kind: OuterType::Data,
            len: MAX_CIPHERTEXT
        })
    );
    assert_eq!(
        RecordHeader::decode(&[23, 3, 3, 0x41, 1], true),
        Err(WireError::TooLong)
    );
    Ok(())
}

#[test]
fn inner_plaintext_checks_types_padding_and_exact_alert_length() {
    assert_eq!(
        inner_plaintext(OuterType::Data, &[23]),
        Ok((ContentType::Data, 0))
    );
    assert_eq!(
        inner_plaintext(OuterType::Data, &[0, 0, 23, 0]),
        Ok((ContentType::Data, 2))
    );
    assert_eq!(
        inner_plaintext(OuterType::Handshake, &[53, 0, 21, 0]),
        Ok((ContentType::Alert, 2))
    );
    assert_eq!(
        inner_plaintext(OuterType::Data, &[1, 0, 21]),
        Ok((ContentType::Alert, 2))
    );
    assert_eq!(
        inner_plaintext(OuterType::Data, &[1, 0, 0, 21]),
        Err(WireError::Invalid)
    );
    assert_eq!(
        inner_plaintext(OuterType::Data, &[1, 1, 21]),
        Err(WireError::Invalid)
    );
    assert_eq!(
        inner_plaintext(OuterType::Data, &[0, 0, 0]),
        Err(WireError::Type)
    );
    assert_eq!(
        inner_plaintext(OuterType::Data, &[20, 0]),
        Err(WireError::Type)
    );
    assert_eq!(
        inner_plaintext(OuterType::Handshake, &[23]),
        Err(WireError::Type)
    );
    assert_eq!(
        inner_plaintext(OuterType::Handshake, &[22]),
        Err(WireError::Invalid)
    );
}

#[test]
fn reassembles_at_every_boundary_and_reads_coalesced_messages() -> Result {
    let first = handshake(HandshakeType::MlsMessage, b"first")?;
    let second = handshake(HandshakeType::MlsMessage, b"second")?;
    let stream = [first, second].concat();
    for split in 1..stream.len() {
        let mut reassembly = Reassembly::default();
        let mut delivered = Vec::new();
        for fragment in [&stream[..split], &stream[split..]] {
            reassembly.push(
                Protection::Epoch(1),
                ContentType::Handshake,
                fragment,
                |msg| {
                    assert_eq!(msg.kind, HandshakeType::MlsMessage);
                    delivered.push(msg.body.to_vec());
                    Ok(())
                },
            )?;
        }
        assert_eq!(
            delivered,
            [b"first".to_vec(), b"second".to_vec()],
            "split {split}"
        );
    }

    let mut reassembly = Reassembly::default();
    let mut delivered = Vec::new();
    for fragment in stream.chunks(1) {
        reassembly.push(
            Protection::Epoch(1),
            ContentType::Handshake,
            fragment,
            |msg| {
                delivered.push(msg.body.to_vec());
                Ok(())
            },
        )?;
    }
    assert_eq!(delivered, [b"first".to_vec(), b"second".to_vec()]);
    Ok(())
}

#[test]
fn only_consecutive_handshake_records_under_the_same_key_can_continue_a_fragment() -> Result {
    let bytes = handshake(HandshakeType::MlsMessage, b"split")?;
    for (key, content) in [
        (Protection::Epoch(2), ContentType::Handshake),
        (Protection::PreHandshake, ContentType::Handshake),
        (Protection::Epoch(1), ContentType::Data),
        (Protection::Epoch(1), ContentType::Alert),
    ] {
        let mut reassembly = Reassembly::default();
        reassembly.push(
            Protection::Epoch(1),
            ContentType::Handshake,
            &bytes[..2],
            |_| Err(WireError::Invalid),
        )?;
        assert_eq!(
            reassembly.push(key, content, &bytes[2..], |_| Err(WireError::Invalid)),
            Err(WireError::Fragment)
        );
    }
    let mut reassembly = Reassembly::default();
    assert_eq!(
        reassembly.push(Protection::Clear, ContentType::Handshake, &[], |_| Ok(())),
        Err(WireError::Invalid),
    );
    Ok(())
}

#[test]
fn switch_messages_must_end_the_record_and_earlier_messages_are_delivered() -> Result {
    let mut epoch_update = Vec::new();
    TwoPartyMessage::EpochKeyUpdate {
        epoch: 2,
        confirmation: &[3; 48],
    }
    .write_mls(&mut epoch_update)?;
    let before = handshake(HandshakeType::MlsMessage, b"before switch")?;
    for (kind, body, protection) in [
        (
            HandshakeType::ClientStart,
            b"pre-start".as_slice(),
            Protection::Clear,
        ),
        (HandshakeType::ServerStart, &[1; 32], Protection::Clear),
        (HandshakeType::EndOfEarlyData, &[], Protection::EarlyData),
        (
            HandshakeType::MlsMessage,
            epoch_update.as_slice(),
            Protection::Epoch(1),
        ),
    ] {
        let bytes = [before.clone(), handshake(kind, body)?].concat();
        let mut delivered = 0;
        let mut reassembly = Reassembly::default();
        reassembly.push(protection, ContentType::Handshake, &bytes, |_| {
            delivered += 1;
            Ok(())
        })?;
        assert_eq!(delivered, 2);
        for split in 0..bytes.len() {
            let mut broken = bytes.clone();
            broken.push(3);
            let mut delivered = 0;
            let mut reassembly = Reassembly::default();
            let mut sink = |_: Handshake<'_>| {
                delivered += 1;
                Ok(())
            };
            if split > 0 {
                reassembly.push(
                    protection,
                    ContentType::Handshake,
                    &broken[..split],
                    &mut sink,
                )?;
            }
            assert_eq!(
                reassembly.push(
                    protection,
                    ContentType::Handshake,
                    &broken[split..],
                    &mut sink
                ),
                Err(WireError::KeySwitch)
            );
            assert_eq!(delivered, 1);
        }
    }
    Ok(())
}

#[test]
fn malformed_inner_mls_is_preserved_for_epoch_error_handling() -> Result {
    let malformed = [0, 1, 0xf0, 2, 1]; // A truncated EpochKeyUpdate.
    let wire = [handshake(HandshakeType::MlsMessage, &malformed)?, vec![255]].concat();
    let mut delivered = false;
    Reassembly::default().push(
        Protection::Epoch(1),
        ContentType::Handshake,
        &wire,
        |message| {
            assert_eq!(message.body, malformed);
            assert!(MlsMessage::decode(message.body).is_err());
            delivered = true;
            Ok(())
        },
    )?;
    assert!(delivered);
    Ok(())
}

#[test]
fn handshake_lengths_are_rejected_at_the_header_and_maxima_reassemble() -> Result {
    let too_large_mls = [3, 4, 0, 1];
    let too_large_start = [1, 4, 0x10, 1];
    for header in [too_large_mls, too_large_start, [3, 0xff, 0xff, 0xff]] {
        let mut reassembly = Reassembly::default();
        reassembly.push(
            Protection::Clear,
            ContentType::Handshake,
            &header[..3],
            |_| Ok(()),
        )?;
        assert_eq!(
            reassembly.push(
                Protection::Clear,
                ContentType::Handshake,
                &header[3..],
                |_| Ok(())
            ),
            Err(WireError::TooLong)
        );
    }
    for bad in [[4, 0, 0, 0], [2, 0, 0, 31], [5, 0, 0, 1]] {
        assert!(Handshake::read_prefix(&bad).is_err());
    }
    for (kind, len) in [
        (HandshakeType::MlsMessage, MAX_MLS_MESSAGE_LEN),
        (HandshakeType::ClientStart, MAX_MLS_MESSAGE_LEN + 4096),
    ] {
        let mut count = 0;
        let body = vec![42; len];
        let mut reassembly = Reassembly::default();
        Handshake { kind, body: &body }.for_each_fragment(MAX_PLAINTEXT, |fragment| {
            reassembly.push(
                Protection::Clear,
                ContentType::Handshake,
                fragment,
                |message| {
                    assert_eq!(message, Handshake { kind, body: &body });
                    count += 1;
                    Ok(())
                },
            )
        })?;
        assert_eq!(count, 1);
    }
    Ok(())
}

#[test]
fn vectors_borrow_and_reject_malformed_lengths_and_optional_flags() -> Result {
    for len in [0, 1, 63, 64, 16_383, 16_384, MAX_MLS_MESSAGE_LEN] {
        let value = vec![0xaa; len];
        let mut wire = Vec::new();
        put_vector(&value, &mut wire)?;
        let mut reader = Reader::new(&wire);
        assert_eq!(reader.vector()?, value);
        assert_eq!(reader.finish(), Ok(()));
    }
    assert_eq!(Reader::new(&[0x40, 1, 5]).vector(), Err(WireError::Invalid));
    assert_eq!(
        Reader::new(&[0x80, 0, 0x10, 0]).vector(),
        Err(WireError::Invalid)
    );
    assert_eq!(Reader::new(&[0xc0]).vector(), Err(WireError::Invalid));
    assert_eq!(
        Reader::new(&[0xbf, 0xff, 0xff, 0xff]).vector(),
        Err(WireError::Truncated)
    );
    assert_eq!(
        Reader::new(&[2, 0]).optional_vector(),
        Err(WireError::Invalid)
    );
    Ok(())
}

#[test]
fn profile_messages_match_wire_encoding_and_reject_trailing_bytes() -> Result {
    let nonce = [0x70; 32];
    let reconnect = Reconnect {
        content: ReconnectContent {
            number: 7,
            nonce: &nonce,
            early_data: false,
            current: b"C",
            pending: Some(b"P"),
        },
        current_binder: b"c",
        pending_binder: Some(b"p"),
    };
    let mut reconnect_bytes = vec![0, 1, 0xf0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 7];
    reconnect_bytes.extend_from_slice(&nonce);
    reconnect_bytes.extend_from_slice(&[0, 0, 1, b'C', 1, 1, b'P', 1, b'c', 1, 1, b'p']);
    let mut challenge = vec![0, 1, 0xf0, 2, 3, 2];
    challenge.extend_from_slice(&nonce);
    challenge.extend_from_slice(&[1, 1, b'P']);
    let cases = [
        (
            TwoPartyMessage::EpochKeyUpdate {
                epoch: 8,
                confirmation: b"K",
            },
            vec![0, 1, 0xf0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 8, 1, b'K'],
        ),
        (TwoPartyMessage::Reconnect(reconnect), reconnect_bytes),
        (
            TwoPartyMessage::Challenge {
                content: ChallengeContent {
                    epoch: 2,
                    challenge: &nonce,
                    early_data: 1,
                },
                proof: b"P",
            },
            challenge,
        ),
        (
            TwoPartyMessage::ChallengeResponse {
                epoch: 0,
                response: b"R",
            },
            vec![0, 1, 0xf0, 2, 4, 0, 1, b'R'],
        ),
        (
            TwoPartyMessage::Adopted(b"A"),
            vec![0, 1, 0xf0, 2, 5, 1, b'A'],
        ),
        (
            TwoPartyMessage::Reset(b"T"),
            vec![0, 1, 0xf0, 2, 6, 1, b'T'],
        ),
    ];
    for (message, expected) in cases {
        let mut bytes = Vec::new();
        message.write_mls(&mut bytes)?;
        assert_eq!(bytes, expected);
        let MlsMessage::TwoParty(decoded) = MlsMessage::decode(&bytes)? else {
            return Err("expected a profile message".into());
        };
        assert_eq!(decoded, message);
        for end in 0..bytes.len() {
            assert!(MlsMessage::decode(&bytes[..end]).is_err());
        }
        bytes.push(0);
        assert!(matches!(
            MlsMessage::decode(&bytes),
            Err(WireError::Trailing)
        ));
    }

    let mut invalid = Vec::new();
    let reconnect = Reconnect {
        pending_binder: None,
        ..reconnect
    };
    assert_eq!(
        TwoPartyMessage::Reconnect(reconnect).write_mls(&mut invalid),
        Err(WireError::Invalid)
    );
    assert!(invalid.is_empty());
    assert!(matches!(
        MlsMessage::decode(&[0, 2, 0xf0, 2, 6, 0]),
        Err(WireError::Version)
    ));
    assert!(matches!(
        MlsMessage::decode(&[0, 1, 0xf0, 2, 7, 0]),
        Err(WireError::Type)
    ));
    assert!(matches!(
        MlsMessage::decode(&[0, 1, 0, 2, 0]),
        Err(WireError::Type)
    ));
    Ok(())
}

#[test]
fn mls_tls_component_uses_ordered_versions_and_alpn_names() -> Result {
    let mut bytes = Vec::new();
    LeafInfo::encode(&[2, 1], &[b"vpn", b"mesh"], &mut bytes)?;
    assert_eq!(bytes, b"\x04\0\x02\0\x01\x09\x03vpn\x04mesh");
    let info = LeafInfo::decode(&bytes)?;
    assert_eq!(info.versions().collect::<Vec<_>>(), [2, 1]);
    assert_eq!(
        info.application_protocols().collect::<Vec<_>>(),
        [b"vpn".as_slice(), b"mesh".as_slice()]
    );
    assert!(LeafInfo::decode(&[1, 1, 2, 1, b'p']).is_err());
    assert!(LeafInfo::decode(&[2, 0, 1, 1, 0]).is_err());
    let mut bytes = Vec::new();
    let group = GroupInfo {
        version: 1,
        application_protocol: b"vpn",
    };
    group.encode(&mut bytes)?;
    assert_eq!(bytes, b"\0\x01\x03vpn");
    assert_eq!(GroupInfo::decode(&bytes)?, group);
    bytes.push(0);
    assert_eq!(GroupInfo::decode(&bytes), Err(WireError::Trailing));
    assert!(GroupInfo::decode(&[0, 1, 0]).is_err());
    let max = [0xfe; 255];
    let mut bytes = Vec::new();
    GroupInfo {
        version: 1,
        application_protocol: &max,
    }
    .encode(&mut bytes)?;
    assert_eq!(GroupInfo::decode(&bytes)?.application_protocol, max);
    assert_eq!(
        GroupInfo {
            version: 1,
            application_protocol: &[0xfe; 256]
        }
        .encode(&mut Vec::new()),
        Err(WireError::TooLong)
    );
    Ok(())
}

#[test]
fn pre_handshake_configurations_and_prefixes_match_their_wire_bytes() -> Result {
    let suite = CipherSuite { kdf: 2, aead: 3 };
    let mut bytes = Vec::new();
    Config::Hpke {
        id: 5,
        kem: 0x1234,
        public_key: b"P",
        cipher_suites: vec![suite],
    }
    .encode(&mut bytes)?;
    assert_eq!(bytes, b"\x05\x01\x12\x34\x01P\x04\0\x02\0\x03");
    let Config::Hpke {
        id,
        kem,
        public_key,
        cipher_suites,
    } = Config::decode(&bytes)?
    else {
        return Err("expected HPKE config".into());
    };
    assert_eq!(
        (id, kem, public_key, cipher_suites.as_slice()),
        (5, 0x1234, b"P".as_slice(), [suite].as_slice())
    );
    bytes.clear();
    Config::Psk {
        id: 9,
        cipher_suite: suite,
    }
    .encode(&mut bytes)?;
    assert_eq!(bytes, b"\x09\x02\0\x02\0\x03");
    let Config::Psk { id, cipher_suite } = Config::decode(&bytes)? else {
        return Err("expected PSK config".into());
    };
    assert_eq!((id, cipher_suite), (9, suite));
    assert!(Config::decode(&[5, 2, 0, 1, 0xff, 0xff]).is_err());
    assert!(Config::decode(&[5, 1, 0, 0, 0, 1, 1]).is_err());

    let random = [0x77; 32];
    let references = SessionReferences {
        client_random: &random,
        current: b"r",
        pending: Some(b"p"),
    };
    for (prefix, expected, wrap_end) in [
        (
            ClientStartPrefix::Hpke {
                config: 8,
                suite,
                enc: b"E",
            },
            b"\x01\x08\0\x02\0\x03\x01E".to_vec(),
            None,
        ),
        (
            ClientStartPrefix::Psk {
                config: 9,
                client_random: &random,
            },
            [b"\x02\x09".as_slice(), &random].concat(),
            None,
        ),
        (
            ClientStartPrefix::Session {
                references,
                current_key: b"K",
                pending_key: Some(b"O"),
            },
            [b"\x03".as_slice(), &random, b"\x01r\x01\x01p\x01K\x01\x01O"].concat(),
            Some(38),
        ),
    ] {
        let mut bytes = Vec::new();
        prefix.encode(&mut bytes)?;
        assert_eq!(bytes, expected);
        put_vector(b"sealed", &mut bytes)?;
        let start = ClientStart::decode(&bytes)?;
        assert_eq!(start.prefix, prefix);
        assert_eq!(start.wrap_aad, wrap_end.map(|end| &bytes[..end]));
        assert_eq!(start.payload_aad, expected.as_slice());
        assert_eq!(start.payload, b"sealed");
        bytes.push(0);
        assert!(matches!(
            ClientStart::decode(&bytes),
            Err(WireError::Trailing)
        ));
    }
    let mismatched = [b"\x03".as_slice(), &random, b"\x01r\x01\x01p\x01K\0\0"].concat();
    assert!(matches!(
        ClientStart::decode(&mismatched),
        Err(WireError::Invalid)
    ));
    assert_eq!(server_start(&random)?, &random);
    assert!(server_start(&[0; 33]).is_err());
    Ok(())
}

#[test]
fn decrypted_client_start_payload_accepts_only_one_handshake_and_zero_padding() -> Result {
    let hello = handshake(HandshakeType::MlsMessage, b"hello")?;
    let end = handshake(HandshakeType::EndOfEarlyData, &[])?;
    assert_eq!(
        open_payload(&[hello.clone(), vec![0; 256]].concat())?,
        b"hello"
    );
    assert_eq!(
        open_payload(&[hello.clone(), end.clone()].concat()),
        Err(WireError::Invalid)
    );
    assert_eq!(open_payload(&end), Err(WireError::Type));
    assert_eq!(
        open_payload(&hello[..hello.len() - 1]),
        Err(WireError::Truncated)
    );
    Ok(())
}

#[test]
fn standard_mls_objects_are_decoded_exactly_after_dispatch() -> Result {
    use openmls::prelude::MlsMessageBodyIn;

    let minimal_welcome = [0, 1, 0, 3, 0, 1, 0, 0];
    let MlsMessage::Standard(message) = MlsMessage::decode(&minimal_welcome)? else {
        return Err("expected standard MLS wire format".into());
    };
    assert!(matches!(*message, MlsMessageBodyIn::Welcome(_)));
    let mut trailing = minimal_welcome.to_vec();
    trailing.push(0);
    assert!(MlsMessage::decode(&trailing).is_err());
    Ok(())
}

#[test]
fn rejected_lengths_have_bounded_peak_allocations() {
    let overlong = allocation_counter::measure(|| {
        let mut reassembly = Reassembly::default();
        let header = [3, 0xff, 0xff, 0xff];
        for byte in &header[..3] {
            assert_eq!(
                reassembly.push(
                    Protection::Clear,
                    ContentType::Handshake,
                    std::slice::from_ref(byte),
                    |_| Ok(())
                ),
                Ok(())
            );
        }
        assert_eq!(
            reassembly.push(
                Protection::Clear,
                ContentType::Handshake,
                &header[3..],
                |_| Ok(())
            ),
            Err(WireError::TooLong)
        );
    });
    assert_eq!(overlong.bytes_max, 0, "{overlong:?}");

    let huge_length = [0xbf, 0xff, 0xff, 0xff];
    for prefix in [
        &[0, 1, 0, 5, 0, 1, 0, 1][..], // KeyPackage init_key
        &[0, 1, 0, 3, 0, 1, 0][..],    // Welcome encrypted_group_info
        &[0, 1, 0, 1][..],             // PublicMessage group_id
    ] {
        let wire = [prefix, &huge_length, &[0; 128]].concat();
        let peak = allocation_counter::measure(|| {
            assert!(matches!(MlsMessage::decode(&wire), Err(WireError::Invalid)));
        });
        // tls_codec 0.5 permits one initial 4 KiB chunk for a truncated opaque vector.
        assert!(peak.bytes_max <= 4096, "{peak:?}");
        assert_eq!(peak.bytes_current, 0, "{peak:?}");
        eprintln!(
            "rejected MLS wire format {}: {} B peak",
            prefix[3], peak.bytes_max
        );
    }
}
