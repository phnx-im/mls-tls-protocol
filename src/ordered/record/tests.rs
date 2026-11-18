// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::ordered::wire::{
    handshake::{Handshake, HandshakeType},
    profile::MAX_MLS_MESSAGE_LEN,
    MAX_CIPHERTEXT, MAX_PLAINTEXT,
};

type Result<T = (), E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

fn aes_key() -> Result<TrafficKey, RecordError> {
    TrafficKey::derive(Hash::Sha384, Algorithm::Aes256Gcm, &[7; 48])
}

fn seal(sealer: &mut Sealer, purpose: Purpose, payload: &[u8], padding: usize) -> Result<Vec<u8>> {
    let end = HEADER_LEN + payload.len();
    let mut frame = vec![0xba; end + 1 + padding + TAG_LEN];
    frame[HEADER_LEN..end].copy_from_slice(payload);
    let mut packet = PacketBuf::new(&mut frame, HEADER_LEN, end)?;
    sealer.seal(purpose, &mut packet, padding)?;
    assert_eq!(packet.bytes().len(), frame.len());
    Ok(frame)
}

fn hex(input: &str) -> Result<Vec<u8>> {
    let (bytes, tail) = input.as_bytes().as_chunks::<2>();
    if !tail.is_empty() {
        return Err("incomplete vector byte".into());
    }
    bytes
        .iter()
        .map(|byte| Ok(u8::from_str_radix(std::str::from_utf8(byte)?, 16)?))
        .collect()
}

#[test]
fn record_vectors_match_independent_hkdf_and_aead() -> Result {
    let cases = include_str!("../../../tests/vectors/records.txt");
    let payload = [0, 255, 77, 76, 83, 0];
    let mut count = 0;
    for line in cases.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split_whitespace().collect();
        let [hash, algorithm, key, iv, nonce, first, second] = fields.as_slice() else {
            return Err("invalid vector row".into());
        };
        let hash = match *hash {
            "SHA256" => Hash::Sha256,
            "SHA384" => Hash::Sha384,
            "SHA512" => Hash::Sha512,
            _ => return Err("unknown hash".into()),
        };
        let algorithm = match *algorithm {
            "aes-128-gcm" => Algorithm::Aes128Gcm,
            "aes-256-gcm" => Algorithm::Aes256Gcm,
            "chacha20-poly1305" => Algorithm::ChaCha20Poly1305,
            _ => return Err("unknown AEAD".into()),
        };
        let secret: Vec<_> = (0..hash.size() as u8).collect();
        let mut derived = vec![0; algorithm.key_len()];
        hash.expand(&secret, b"key", &mut derived)?;
        assert_eq!(derived, hex(key)?);
        let traffic_key = TrafficKey::derive(hash, algorithm, &secret)?;
        assert_eq!(&traffic_key.iv[..], hex(iv)?);
        assert_eq!(&traffic_key.nonce(0x0102030405060708)[..], hex(nonce)?);
        let mut sealer = Sealer::new(traffic_key, OuterType::Data);
        let mut opener = Opener::new(
            TrafficKey::derive(hash, algorithm, &secret)?,
            OuterType::Data,
        );
        for vector in [first, second] {
            let mut frame = seal(&mut sealer, Purpose::Application, &payload, 3)?;
            assert_eq!(frame, hex(vector)?);
            let opened = opener.open(&mut frame)?.ok_or("incomplete vector record")?;
            assert_eq!(opened.content, ContentType::Data);
            assert_eq!(opened.consumed, frame.len());
            assert_eq!(frame[opened.payload], payload);
        }
        count += 1;
    }
    assert_eq!(count, 9);
    Ok(())
}

#[test]
fn incomplete_records_preserve_the_sequence_and_buffer() -> Result {
    let mut sealer = Sealer::new(aes_key()?, OuterType::Data);
    let first = seal(&mut sealer, Purpose::Application, b"first", 1)?;
    let second = seal(&mut sealer, Purpose::Application, b"second", 0)?;
    let mut records = [first, second].concat();
    let mut opener = Opener::new(aes_key()?, OuterType::Data);
    let original = records.clone();
    let first_len = HEADER_LEN + 5 + 2 + TAG_LEN;
    for split in 0..first_len {
        assert!(opener.open(&mut records[..split])?.is_none());
        assert_eq!(records, original);
    }
    let opened = opener.open(&mut records)?.ok_or("missing first record")?;
    assert_eq!(opened.consumed, first_len);
    assert_eq!(&records[opened.payload], b"first");
    let opened = opener
        .open(&mut records[first_len..])?
        .ok_or("missing second record")?;
    assert_eq!(
        &records[first_len + opened.payload.start..first_len + opened.payload.end],
        b"second"
    );
    Ok(())
}

#[test]
fn tampering_reordering_and_replay_retire_the_receive_key() -> Result {
    let mut sealer = Sealer::new(aes_key()?, OuterType::Data);
    let first = seal(&mut sealer, Purpose::Application, b"one", 0)?;
    let second = seal(&mut sealer, Purpose::Application, b"two", 0)?;

    let mut damaged = first.clone();
    let last = damaged.last_mut().ok_or("missing tag")?;
    *last ^= 1;
    let mut opener = Opener::new(aes_key()?, OuterType::Data);
    assert_eq!(opener.open(&mut damaged), Err(RecordError::Authentication));
    assert_eq!(opener.open(&mut first.clone()), Err(RecordError::Exhausted));

    let mut opener = Opener::new(aes_key()?, OuterType::Data);
    assert_eq!(
        opener.open(&mut second.clone()),
        Err(RecordError::Authentication)
    );
    let mut opener = Opener::new(aes_key()?, OuterType::Data);
    assert!(opener.open(&mut first.clone())?.is_some());
    let mut first = first;
    assert_eq!(opener.open(&mut first), Err(RecordError::Authentication));

    // An alert is legal under either outer type, so only the AAD can reject this type change.
    let mut sealer = Sealer::new(aes_key()?, OuterType::Handshake);
    let mut alert = seal(&mut sealer, Purpose::Close, &[1, 0], 0)?;
    alert[0] = OuterType::Data as u8;
    let mut opener = Opener::new(aes_key()?, OuterType::Data);
    assert_eq!(opener.open(&mut alert), Err(RecordError::Authentication));
    Ok(())
}

#[test]
fn plaintext_and_ciphertext_sizes_have_separate_limits() -> Result {
    let mut sealer = Sealer::new(aes_key()?, OuterType::Data);
    let mut full = seal(
        &mut sealer,
        Purpose::Application,
        &vec![3; MAX_PLAINTEXT - 2],
        1,
    )?;
    let mut opener = Opener::new(aes_key()?, OuterType::Data);
    assert!(opener.open(&mut full)?.is_some());
    let mut bytes = vec![0; HEADER_LEN + MAX_PLAINTEXT + 1 + TAG_LEN];
    let mut packet = PacketBuf::new(&mut bytes, HEADER_LEN, HEADER_LEN + MAX_PLAINTEXT)?;
    assert_eq!(
        sealer.seal(Purpose::Application, &mut packet, 0),
        Err(WireError::TooLong.into())
    );
    assert_eq!(sealer.sequence, 1);

    let mut sealer = Sealer::new(aes_key()?, OuterType::Handshake);
    let mut full = seal(
        &mut sealer,
        Purpose::PreHandshake,
        &vec![3; MAX_PLAINTEXT],
        0,
    )?;
    let mut opener = Opener::new(aes_key()?, OuterType::Handshake);
    assert!(opener.open(&mut full)?.is_some());

    for len in [
        MAX_PLAINTEXT + TAG_LEN + 1,
        MAX_CIPHERTEXT,
        MAX_CIPHERTEXT + 1,
    ] {
        let mut header = RecordHeader {
            kind: OuterType::Data,
            len,
        }
        .encode()?;
        let mut opener = Opener::new(aes_key()?, OuterType::Data);
        assert_eq!(opener.open(&mut header), Err(WireError::TooLong.into()));
    }
    Ok(())
}

#[test]
fn control_reserve_fits_a_maximum_commit_switch_and_alert() -> Result {
    let mut sealer = Sealer::new(aes_key()?, OuterType::Data);
    sealer.sequence = AES_GCM_LIMIT - CONTROL_RESERVE - 1;
    seal(&mut sealer, Purpose::Application, b"last data", 0)?;
    let mut output = [0x7a; HEADER_LEN + 1 + TAG_LEN];
    let mut packet = PacketBuf::new(&mut output, HEADER_LEN, HEADER_LEN)?;
    assert_eq!(
        sealer.seal(Purpose::Application, &mut packet, 0),
        Err(RecordError::Reserve)
    );
    let commit = vec![0; MAX_MLS_MESSAGE_LEN];
    let mut fragments = 0;
    Handshake {
        kind: HandshakeType::MlsMessage,
        body: &commit,
    }
    .for_each_fragment(MAX_PLAINTEXT - 1, |fragment| -> Result {
        seal(&mut sealer, Purpose::Commit, fragment, 0)?;
        fragments += 1;
        Ok(())
    })?;
    assert_eq!(fragments, 17);
    let mut bytes = [0x7a; HEADER_LEN + 2 + TAG_LEN];
    let mut packet = PacketBuf::new(&mut bytes, HEADER_LEN, HEADER_LEN + 1)?;
    assert_eq!(
        sealer.seal(Purpose::Commit, &mut packet, 0),
        Err(RecordError::Reserve)
    );
    seal(&mut sealer, Purpose::EpochKeyUpdate, b"switch", 0)?;
    seal(&mut sealer, Purpose::Close, &[1, 0], 0)?;
    assert_eq!(sealer.sequence, AES_GCM_LIMIT);
    assert_eq!(
        sealer.seal(Purpose::Application, &mut packet, 0),
        Err(RecordError::Exhausted)
    );
    Ok(())
}

#[test]
fn close_retires_keys_and_chacha_sequence_cannot_wrap() -> Result {
    let key = || TrafficKey::derive(Hash::Sha256, Algorithm::ChaCha20Poly1305, &[1; 32]);
    let mut sealer = Sealer::new(key()?, OuterType::Data);
    let mut opener = Opener::new(key()?, OuterType::Data);
    sealer.sequence = u64::MAX - 1;
    opener.sequence = u64::MAX - 1;
    let mut alert = seal(&mut sealer, Purpose::Close, &[1, 0], 5)?;
    assert_eq!(sealer.sequence, u64::MAX);
    assert_eq!(
        opener
            .open(&mut alert)?
            .ok_or("missing close_notify")?
            .content,
        ContentType::Alert
    );
    assert_eq!(opener.sequence, u64::MAX);
    assert_eq!(opener.open(&mut alert), Err(RecordError::Exhausted));
    assert!(sealer.key.is_none());
    Ok(())
}

#[test]
fn insufficient_room_preserves_payload_and_bad_secret_is_refused() -> Result {
    assert!(matches!(
        TrafficKey::derive(Hash::Sha384, Algorithm::Aes256Gcm, &[1; 32]),
        Err(RecordError::Key)
    ));
    let mut sealer = Sealer::new(aes_key()?, OuterType::Data);
    let mut data = *b"payload";
    let mut packet = PacketBuf::new(&mut data, 0, 7)?;
    assert_eq!(
        sealer.seal(Purpose::Application, &mut packet, 0),
        Err(RecordError::NoRoom)
    );
    assert_eq!(packet.bytes(), b"payload");
    assert_eq!(sealer.sequence, 0);
    Ok(())
}
