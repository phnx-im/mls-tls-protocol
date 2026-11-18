// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::error::Error;

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hpke_rs::{Hpke, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use openmls::prelude::{AeadType, OpenMlsCrypto};
use openmls_rust_crypto::RustCrypto;
use zeroize::Zeroizing;

#[test]
fn x_wing_context_exposes_encapsulation_before_sealing_and_exports_matching_key(
) -> Result<(), Box<dyn Error>> {
    let hpke = || {
        Hpke::<HpkeRustCrypto>::new(
            Mode::Base,
            KemAlgorithm::XWingDraft06,
            KdfAlgorithm::HkdfSha256,
            AeadAlgorithm::Aes128Gcm,
        )
    };
    let mut receiver = hpke();
    let keys = receiver.generate_key_pair()?;
    let info = b"mls-tls pre\0test config";
    let (enc, mut sender) = hpke().setup_sender(keys.public_key(), info, None, None, None)?;

    let mut aad = b"test ClientStart prefix".to_vec();
    aad.extend_from_slice(&enc);
    let ciphertext = sender.seal(&aad, b"test ClientHello")?;
    let sender_key = Zeroizing::new(sender.export(b"mls-tls pre key", 32)?);
    let mut receiver = receiver.setup_receiver(&enc, keys.private_key(), info, None, None, None)?;
    assert_eq!(receiver.open(&aad, &ciphertext)?, b"test ClientHello");
    let receiver_key = Zeroizing::new(receiver.export(b"mls-tls pre key", 32)?);
    assert_eq!(sender_key.as_slice(), receiver_key.as_slice());
    Ok(())
}

#[test]
fn in_place_aead_matches_openmls_for_all_record_algorithms() -> Result<(), Box<dyn Error>> {
    let provider = RustCrypto::default();
    let nonce = [0x31; 12];
    let aad = [0x17, 0x03, 0x03, 0x00, 0x1b];
    let data = *b"test record";
    let mut buffer = data;

    macro_rules! check {
        ($algorithm:expr, $cipher:ty, $key:expr) => {{
            let key = $key;
            let cipher = <$cipher>::new(&key.into());
            let ciphertext = provider.aead_encrypt($algorithm, &key, &data, &nonce, &aad)?;
            let tag = cipher
                .encrypt_inout_detached(&nonce.into(), &aad, (&mut buffer[..]).into())
                .map_err(|_| "in-place encryption failed")?;
            assert_eq!(&ciphertext[..data.len()], buffer.as_slice());
            assert_eq!(&ciphertext[data.len()..], tag.as_slice());
            cipher
                .decrypt_inout_detached(&nonce.into(), &aad, (&mut buffer[..]).into(), &tag)
                .map_err(|_| "in-place decryption failed")?;
            assert_eq!(buffer, data);
        }};
    }

    check!(AeadType::Aes128Gcm, Aes128Gcm, [0x11; 16]);
    check!(AeadType::Aes256Gcm, Aes256Gcm, [0x11; 32]);
    check!(AeadType::ChaCha20Poly1305, ChaCha20Poly1305, [0x11; 32]);
    Ok(())
}
