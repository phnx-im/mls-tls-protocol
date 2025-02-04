// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::Utc;
use openmls::{
    group::{MlsGroup, MlsGroupJoinConfig, StagedWelcome},
    prelude::{Ciphersuite, CredentialWithKey, KeyPackage, OpenMlsCrypto},
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use pkcs8::der::Encode;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use uuid::Uuid;

use crate::authentication::leaf_certificate::LeafCertificateSigner;

use super::{
    leaf_certificate::LEAF_SIGNATURE_SCHEME,
    root_certificate::{RootCertificateSigner, ROOT_SIGNATURE_SCHEME},
    *,
};

#[test]
fn generate_sign_and_verify_certificate() {
    let seed = [1u8; SEED_LEN];
    let crypto_provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let root_signer =
        RootCertificateSigner::new_with_time_and_rng(Utc::now(), &mut rng, "example.com").unwrap();

    let identifier = Uuid::new_v4();

    let leaf_signer = root_signer
        .issue_new_leaf_with_time_and_rng(identifier, Utc::now(), &mut rng)
        .unwrap();

    crypto_provider
        .crypto()
        .verify_signature(
            ROOT_SIGNATURE_SCHEME,
            leaf_signer
                .certificate
                .tbs_certificate
                .to_der()
                .unwrap()
                .as_slice(),
            root_signer
                .certificate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
            leaf_signer.certificate.signature.as_bytes().unwrap(),
        )
        .unwrap();

    let payload = b"Hello, world!";

    let signature_bytes = leaf_signer.sign(payload).unwrap();

    let credential_with_key = leaf_signer.mls_credential_with_key().unwrap();
    crypto_provider
        .crypto()
        .verify_signature(
            LEAF_SIGNATURE_SCHEME,
            payload.as_slice(),
            credential_with_key.signature_key.as_slice(),
            &signature_bytes,
        )
        .unwrap();

    // Test serialization
    let serialized_leaf_signer = leaf_signer.serialize().unwrap();
    let deserialized_leaf_signer =
        LeafCertificateSigner::deserialize(&serialized_leaf_signer).unwrap();

    // Sign with the deserialized signer and verify with the original one

    let signature_bytes = deserialized_leaf_signer.sign(payload).unwrap();
    crypto_provider
        .crypto()
        .verify_signature(
            LEAF_SIGNATURE_SCHEME,
            payload.as_slice(),
            credential_with_key.signature_key.as_slice(),
            &signature_bytes,
        )
        .unwrap();

    // Sign with the original signer and verify with the deserialized one
    let signature_bytes = leaf_signer.sign(payload).unwrap();
    crypto_provider
        .crypto()
        .verify_signature(
            LEAF_SIGNATURE_SCHEME,
            payload.as_slice(),
            deserialized_leaf_signer
                .certificate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
            &signature_bytes,
        )
        .unwrap();
}

#[test]
fn deterministic_certificate_generation() {
    let seed = [1u8; SEED_LEN];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let cert1 =
        RootCertificateSigner::new_with_time_and_rng(Utc::now(), &mut rng, "example.com").unwrap();

    let mut rng = ChaCha20Rng::from_seed(seed);

    let cert2 =
        RootCertificateSigner::new_with_time_and_rng(Utc::now(), &mut rng, "example.com").unwrap();

    assert_eq!(cert1.certificate, cert2.certificate);
}

#[test]
fn certificates_in_openmls() {
    // RNG based on seed shared by client and server
    let rng = &mut ChaCha20Rng::from_seed([1u8; 32]);
    let now = Utc::now();

    let ciphersuite = Ciphersuite::MLS_256_XWING_AES256GCM_SHA512_P384;

    let root_certificate =
        RootCertificateSigner::new_with_time_and_rng(now, rng, "server").unwrap();
    let server_signer = root_certificate
        .issue_new_leaf_with_time_and_rng("server_leaf", now, rng)
        .unwrap();
    let client_signer = root_certificate
        .issue_new_leaf_with_time_and_rng("client", now, rng)
        .unwrap();

    let provider = OpenMlsRustCrypto::default();

    // Generate client KeyPackage
    let key_package_bundle = KeyPackage::builder()
        .build(
            ciphersuite,
            &provider,
            &client_signer,
            client_signer.mls_credential_with_key().unwrap(),
        )
        .unwrap();

    // Create a group
    let mut server_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build(
            &provider,
            &server_signer,
            server_signer.mls_credential_with_key().unwrap(),
        )
        .unwrap();

    // Server verifies the client's credential
    let client_credential_with_key = CredentialWithKey {
        credential: key_package_bundle
            .key_package()
            .leaf_node()
            .credential()
            .clone(),
        signature_key: key_package_bundle
            .key_package()
            .leaf_node()
            .signature_key()
            .clone(),
    };
    root_certificate
        .certificate
        .verify_openmls_credential(&client_credential_with_key, None)
        .unwrap();

    // Add the client to the group
    let (_commit, welcome, _group_info) = server_group
        .add_members(
            &provider,
            &server_signer,
            &[key_package_bundle.key_package().clone()],
        )
        .unwrap();

    let mls_group_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let staged_welcome = StagedWelcome::new_from_welcome(
        &provider,
        &mls_group_config,
        welcome.into_welcome().unwrap(),
        None,
    )
    .unwrap();

    // Client verifies the server's credential
    let server_credential_with_key = CredentialWithKey {
        credential: staged_welcome
            .welcome_sender()
            .unwrap()
            .credential()
            .clone(),
        signature_key: staged_welcome
            .welcome_sender()
            .unwrap()
            .signature_key()
            .clone(),
    };
    root_certificate
        .certificate
        .verify_openmls_credential(&server_credential_with_key, Some("server_leaf"))
        .unwrap();

    let _client_group = staged_welcome.into_group(&provider).unwrap();
}
