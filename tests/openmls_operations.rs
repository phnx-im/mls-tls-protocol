// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::error::Error;

use openmls::component::{ComponentType, ComponentsList};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use zeroize::Zeroizing;

const COMPONENT: u16 = 0x8000;
const T_SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const PQ_SUITE: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519;
const SUPPORTED_FORMATS: u16 = 0xf000;
const REQUIRED_FORMATS: u16 = 0xf001;
const TWO_PARTY_FORMAT: u16 = 0xf002;
const NOT_BEFORE: u64 = 100;
const EXPIRES: u64 = 200;
const TIME: LeafNodeLifetimePolicy = LeafNodeLifetimePolicy::VerifyAt(NOT_BEFORE);

type ProbeResult<T> = Result<T, Box<dyn Error>>;

struct Party {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    group: MlsGroup,
}

impl Party {
    fn start_commit(&mut self) -> ProbeResult<Vec<u8>> {
        self.start_commit_with_psk(None)
    }

    fn start_commit_with_psk(&mut self, psk: Option<PreSharedKeyId>) -> ProbeResult<Vec<u8>> {
        let commit = self
            .group
            .commit_builder()
            .leaf_node_lifetime_policy(TIME)
            .force_self_update(true)
            .propose_psks(psk)?
            .load_psks(self.provider.storage())?
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &self.signer,
                |_| true,
            )?
            .stage_commit(&self.provider)?
            .into_commit();
        Ok(commit.to_bytes()?)
    }

    fn current_export(&mut self) -> ProbeResult<ExportedSecret<GroupSafeExport>> {
        Ok(self.group.safe_export_secret(
            self.provider.crypto(),
            self.provider.storage(),
            COMPONENT,
        )?)
    }

    fn pending_export(&mut self) -> ProbeResult<ExportedSecret<PendingSafeExport>> {
        Ok(self.group.safe_export_secret_from_pending(
            self.provider.crypto(),
            self.provider.storage(),
            COMPONENT,
        )?)
    }

    fn receive_commit(&mut self, wire: &[u8]) -> ProbeResult<Box<StagedCommit>> {
        stage_commit(&mut self.group, &self.provider, wire, None)
    }

    fn reload(&mut self) -> ProbeResult<()> {
        self.group = MlsGroup::load(self.provider.storage(), self.group.group_id())?
            .ok_or("group missing after reload")?;
        Ok(())
    }
}

fn stage_commit(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    wire: &[u8],
    psk: Option<&PreSharedKeyId>,
) -> ProbeResult<Box<StagedCommit>> {
    let message = MlsMessageIn::tls_deserialize_exact(wire)?.try_into_protocol_message()?;
    assert_eq!(message.wire_format(), WireFormat::PublicMessage);
    let message = group.process_message_with_lifetime_policy(provider, message, TIME)?;
    assert!(message.aad().is_empty());
    let ProcessedMessageContent::StagedCommitMessage(commit) = message.into_content() else {
        return Err("expected a staged Commit".into());
    };

    assert_eq!(
        commit.queued_proposals().count(),
        usize::from(psk.is_some())
    );
    if let Some(psk) = psk {
        let proposal = commit
            .psk_proposals()
            .next()
            .ok_or("missing application PSK")?;
        assert_eq!(proposal.psk_proposal().psk(), psk);
    }
    assert!(commit.update_path_leaf_node().is_some());
    Ok(commit)
}

struct InitialPsk<'a> {
    id: &'a PreSharedKeyId,
    initiator: &'a [u8],
    responder: &'a [u8],
}

fn credential(name: &[u8], signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(name.to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    }
}

fn dictionary() -> ProbeResult<Extension> {
    let mut dict = AppDataDictionary::new();
    dict.insert(
        ComponentType::AppComponents.into(),
        ComponentsList::new(vec![COMPONENT]).tls_serialize_detached()?,
    );
    Ok(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dict),
    ))
}

fn formats(extension_type: u16) -> ProbeResult<Extension> {
    Ok(Extension::Unknown(
        extension_type,
        UnknownExtension(vec![TWO_PARTY_FORMAT].tls_serialize_detached()?),
    ))
}

fn start_pair(suite: Ciphersuite, psk: Option<InitialPsk<'_>>) -> ProbeResult<(Party, Party)> {
    let initiator_provider = OpenMlsRustCrypto::default();
    let responder_provider = OpenMlsRustCrypto::default();
    let initiator_signer = SignatureKeyPair::new(suite.signature_algorithm())?;
    let responder_signer = SignatureKeyPair::new(suite.signature_algorithm())?;
    let leaf_extensions = Extensions::from_vec(vec![dictionary()?, formats(SUPPORTED_FORMATS)?])?;
    let capabilities = Capabilities::builder()
        .ciphersuites(vec![suite])
        .credentials(vec![CredentialType::Basic])
        .extensions(vec![
            ExtensionType::AppDataDictionary,
            ExtensionType::Unknown(SUPPORTED_FORMATS),
            ExtensionType::Unknown(REQUIRED_FORMATS),
        ])
        .build();

    let key_package = KeyPackage::builder()
        .key_package_lifetime(Lifetime::init(NOT_BEFORE, EXPIRES))
        .leaf_node_capabilities(capabilities.clone())
        .leaf_node_extensions(leaf_extensions.clone())
        .build(
            suite,
            &initiator_provider,
            &initiator_signer,
            credential(b"initiator", &initiator_signer),
        )?;
    let key_package =
        KeyPackageIn::tls_deserialize_exact(key_package.key_package().tls_serialize_detached()?)?;
    for time in [NOT_BEFORE - 1, EXPIRES] {
        assert!(key_package
            .clone()
            .validate_with_lifetime_policy(
                responder_provider.crypto(),
                ProtocolVersion::Mls10,
                LeafNodeLifetimePolicy::VerifyAt(time),
            )
            .is_err());
    }
    let key_package = key_package.validate_with_lifetime_policy(
        responder_provider.crypto(),
        ProtocolVersion::Mls10,
        TIME,
    )?;

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(suite)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(0)
        .use_ratchet_tree_extension(true)
        .lifetime(Lifetime::init(NOT_BEFORE, EXPIRES))
        .capabilities(capabilities)
        .with_leaf_node_extensions(leaf_extensions)?
        .with_group_context_extensions(Extensions::from_vec(vec![
            dictionary()?,
            formats(REQUIRED_FORMATS)?,
        ])?)
        .build();
    let mut responder_group = MlsGroup::new(
        &responder_provider,
        &responder_signer,
        &config,
        credential(b"responder", &responder_signer),
    )?;
    if let Some(psk) = &psk {
        psk.id.store(&initiator_provider, psk.initiator)?;
        psk.id.store(&responder_provider, psk.responder)?;
    }
    let welcome = responder_group
        .commit_builder()
        .propose_adds([key_package])
        .propose_psks(psk.as_ref().map(|psk| psk.id.clone()))?
        .leaf_node_lifetime_policy(TIME)
        .load_psks(responder_provider.storage())?
        .build(
            responder_provider.rand(),
            responder_provider.crypto(),
            &responder_signer,
            |_| true,
        )?
        .stage_commit(&responder_provider)?
        .into_welcome()
        .ok_or("missing Welcome")?;
    if let Some(psk) = &psk {
        delete_import(responder_provider.storage(), psk.id)?;
    }
    responder_group.merge_pending_commit(&responder_provider)?;

    let join = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(0)
        .build();
    let staged = StagedWelcome::build_from_welcome(&initiator_provider, &join, welcome)?
        .leaf_node_lifetime_policy(TIME);
    let expected = psk
        .as_ref()
        .map_or(&[][..], |psk| std::slice::from_ref(psk.id));
    assert_eq!(staged.processed_welcome().psks(), expected);
    let staged = staged.build()?;
    if let Some(psk) = psk {
        delete_import(initiator_provider.storage(), psk.id)?;
    }
    let initiator_group = staged.into_group(&initiator_provider)?;
    assert_eq!(initiator_group.members().count(), 2);
    assert_eq!(initiator_group.epoch().as_u64(), 1);
    assert_eq!(
        initiator_group.extensions().unknown(REQUIRED_FORMATS),
        Some(&UnknownExtension(vec![0x02, 0xf0, 0x02]))
    );
    assert!(initiator_group.extensions().app_data_dictionary().is_some());

    Ok((
        Party {
            provider: initiator_provider,
            signer: initiator_signer,
            group: initiator_group,
        },
        Party {
            provider: responder_provider,
            signer: responder_signer,
            group: responder_group,
        },
    ))
}

#[test]
fn current_pending_and_staged_exports_are_consumed_across_reload() -> ProbeResult<()> {
    for suite in [
        T_SUITE,
        PQ_SUITE,
        Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
    ] {
        let (mut initiator, mut responder) = start_pair(suite, None)?;
        assert_eq!(initiator.current_export()?, responder.current_export()?);
        initiator.reload()?;
        assert!(initiator.current_export().is_err());

        let wire = initiator.start_commit()?;
        let pending = initiator.pending_export()?;
        initiator.reload()?;
        assert!(initiator.pending_export().is_err());

        let mut staged = responder.receive_commit(&wire)?;
        let staged_export = staged.safe_export_secret(responder.provider.crypto(), COMPONENT)?;
        assert_eq!(pending, staged_export);
        assert!(staged
            .safe_export_secret(responder.provider.crypto(), COMPONENT)
            .is_err());
        responder
            .group
            .merge_staged_commit(&responder.provider, *staged)?;
        initiator.group.merge_pending_commit(&initiator.provider)?;
        for party in [&mut initiator, &mut responder] {
            party.reload()?;
            assert_eq!(party.group.epoch().as_u64(), 2);
            assert!(party.current_export().is_err());
        }
    }
    Ok(())
}

#[test]
fn invalid_and_colliding_commits_leave_pending_state_available() -> ProbeResult<()> {
    let (mut initiator, mut responder) = start_pair(T_SUITE, None)?;
    initiator.current_export()?;
    responder.current_export()?;
    let original = responder.start_commit()?;
    let displaced = responder.pending_export()?;

    let winning = initiator.start_commit()?;
    let winning_export = initiator.pending_export()?;
    let mut damaged = winning.clone();
    *damaged.last_mut().ok_or("empty Commit")? ^= 1;
    assert!(responder.receive_commit(&damaged).is_err());
    responder.reload()?;
    assert_eq!(responder.group.epoch().as_u64(), 1);
    assert!(responder.group.pending_commit().is_some());
    assert!(responder.pending_export().is_err());

    let mut staged = responder.receive_commit(&winning)?;
    let staged_export = staged.safe_export_secret(responder.provider.crypto(), COMPONENT)?;
    assert_eq!(staged_export, winning_export);
    assert_ne!(staged_export, displaced);
    assert!(responder.group.pending_commit().is_some());

    drop(staged);
    responder
        .group
        .clear_pending_commit(responder.provider.storage())?;
    responder.reload()?;
    assert!(responder.group.pending_commit().is_none());
    let replacement = responder.start_commit()?;
    assert_ne!(original, replacement);
    let replacement_export = responder.pending_export()?;
    assert_ne!(displaced, replacement_export);
    let mut staged = initiator.receive_commit(&replacement)?;
    assert_eq!(
        replacement_export,
        staged.safe_export_secret(initiator.provider.crypto(), COMPONENT)?
    );
    Ok(())
}

#[test]
fn applying_a_staged_commit_to_a_snapshot_keeps_the_live_group_unchanged() -> ProbeResult<()> {
    let (mut initiator, mut responder) = start_pair(T_SUITE, None)?;
    let wire = initiator.start_commit()?;

    let (worker, mut staged_group) = snapshot_group(&responder)?;
    let commit = stage_commit(&mut staged_group, &worker, &wire, None)?;
    staged_group.merge_staged_commit(&worker, *commit)?;
    assert_eq!(staged_group.epoch().as_u64(), 2);
    responder.reload()?;
    assert_eq!(responder.group.epoch().as_u64(), 1);
    Ok(())
}

fn snapshot_group(party: &Party) -> ProbeResult<(OpenMlsRustCrypto, MlsGroup)> {
    // MemoryStorage is a probe fixture. Production snapshots need zeroizing storage.
    let worker = OpenMlsRustCrypto::default();
    let live = party
        .provider
        .storage()
        .values
        .read()
        .map_err(|_| "live store lock")?;
    worker
        .storage()
        .values
        .write()
        .map_err(|_| "worker store lock")?
        .clone_from(&live);
    let group = MlsGroup::load(worker.storage(), party.group.group_id())?
        .ok_or("missing group in snapshot")?;
    Ok((worker, group))
}

fn delete_import(
    storage: &impl openmls::storage::StorageProvider,
    psk: &PreSharedKeyId,
) -> ProbeResult<()> {
    storage
        .delete_psk(psk.psk())
        .map_err(|error| format!("delete imported PSK: {error}"))?;
    Ok(())
}

fn derive_apq_inputs(
    crypto: &impl OpenMlsCrypto,
    exported: &[u8],
    nonce: Vec<u8>,
) -> ProbeResult<(PreSharedKeyId, SecretVLBytes)> {
    let hash_len = PQ_SUITE.hash_length();
    let derive = |label: &[u8]| -> ProbeResult<SecretVLBytes> {
        let mut info = u16::try_from(hash_len)?.to_be_bytes().to_vec();
        info.push(u8::try_from(label.len())?);
        info.extend_from_slice(label);
        info.push(0);
        Ok(crypto.hkdf_expand(PQ_SUITE.hash_algorithm(), exported, &info, hash_len)?)
    };
    let id = derive(b"MLS 1.0 psk_id")?;
    let psk = derive(b"MLS 1.0 psk")?;
    Ok((
        PreSharedKeyId::application(COMPONENT, id.as_slice().to_vec(), nonce),
        psk,
    ))
}

#[test]
fn application_psk_id_matches_the_extensions_draft_encoding() -> ProbeResult<()> {
    let nonce = [0x37; 32];
    let mut expected = vec![0x03, 0x80, 0x00, 0x02, 0xfa, 0x08, 0x20];
    expected.extend_from_slice(&nonce);
    let psk = PreSharedKeyId::application(COMPONENT, vec![0xfa, 0x08], nonce.to_vec());
    assert_eq!(psk.tls_serialize_detached()?, expected);
    assert_eq!(PreSharedKeyId::tls_deserialize_exact(&expected)?, psk);
    Ok(())
}

#[test]
fn apq_imports_a_welcome_psk_and_discards_both_halves_after_failed_t_validation() -> ProbeResult<()>
{
    let (mut pq_initiator, mut pq_responder) = start_pair(PQ_SUITE, None)?;
    let nonce = vec![0x4a; T_SUITE.hash_length()];
    let responder_epoch = pq_responder.current_export()?;
    let (initial, responder_secret) = derive_apq_inputs(
        pq_responder.provider.crypto(),
        responder_epoch.as_slice(),
        nonce.clone(),
    )?;
    drop(responder_epoch);
    let initiator_epoch = pq_initiator.current_export()?;
    let (expected, initiator_secret) = derive_apq_inputs(
        pq_initiator.provider.crypto(),
        initiator_epoch.as_slice(),
        nonce,
    )?;
    drop(initiator_epoch);
    assert_eq!(initial, expected);
    let (mut t_initiator, mut t_responder) = start_pair(
        T_SUITE,
        Some(InitialPsk {
            id: &initial,
            initiator: initiator_secret.as_slice(),
            responder: responder_secret.as_slice(),
        }),
    )?;
    drop((initiator_secret, responder_secret));
    assert_eq!(t_responder.current_export()?, t_initiator.current_export()?);

    let next_nonce = vec![0x7f; T_SUITE.hash_length()];
    let pq_commit = pq_initiator.start_commit()?;
    let pq_pending = pq_initiator.pending_export()?;
    let (psk, secret) = derive_apq_inputs(
        pq_initiator.provider.crypto(),
        pq_pending.as_slice(),
        next_nonce.clone(),
    )?;
    drop(pq_pending);
    psk.store(&t_initiator.provider, secret.as_slice())?;
    let t_commit = t_initiator.start_commit_with_psk(Some(psk.clone()))?;
    delete_import(t_initiator.provider.storage(), &psk)?;
    drop(secret);
    let t_pending = t_initiator.pending_export()?;

    let (pq_worker, mut pq_snapshot) = snapshot_group(&pq_responder)?;
    let (t_worker, mut t_snapshot) = snapshot_group(&t_responder)?;
    let mut staged = stage_commit(&mut pq_snapshot, &pq_worker, &pq_commit, None)?;
    let staged_export = staged.safe_export_secret(pq_worker.crypto(), COMPONENT)?;
    let (expected, secret) =
        derive_apq_inputs(pq_worker.crypto(), staged_export.as_slice(), next_nonce)?;
    drop(staged_export);
    assert_eq!(psk, expected);
    pq_snapshot.merge_staged_commit(&pq_worker, *staged)?;
    assert_eq!(pq_snapshot.epoch().as_u64(), 2);

    let mut wrong_secret = Zeroizing::new(secret.as_slice().to_vec());
    wrong_secret[0] ^= 1;
    psk.store(&t_worker, &wrong_secret)?;
    assert!(stage_commit(&mut t_snapshot, &t_worker, &t_commit, Some(&psk)).is_err());
    delete_import(t_worker.storage(), &psk)?;
    drop(wrong_secret);
    drop((pq_worker, pq_snapshot, t_worker, t_snapshot));

    for responder in [&mut pq_responder, &mut t_responder] {
        responder.reload()?;
        assert_eq!(responder.group.epoch().as_u64(), 1);
        assert!(responder.group.pending_commit().is_none());
    }
    assert!(t_responder.receive_commit(&t_commit).is_err());

    let (t_worker, mut t_snapshot) = snapshot_group(&t_responder)?;
    psk.store(&t_worker, secret.as_slice())?;
    drop(secret);
    let mut t_staged = stage_commit(&mut t_snapshot, &t_worker, &t_commit, Some(&psk))?;
    let t_export = t_staged.safe_export_secret(t_worker.crypto(), COMPONENT)?;
    delete_import(t_worker.storage(), &psk)?;
    assert_eq!(t_export, t_pending);
    t_snapshot.merge_staged_commit(&t_worker, *t_staged)?;
    assert_eq!(t_snapshot.epoch().as_u64(), 2);
    Ok(())
}
