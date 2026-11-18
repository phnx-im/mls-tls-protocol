// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::error::Error;

use openmls::component::{ComponentType, ComponentsList};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

const COMPONENT: u16 = 0x8000;
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
        let commit = self
            .group
            .commit_builder()
            .leaf_node_lifetime_policy(TIME)
            .force_self_update(true)
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
        let message = MlsMessageIn::tls_deserialize_exact(wire)?.try_into_protocol_message()?;
        assert_eq!(message.wire_format(), WireFormat::PublicMessage);
        let message =
            self.group
                .process_message_with_lifetime_policy(&self.provider, message, TIME)?;
        assert!(message.aad().is_empty());
        let ProcessedMessageContent::StagedCommitMessage(commit) = message.into_content() else {
            return Err("expected a staged Commit".into());
        };
        assert!(commit.queued_proposals().next().is_none());
        assert!(commit.update_path_leaf_node().is_some());
        Ok(commit)
    }

    fn reload(&mut self) -> ProbeResult<()> {
        self.group = MlsGroup::load(self.provider.storage(), self.group.group_id())?
            .ok_or("group missing after reload")?;
        Ok(())
    }
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

fn start_pair(suite: Ciphersuite) -> ProbeResult<(Party, Party)> {
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
    let welcome = responder_group
        .commit_builder()
        .propose_adds([key_package])
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
    responder_group.merge_pending_commit(&responder_provider)?;

    let join = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(0)
        .build();
    let initiator_group = StagedWelcome::build_from_welcome(&initiator_provider, &join, welcome)?
        .leaf_node_lifetime_policy(TIME)
        .build()?
        .into_group(&initiator_provider)?;
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
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
        Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
    ] {
        let (mut initiator, mut responder) = start_pair(suite)?;
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
    let (mut initiator, mut responder) =
        start_pair(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)?;
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
    let (mut initiator, mut responder) =
        start_pair(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)?;
    let group_id = responder.group.group_id().clone();
    let wire = initiator.start_commit()?;

    // MemoryStorage is a probe fixture. Production snapshots need zeroizing storage.
    let worker = OpenMlsRustCrypto::default();
    let live = responder
        .provider
        .storage()
        .values
        .read()
        .map_err(|_| "live store lock")?;
    let mut isolated = worker
        .storage()
        .values
        .write()
        .map_err(|_| "isolated store lock")?;
    isolated.clone_from(&live);
    drop(isolated);
    drop(live);

    let mut staged_group =
        MlsGroup::load(worker.storage(), &group_id)?.ok_or("missing group in snapshot")?;
    let input = MlsMessageIn::tls_deserialize_exact(wire)?.try_into_protocol_message()?;
    let msg = staged_group.process_message_with_lifetime_policy(&worker, input, TIME)?;
    let ProcessedMessageContent::StagedCommitMessage(commit) = msg.into_content() else {
        return Err("expected a staged Commit".into());
    };
    staged_group.merge_staged_commit(&worker, *commit)?;
    assert_eq!(staged_group.epoch().as_u64(), 2);
    responder.reload()?;
    assert_eq!(responder.group.epoch().as_u64(), 1);
    Ok(())
}
