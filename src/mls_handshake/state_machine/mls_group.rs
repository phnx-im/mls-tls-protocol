// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::prelude::{KeyPackageIn, MlsMessageOut};
use serde::{Deserialize, Serialize};

use crate::handshake::ClientIdentity;

use super::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(in crate::mls_handshake) struct MlsSession {
    pub(in crate::mls_handshake) group_id: GroupId,
    pub(in crate::mls_handshake) epoch: u64,
}

impl MlsSession {
    pub(super) fn new(group_id: GroupId, epoch: u64) -> Self {
        Self { group_id, epoch }
    }

    pub(super) fn create_server_session(
        connection: &Connection,
        leaf_signer: &LeafCertificateSigner,
        key_package_in: KeyPackageIn,
        root_certificate: &RootCertificate,
    ) -> Result<(Self, TrafficSecrets, ClientIdentity, MlsMessageOut), HandshakeError> {
        let provider = Provider::from(connection);
        let key_package = key_package_in
            .validate(provider.crypto(), openmls::prelude::ProtocolVersion::Mls10)
            .map_err(|e| HandshakeError::ClientHelloError(e.into()))?;

        // Verify the client certificate with the root certificate
        let credential_with_key = CredentialWithKey {
            credential: key_package.leaf_node().credential().clone(),
            signature_key: key_package.leaf_node().signature_key().clone(),
        };
        root_certificate.verify_openmls_credential(&credential_with_key, None)?;

        let client_identity_bytes = credential_with_key.signature_key.as_slice().to_vec();
        let client_identity = ClientIdentity(client_identity_bytes);

        // Create a new group with the server as the only member
        let group_id = GroupId::from_slice(Uuid::new_v4().as_bytes());
        let mut server_group = MlsGroup::builder()
            .with_group_id(group_id)
            .with_capabilities(capabilities())
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(
                &provider,
                leaf_signer,
                leaf_signer.mls_credential_with_key()?,
            )
            .map_err(|e| HandshakeError::ClientHelloError(e.into()))?;
        // Add client to the group
        let (_commit, welcome, _group_info) = server_group
            .add_members(&provider, leaf_signer, &[key_package.clone()])
            .map_err(|e| HandshakeError::ClientHelloError(e.into()))?;
        server_group
            .merge_pending_commit(&provider)
            .map_err(|e| HandshakeError::ClientHelloError(e.into()))?;

        let traffic_secrets = export_traffic_secrets(&provider, &server_group)?;

        let mls_session = Self {
            group_id: server_group.group_id().clone(),
            epoch: server_group.epoch().as_u64(),
        };

        Ok((mls_session, traffic_secrets, client_identity, welcome))
    }

    pub(super) fn update(
        &self,
        connection: &Connection,
        leaf_signer: &LeafCertificateSigner,
    ) -> Result<MlsMessageOut, HandshakeError> {
        let provider = Provider::from(connection);

        let mut group = MlsGroup::load(provider.storage(), &self.group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        let update = group
            .self_update(
                &provider,
                leaf_signer,
                LeafNodeParameters::builder()
                    .with_capabilities(capabilities())
                    .build(),
            )
            .map_err(|e| HandshakeError::ResumptionError(e.into()))?;

        Ok(update.into_commit())
    }

    pub(super) fn merge_update(
        &mut self,
        connection: &Connection,
    ) -> Result<TrafficSecrets, HandshakeError> {
        let provider = Provider::from(connection);
        let mut group = MlsGroup::load(provider.storage(), &self.group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        group
            .merge_pending_commit(&provider)
            .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;

        self.epoch = group.epoch().as_u64();

        export_traffic_secrets(&provider, &group)
    }

    pub(super) fn process_mls_update(
        connection: &Connection,
        mls_message: MlsMessageIn,
        drop_pending_commit: bool,
    ) -> Result<(TrafficSecrets, MlsSession, ClientIdentity), HandshakeError> {
        let MlsMessageBodyIn::PrivateMessage(private_message) = mls_message.extract() else {
            return Err(HandshakeError::UnexpectedMessage {
                expected: "PrivateMessage",
                actual: "Unknown",
            });
        };

        let provider = Provider::from(connection);

        let protocol_message = ProtocolMessage::PrivateMessage(private_message);

        let mut group = MlsGroup::load(provider.storage(), protocol_message.group_id())
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        let message_epoch = protocol_message.epoch();
        let group_epoch = group.epoch();
        let next_group_epoch = (group_epoch.as_u64() + 1).into();

        if message_epoch == next_group_epoch && group.pending_commit().is_some() {
            group
                .merge_pending_commit(&provider)
                .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;
        } else if drop_pending_commit {
            group
                .clear_pending_commit(provider.storage())
                .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;
        }

        let processed_message = group
            .process_message(&provider, protocol_message)
            .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;

        // Validation

        // Can't be an external commit
        if !matches!(processed_message.sender(), Sender::Member(_)) {
            return Err(HandshakeError::ValidationError(
                "Resumption message must be from a member".to_string(),
            ));
        };

        let sender_credential = processed_message.credential().clone();

        // Resumption must be a commit
        let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            processed_message.into_content()
        else {
            return Err(HandshakeError::ValidationError(
                "Resumption message must contain a commit".to_string(),
            ));
        };

        // Commit must contain a path
        let Some(leaf_node) = staged_commit.update_path_leaf_node() else {
            return Err(HandshakeError::ValidationError(
                "Resumption commit must contain a path".to_string(),
            ));
        };

        let client_identity_bytes = leaf_node.signature_key().as_slice().to_vec();
        let client_identity = ClientIdentity(client_identity_bytes);

        // Credential can't have changed
        if &sender_credential != leaf_node.credential() {
            return Err(HandshakeError::ValidationError(
                "Resumption commit must contain the same credential".to_string(),
            ));
        }

        // Commit can't contain any proposals
        if staged_commit.queued_proposals().count() > 0 {
            return Err(HandshakeError::ValidationError(
                "Resumption commit must not contain any proposals".to_string(),
            ));
        }

        group
            .merge_staged_commit(&provider, *staged_commit)
            .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;

        let traffic_secrets = export_traffic_secrets(&provider, &group)?;

        let mls_session = Self {
            group_id: group.group_id().clone(),
            epoch: group.epoch().as_u64(),
        };

        Ok((traffic_secrets, mls_session, client_identity))
    }

    pub(super) fn process_epoch_key_update(
        &self,
        connection: &Connection,
        confirmation: EpochKeyUpdate,
    ) -> Result<(), HandshakeError> {
        let provider = Provider::from(connection);
        let group = MlsGroup::load(provider.storage(), &self.group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        let own_epoch = group.epoch().as_u64();

        if own_epoch != confirmation.epoch {
            return Err(HandshakeError::ValidationError(
                "Epoch mismatch".to_string(),
            ));
        }

        Ok(())
    }

    pub(super) fn create_epoch_key_update(
        &self,
        connection: &Connection,
    ) -> Result<EpochKeyUpdate, HandshakeError> {
        let provider = Provider::from(connection);
        let group = MlsGroup::load(provider.storage(), &self.group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        let own_epoch = group.epoch().as_u64();

        let epoch_key_update = EpochKeyUpdate { epoch: own_epoch };

        Ok(epoch_key_update)
    }

    pub(in crate::mls_handshake) fn delete(
        &self,
        connection: &Connection,
    ) -> Result<(), HandshakeError> {
        let provider = Provider::from(connection);
        let mut group = MlsGroup::load(provider.storage(), &self.group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        group.delete(provider.storage())?;

        Ok(())
    }
}
