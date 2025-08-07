// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use hpqmls::{
    authentication::{HpqCredentialWithKey, HpqSignatureKeyPair},
    messages::{HpqKeyPackageIn, HpqMlsMessageIn, HpqMlsMessageOut},
    HpqGroupId, HpqMlsGroup,
};
use openmls::prelude::BasicCredential;
use serde::{Deserialize, Serialize};

use crate::handshake::ClientIdentity;

use super::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(in crate::mls_handshake) struct MlsSession {
    pub(in crate::mls_handshake) group_id: HpqGroupId,
    pub(in crate::mls_handshake) epoch: u64,
}

impl MlsSession {
    pub(super) fn new(group_id: HpqGroupId, epoch: u64) -> Self {
        Self { group_id, epoch }
    }

    pub(super) fn create_server_session(
        connection: &Connection,
        leaf_signer: &HpqSignatureKeyPair,
        key_package_in: HpqKeyPackageIn,
    ) -> Result<(Self, TrafficSecrets, ClientIdentity, HpqMlsMessageOut), HandshakeError> {
        let provider = Provider::from(connection);
        let key_package = key_package_in
            .validate(provider.crypto())
            .map_err(|e| HandshakeError::ClientHelloError(e.into()))?;

        // Get the client's identity
        let t_client_basic_credential =
            BasicCredential::try_from(key_package.t_key_package.leaf_node().credential().clone())
                .map_err(|_| VerificationError::WrongCredentialType)?;
        let client_identity = ClientIdentity(t_client_basic_credential.identity().to_vec());

        // TODO: Check that client identity is the same in both groups?

        // Identity is irrelevant, as clients directly verify the server's
        // verifying key.
        let credential_with_key = HpqCredentialWithKey::new(b"server", leaf_signer);

        // Create a new group with the server as the only member
        let t_group_id = GroupId::from_slice(Uuid::new_v4().as_bytes());
        let pq_group_id = GroupId::from_slice(Uuid::new_v4().as_bytes());
        let mut server_group = HpqMlsGroup::builder()
            .with_group_ids(t_group_id, pq_group_id)
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(&provider, leaf_signer, credential_with_key)
            .map_err(|e| HandshakeError::ClientHelloError(e.into()))?;
        // Add client to the group
        let bundle = server_group
            .commit_builder()
            .propose_adds(std::iter::once(key_package))
            .finalize(&provider, leaf_signer, |_| true, |_| true)
            .map_err(|e| HandshakeError::ClientHelloError(e.into()))?;
        server_group
            .merge_pending_commit(&provider)
            .map_err(|e| HandshakeError::ClientHelloError(e.into()))?;

        let traffic_secrets = export_traffic_secrets(provider.crypto(), &server_group.t_group)?;

        let mls_session = Self {
            group_id: server_group.group_id(),
            epoch: server_group.t_group.epoch().as_u64(),
        };

        Ok((
            mls_session,
            traffic_secrets,
            client_identity,
            bundle.into_welcome().unwrap().into(),
        ))
    }

    pub(super) fn update(
        &self,
        connection: &Connection,
        leaf_signer: &HpqSignatureKeyPair,
    ) -> Result<HpqMlsMessageOut, HandshakeError> {
        let provider = Provider::from(connection);

        let mut group = HpqMlsGroup::load(provider.storage(), &self.group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        let update = group
            .commit_builder()
            .force_self_update(true)
            .finalize(&provider, leaf_signer, |_| true, |_| true)
            .map_err(|e| HandshakeError::ResumptionError(e.into()))?;

        Ok(update.commit)
    }

    pub(super) fn merge_update(
        &mut self,
        connection: &Connection,
    ) -> Result<TrafficSecrets, HandshakeError> {
        let provider = Provider::from(connection);
        let mut group = HpqMlsGroup::load(provider.storage(), &self.group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        group
            .merge_pending_commit(&provider)
            .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;

        self.epoch = group.t_group.epoch().as_u64();

        export_traffic_secrets(provider.crypto(), &group.t_group)
    }

    pub(super) fn process_mls_update(
        connection: &Connection,
        mls_message: HpqMlsMessageIn,
        drop_pending_commit: bool,
    ) -> Result<(TrafficSecrets, MlsSession, ClientIdentity), HandshakeError> {
        let original_message = mls_message.clone();
        let (
            MlsMessageBodyIn::PrivateMessage(private_t_message),
            Some(MlsMessageBodyIn::PrivateMessage(private_pq_message)),
        ) = (
            mls_message.t_message.extract(),
            mls_message.pq_message.map(|m| m.extract()),
        )
        else {
            return Err(HandshakeError::UnexpectedMessage {
                expected: "PrivateMessage",
                actual: "Unknown",
            });
        };

        let provider = Provider::from(connection);

        let protocol_t_message = ProtocolMessage::PrivateMessage(private_t_message);
        let protocol_pq_message = ProtocolMessage::PrivateMessage(private_pq_message);

        let group_id = HpqGroupId {
            t_group_id: protocol_t_message.group_id().clone(),
            pq_group_id: protocol_pq_message.group_id().clone(),
        };

        let mut group = HpqMlsGroup::load(provider.storage(), &group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        let message_epoch = protocol_t_message.epoch();
        let group_epoch = group.t_group.epoch();
        let next_group_epoch = (group_epoch.as_u64() + 1).into();

        if message_epoch == next_group_epoch && group.t_group.pending_commit().is_some() {
            group
                .merge_pending_commit(&provider)
                .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;
        } else if drop_pending_commit {
            group
                .clear_pending_commits(provider.storage())
                .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;
        }

        println!("Processing message in HPQMLS");
        let processed_message = group
            .process_message(&provider, original_message)
            .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;
        println!("Done processing message in HPQMLS");

        // Validation

        // Can't be an external commit
        if !matches!(processed_message.t_message.sender(), Sender::Member(_)) {
            return Err(HandshakeError::ValidationError(
                "Resumption message must be from a member".to_string(),
            ));
        };

        let sender_credential = processed_message.t_message.credential().clone();

        // Resumption must be a commit
        let staged_commit =
            processed_message
                .into_staged_commit()
                .ok_or(HandshakeError::ValidationError(
                    "Resumption message must be a staged commit".to_string(),
                ))?;

        // Commit must contain a path
        let Some(leaf_node) = staged_commit.t_staged_commit.update_path_leaf_node() else {
            return Err(HandshakeError::ValidationError(
                "Resumption commit must contain a path".to_string(),
            ));
        };

        let basic_credential = BasicCredential::try_from(leaf_node.credential().clone())
            .map_err(|_| VerificationError::WrongCredentialType)?;
        let client_identity = ClientIdentity(basic_credential.identity().to_vec());

        // Credential can't have changed
        if &sender_credential != leaf_node.credential() {
            return Err(HandshakeError::ValidationError(
                "Resumption commit must contain the same credential".to_string(),
            ));
        }

        // Commit can't contain any proposals
        // TODO: This is de-activated while we're using proposals in HPQMLS
        //if staged_commit.t_staged_commit.queued_proposals().count() > 0 {
        //    return Err(HandshakeError::ValidationError(
        //        "Resumption commit must not contain any proposals".to_string(),
        //    ));
        //}

        group
            .merge_staged_commit(&provider, staged_commit)
            .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;

        let traffic_secrets = export_traffic_secrets(provider.crypto(), &group.t_group)?;

        let mls_session = Self {
            group_id: group.group_id().clone(),
            epoch: group.t_group.epoch().as_u64(),
        };

        Ok((traffic_secrets, mls_session, client_identity))
    }

    pub(super) fn process_epoch_key_update(
        &self,
        connection: &Connection,
        confirmation: EpochKeyUpdate,
    ) -> Result<(), HandshakeError> {
        let provider = Provider::from(connection);
        let group = HpqMlsGroup::load(provider.storage(), &self.group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        let own_epoch = group.t_group.epoch().as_u64();

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
        let group = HpqMlsGroup::load(provider.storage(), &self.group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        let own_epoch = group.t_group.epoch().as_u64();

        let epoch_key_update = EpochKeyUpdate { epoch: own_epoch };

        Ok(epoch_key_update)
    }

    pub(in crate::mls_handshake) fn delete(
        &self,
        connection: &Connection,
    ) -> Result<(), HandshakeError> {
        let provider = Provider::from(connection);
        let mut group = HpqMlsGroup::load(provider.storage(), &self.group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        group.delete(provider.storage())?;

        Ok(())
    }
}
