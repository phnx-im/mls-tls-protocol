// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use hpqmls::{
    authentication::{HpqCredentialWithKey, HpqSignatureKeyPair, HpqSigner as _},
    extension::{HpqMlsInfo, PqtMode},
    messages::{HpqKeyPackageIn, HpqMlsMessageIn, HpqMlsMessageOut},
    HpqGroupId, HpqMlsGroup,
};
use openmls::prelude::{
    BasicCredential, Credential, MlsMessageIn, MlsMessageOut, ProcessedMessageContent,
};
use serde::{Deserialize, Serialize};

use crate::{
    handshake::ClientIdentity,
    mls_handshake::messages::{HandshakeMessageIn, HandshakeMessageOut},
};

use super::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(in crate::mls_handshake) struct MlsSession {
    pub(in crate::mls_handshake) group_id: HpqGroupId,
    pub(in crate::mls_handshake) t_epoch: u64,
    pub(in crate::mls_handshake) pq_epoch: u64,
}

impl MlsSession {
    pub(super) fn new(group_id: HpqGroupId, t_epoch: u64, pq_epoch: u64) -> Self {
        Self {
            group_id,
            t_epoch,
            pq_epoch,
        }
    }

    pub(super) fn create_server_session(
        connection: &Connection,
        t_leaf_signer: &HpqSignatureKeyPair,
        pq_leaf_signer: &HpqSignatureKeyPair,
        key_package_in: HpqKeyPackageIn,
    ) -> Result<
        (
            Self,
            TrafficSecrets,
            ClientIdentity,
            HpqMlsMessageOut,
            PqtMode,
        ),
        HandshakeError,
    > {
        let provider = Provider::from(connection);
        let key_package = key_package_in
            .validate(provider.crypto())
            .map_err(|e| HandshakeError::ClientHelloError(e.into()))?;

        let mode = key_package.mode();
        let leaf_signer = match mode {
            PqtMode::ConfOnly => t_leaf_signer,
            PqtMode::ConfAndAuth => pq_leaf_signer,
        };

        // Get the client's identity
        let t_client_basic_credential =
            BasicCredential::try_from(key_package.t_credential().clone())
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
            .set_mode(mode)
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
            t_epoch: server_group.t_epoch().as_u64(),
            pq_epoch: server_group.pq_epoch().as_u64(),
        };

        Ok((
            mls_session,
            traffic_secrets,
            client_identity,
            bundle.into_welcome().unwrap().into(),
            mode,
        ))
    }

    pub(super) fn update(
        &self,
        connection: &Connection,
        leaf_signer: &HpqSignatureKeyPair,
        pq: bool,
    ) -> Result<HandshakeMessageOut, HandshakeError> {
        let update_type = if pq { "combined PQ" } else { "traditional" };
        tracing::debug!(
            update_type,
            t_epoch = self.t_epoch,
            pq_epoch = self.pq_epoch,
            "MLS session update started",
        );
        let result = if pq {
            self.full_update(connection, leaf_signer).map(Into::into)
        } else {
            self.t_update(connection, leaf_signer).map(Into::into)
        };
        if result.is_ok() {
            tracing::debug!(update_type, "MLS session update completed");
        }
        result
    }

    pub(super) fn full_update(
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
            .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?
            .commit;

        Ok(update)
    }

    pub(super) fn t_update(
        &self,
        connection: &Connection,
        leaf_signer: &HpqSignatureKeyPair,
    ) -> Result<MlsMessageOut, HandshakeError> {
        let provider = Provider::from(connection);

        let mut group = HpqMlsGroup::load(provider.storage(), &self.group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        let update = group
            .t_group
            .commit_builder()
            .force_self_update(true)
            .load_psks(provider.storage())
            .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?
            .build(
                provider.rand(),
                provider.crypto(),
                leaf_signer.t_signer(),
                |_| true,
            )
            .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?
            .stage_commit(&provider)
            .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?
            .into_commit();

        Ok(update)
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

        self.t_epoch = group.t_epoch().as_u64();
        self.pq_epoch = group.pq_epoch().as_u64();

        tracing::debug!(
            t_epoch = self.t_epoch,
            pq_epoch = self.pq_epoch,
            "MLS session merged pending commit"
        );

        export_traffic_secrets(provider.crypto(), &group.t_group)
    }

    pub(super) fn process_t_update(
        connection: &Connection,
        mls_message: MlsMessageIn,
        drop_pending_commit: bool,
    ) -> Result<(TrafficSecrets, MlsSession, ClientIdentity, PqtMode), HandshakeError> {
        let provider = &Provider::from(connection);
        let protocol_message = ProtocolMessage::try_from(mls_message)
            .map_err(|e| HandshakeError::ValidationError(format!("Invalid message: {e}")))?;
        let group_id = protocol_message.group_id();
        let mut t_group = MlsGroup::load(provider.storage(), group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        let message_epoch = protocol_message.epoch();
        let group_epoch = t_group.epoch();
        let next_group_epoch = (group_epoch.as_u64() + 1).into();

        let hpq_info = HpqMlsInfo::from_extensions(t_group.extensions())?.ok_or(
            HandshakeError::ValidationError("Missing HPQMLS extension".to_string()),
        )?;

        // Load the corresponding PQ group to potentially merge or clear pending commits
        let mut pq_group = MlsGroup::load(provider.storage(), &hpq_info.pq_session_group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        if message_epoch == next_group_epoch && t_group.pending_commit().is_some() {
            t_group
                .merge_pending_commit(provider)
                .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;
            pq_group
                .merge_pending_commit(provider)
                .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;
        } else if drop_pending_commit {
            t_group
                .clear_pending_commit(provider.storage())
                .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;
            pq_group
                .clear_pending_commit(provider.storage())
                .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;
        }

        let processed_message = t_group
            .process_message(provider, protocol_message)
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
                "Resumption message must be a staged commit".to_string(),
            ));
        };

        // Commit must contain a path
        let Some(leaf_node) = staged_commit.update_path_leaf_node() else {
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

        t_group
            .merge_staged_commit(provider, *staged_commit)
            .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;

        let traffic_secrets = export_traffic_secrets(provider.crypto(), &t_group)?;

        let mls_session = MlsSession {
            group_id: hpq_info.group_id().clone(),
            t_epoch: t_group.epoch().as_u64(),
            pq_epoch: hpq_info.pq_epoch.as_u64(),
        };

        Ok((traffic_secrets, mls_session, client_identity, hpq_info.mode))
    }

    pub(super) fn process_full_update(
        connection: &Connection,
        mls_message: HpqMlsMessageIn,
        drop_pending_commit: bool,
    ) -> Result<(TrafficSecrets, MlsSession, ClientIdentity, PqtMode), HandshakeError> {
        let provider = &Provider::from(connection);
        let protocol_message =
            mls_message
                .into_protocol_message()
                .ok_or(HandshakeError::ValidationError(
                    "Invalid message: Not a ProtocolMessage".to_string(),
                ))?;

        let group_id = protocol_message.group_id();

        let mut group = HpqMlsGroup::load(provider.storage(), &group_id)
            .map_err(|e| HandshakeError::ProviderError(e.into()))?
            .ok_or(HandshakeError::InvalidSessionId)?;

        let message_epoch = protocol_message.t_epoch();
        let group_epoch = group.t_group.epoch();
        let next_group_epoch = (group_epoch.as_u64() + 1).into();

        if message_epoch == next_group_epoch && group.t_group.pending_commit().is_some() {
            group
                .merge_pending_commit(provider)
                .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;
        } else if drop_pending_commit {
            group
                .clear_pending_commits(provider.storage())
                .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;
        }

        let sender_equivalence = |a: &Credential, b: &Credential| a == b;

        let processed_message = group
            .process_message(provider, protocol_message, sender_equivalence)
            .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;

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

        group
            .merge_staged_commit(provider, staged_commit)
            .map_err(|e| HandshakeError::ConnectionUpdateError(e.into()))?;

        let traffic_secrets = export_traffic_secrets(provider.crypto(), &group.t_group)?;

        let mls_session = MlsSession {
            group_id: group.group_id().clone(),
            t_epoch: group.t_epoch().as_u64(),
            pq_epoch: group.pq_epoch().as_u64(),
        };

        let mode = group
            .hpq_info()
            .ok_or(HandshakeError::ValidationError(
                "Missing HPQMLS extension".to_string(),
            ))?
            .mode;

        Ok((traffic_secrets, mls_session, client_identity, mode))
    }

    pub(super) fn process_mls_update(
        connection: &Connection,
        mls_message: HandshakeMessageIn,
        drop_pending_commit: bool,
    ) -> Result<(TrafficSecrets, MlsSession, ClientIdentity, PqtMode), HandshakeError> {
        match mls_message {
            HandshakeMessageIn::HpqMls(hpq_mls_message_in) => {
                Self::process_full_update(connection, *hpq_mls_message_in, drop_pending_commit)
            }
            HandshakeMessageIn::Mls(mls_message_in) => {
                Self::process_t_update(connection, *mls_message_in, drop_pending_commit)
            }
        }
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
