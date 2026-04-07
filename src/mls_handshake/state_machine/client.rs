// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use hpqmls::{
    authentication::{HpqCredentialWithKey, HpqSignatureKeyPair, HpqSigner as _, HpqVerifyingKey},
    extension::PqtMode,
    messages::HpqKeyPackage,
    HpqMlsGroup,
};
use openmls::prelude::{
    tls_codec::{Deserialize as _, Serialize as _},
    LeafNodeIndex, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use std::mem;

use crate::{
    mls_handshake::messages::{
        ConnectionUpdateIn, HandshakeMessageIn, HandshakeMessageOut, ServerHelloIn,
    },
    tls_aead::SecretUpdate,
};

use super::{mls_group::MlsSession, *};

pub(in crate::mls_handshake) struct ClientHandshake {}

impl ClientHandshake {
    pub(in crate::mls_handshake) fn start(
        connection: &Connection,
        own_signature_keypair: &HpqSignatureKeyPair,
        server_verifying_key: HpqVerifyingKey,
        client_id: Uuid,
    ) -> Result<(WaitingForServerHello, Vec<u8>), HandshakeError> {
        let provider = Provider::from(connection);
        let credential_with_key =
            HpqCredentialWithKey::new(client_id.as_bytes(), own_signature_keypair);
        let ciphersuite = if matches!(
            own_signature_keypair.pq_signer().signature_scheme(),
            SignatureScheme::MLDSA87
        ) {
            PqtMode::ConfAndAuth.default_ciphersuite()
        } else {
            PqtMode::ConfOnly.default_ciphersuite()
        };
        let key_package_bundle = HpqKeyPackage::builder().build(
            &provider,
            ciphersuite,
            own_signature_keypair,
            credential_with_key,
        )?;
        let client_hello = ClientHelloOut {
            key_package: key_package_bundle.into_key_package().clone().into(),
        };
        let handshake_message =
            MlsTlsHandshakeOut::from(HandshakePayloadOut::ClientHello(Box::new(client_hello)));
        let message_bytes = handshake_message.tls_serialize_detached()?;
        Ok((
            WaitingForServerHello {
                server_verifying_key,
                profile_id: client_id,
            },
            message_bytes,
        ))
    }
}

pub(in crate::mls_handshake) struct WaitingForServerHello {
    profile_id: Uuid,
    server_verifying_key: HpqVerifyingKey,
}

impl WaitingForServerHello {
    pub(in crate::mls_handshake) fn receive_server_hello(
        self,
        connection: &Connection,
        message_bytes: &[u8],
    ) -> Result<(ClientHandshakeState, TrafficSecrets), HandshakeError> {
        let server_hello = ServerHelloIn::tls_deserialize_exact(message_bytes)?;

        let Some(welcome) = server_hello.welcome.into_welcome() else {
            return Err(HandshakeError::UnexpectedMessage {
                expected: "Welcome",
                actual: "Unknown",
            });
        };

        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        // Join the group
        let provider = Provider::from(connection);
        let client_group = HpqMlsGroup::new_from_welcome(&provider, &join_config, welcome, None)
            .map_err(|e| {
                tracing::error!("Error joining group: {:?}", e);
                HandshakeError::ServerHelloError
            })?;

        if client_group
            .verifying_key_at(LeafNodeIndex::new(0))
            .ok_or(HandshakeError::ServerHelloError)?
            != self.server_verifying_key
        {
            return Err(VerificationError::UnexpectedVerifyingKey.into());
        }

        let mls_session = MlsSession::new(
            client_group.group_id().clone(),
            client_group.t_epoch().as_u64(),
            client_group.pq_epoch().as_u64(),
        );

        let traffic_secrets = export_traffic_secrets(provider.crypto(), &client_group.t_group)?;

        let handshake_state = ClientHandshakeState {
            mls_session,
            internal_state: ClientInternalState::Running,
            profile_id: self.profile_id,
        };

        Ok((handshake_state, traffic_secrets))
    }
}

#[derive(Serialize, Deserialize)]
struct PendingUpdate {
    mls_message: HandshakeMessageOut,
    traffic_secrets: TrafficSecrets,
}

#[derive(Default, Serialize, Deserialize)]
enum ClientInternalState {
    #[default]
    Running,
    WaitingForConnectionConfirmation(PendingUpdate),
    // This is waiting for the server to confirm our own update
    WaitingForEpochKeyUpdate(PendingUpdate),
    // This is waiting for the server to update its keys based on its own update
    WaitingForEpochKeyUpdateReturn(ServerSecret),
}

/// The state of the client during the handshake.
///
/// WARNING: When changing this struct, make sure to add a new
/// `ClientHandshakeStateVersion` in the `persistence` module.
#[derive(Serialize, Deserialize)]
pub(crate) struct ClientHandshakeState {
    pub(crate) profile_id: Uuid,
    mls_session: MlsSession,
    internal_state: ClientInternalState,
}

impl ClientHandshakeState {
    pub fn t_epoch(&self) -> u64 {
        self.mls_session.t_epoch
    }

    pub fn pq_epoch(&self) -> u64 {
        self.mls_session.pq_epoch
    }

    #[allow(dead_code)]
    pub(in crate::mls_handshake) fn resume(
        &mut self,
        connection: &mut Connection,
        leaf_signer: &HpqSignatureKeyPair,
    ) -> Result<(TrafficSecrets, Vec<u8>), HandshakeError> {
        // If we want to resume and we haven't gotten a confirmation from the
        // server regarding our most recent update, we just use that update for
        // the resumption.
        let (mls_message, traffic_secrets) = match mem::take(&mut self.internal_state) {
            // If we're waiting for a server to confirm its own update we also
            // do a fresh update, because if the server hasn't gotten our epoch
            // confirmation, it will take this update as confirmation.
            ClientInternalState::WaitingForEpochKeyUpdateReturn(_)
            // If the state is "Running", we just do a fresh update
            | ClientInternalState::Running => {
                let mls_message = self
                    .mls_session
                    .full_update(connection, leaf_signer)
                    .map_err(|e| HandshakeError::ResumptionError(e.into()))?;

                let traffic_secrets = self.mls_session.merge_update(connection)?;

                (HandshakeMessageOut::HpqMls(Box::new(mls_message)), traffic_secrets)
            }
            ClientInternalState::WaitingForEpochKeyUpdate(pending_update)
            | ClientInternalState::WaitingForConnectionConfirmation(pending_update) => {
                (pending_update.mls_message, pending_update.traffic_secrets)
            }
        };

        let resumption = MlsTlsHandshakeOut::from(HandshakePayloadOut::Resumption(ResumptionOut {
            commit: mls_message.clone(),
        }));

        let message_bytes = resumption.tls_serialize_detached()?;

        self.internal_state =
            ClientInternalState::WaitingForConnectionConfirmation(PendingUpdate {
                mls_message,
                traffic_secrets: traffic_secrets.clone(),
            });

        Ok((traffic_secrets, message_bytes))
    }

    pub(in crate::mls_handshake) fn is_waiting_for_response(&self) -> bool {
        matches!(
            self.internal_state,
            ClientInternalState::WaitingForConnectionConfirmation(_)
                | ClientInternalState::WaitingForEpochKeyUpdate(_)
                | ClientInternalState::WaitingForEpochKeyUpdateReturn(_)
        )
    }

    pub(in crate::mls_handshake) fn update(
        &mut self,
        connection: &mut Connection,
        leaf_signer: &HpqSignatureKeyPair,
        update_requested: bool,
        pq: bool,
    ) -> Result<(ClientSecret, Vec<u8>), HandshakeError> {
        if self.is_waiting_for_response() {
            return Err(HandshakeError::WaitingForResponse);
        }
        let update_type = if pq { "combined PQ" } else { "traditional" };
        tracing::debug!(
            update_type,
            update_requested,
            t_epoch = self.mls_session.t_epoch,
            pq_epoch = self.mls_session.pq_epoch,
            "Client creating key update",
        );

        let mls_message: HandshakeMessageOut =
            self.mls_session.update(connection, leaf_signer, pq)?;
        let traffic_secrets = self.mls_session.merge_update(connection)?;

        let connection_update = SignalingMessageOut::ConnectionUpdate(ConnectionUpdateOut {
            update_requested: update_requested.into(),
            mls_commit: mls_message.clone(),
        });

        let pending_update = PendingUpdate {
            mls_message,
            traffic_secrets: traffic_secrets.clone(),
        };

        let message_bytes = connection_update.tls_serialize_detached()?;

        self.internal_state = ClientInternalState::WaitingForEpochKeyUpdate(pending_update);

        self.store_update(connection)?;

        tracing::debug!(
            update_type,
            size_bytes = message_bytes.len(),
            "Client key update message created",
        );

        Ok((traffic_secrets.client_secret, message_bytes))
    }

    pub(in crate::mls_handshake) fn receive_signaling_message(
        &mut self,
        connection: &mut Connection,
        leaf_signer: &HpqSignatureKeyPair,
        message_bytes: &[u8],
    ) -> Result<(Option<SecretUpdate>, Option<Vec<u8>>), HandshakeError> {
        let signaling_message = SignalingMessageIn::tls_deserialize_exact(message_bytes)?;

        let incoming_message_type = signaling_message.message_type();

        tracing::debug!(
            message_type = incoming_message_type,
            size_bytes = message_bytes.len(),
            "Client received signaling message"
        );

        let result = match signaling_message {
            SignalingMessageIn::ConnectionUpdate(connection_update) => {
                // As client, our connection updates have priority. If we're
                // waiting for something from the server, we ignore everything
                // else.
                if !matches!(self.internal_state, ClientInternalState::Running) {
                    return Ok((None, None));
                }
                let (client_secret, messages_bytes) =
                    self.process_update(connection, leaf_signer, connection_update)?;

                (
                    Some(SecretUpdate::ClientSecret(client_secret)),
                    Some(messages_bytes),
                )
            }
            SignalingMessageIn::ConnectionConfirmation(epoch_key_update) => {
                let ClientInternalState::WaitingForConnectionConfirmation(_pending_update) =
                    mem::take(&mut self.internal_state)
                else {
                    return Err(HandshakeError::UnexpectedMessage {
                        expected: "ConnectionConfirmation",
                        actual: incoming_message_type,
                    });
                };

                self.process_epoch_key_update(connection, epoch_key_update)?;

                self.internal_state = ClientInternalState::Running;

                (None, None)
            }
            SignalingMessageIn::EpochKeyUpdate(epoch_key_update) => {
                match mem::take(&mut self.internal_state) {
                    ClientInternalState::WaitingForEpochKeyUpdateReturn(server_secret) => {
                        self.process_epoch_key_update(connection, epoch_key_update)?;

                        (Some(SecretUpdate::ServerSecret(server_secret)), None)
                    }
                    ClientInternalState::WaitingForEpochKeyUpdate(pending_update) => {
                        self.process_epoch_key_update(connection, epoch_key_update)?;

                        // Return the server secret to the caller
                        (
                            Some(SecretUpdate::ServerSecret(
                                pending_update.traffic_secrets.server_secret,
                            )),
                            None,
                        )
                    }
                    _ => {
                        return Err(HandshakeError::UnexpectedMessage {
                            expected: "EpochKeyUpdateReturn",
                            actual: incoming_message_type,
                        });
                    }
                }
            }
            SignalingMessageIn::KeyUpdate(_key_update) => todo!(),
        };

        self.store_update(connection)?;

        Ok(result)
    }

    fn process_update(
        &mut self,
        connection: &mut Connection,
        leaf_signer: &HpqSignatureKeyPair,
        connection_update: ConnectionUpdateIn,
    ) -> Result<(ClientSecret, Vec<u8>), HandshakeError> {
        let (mut traffic_secrets, mls_session, _, _) = match connection_update.mls_commit {
            HandshakeMessageIn::HpqMls(hpq_mls_message_in) => {
                MlsSession::process_full_update(connection, *hpq_mls_message_in, false)?
            }
            HandshakeMessageIn::Mls(mls_message_in) => {
                MlsSession::process_t_update(connection, *mls_message_in, false)?
            }
        };

        self.mls_session = mls_session;

        let mut response_bytes = self.create_epoch_key_update(connection)?;

        if connection_update.update_requested.into() {
            let connection_update = self.mls_session.t_update(connection, leaf_signer)?;

            let new_traffic_secrets = self.mls_session.merge_update(connection)?;

            // If the server requests an update, the previous traffic secrets
            // are overwritten by the new traffic secrets after the client has
            // performed its update.
            traffic_secrets = new_traffic_secrets;

            let pending_update = PendingUpdate {
                mls_message: connection_update.clone().into(),
                traffic_secrets: traffic_secrets.clone(),
            };

            self.internal_state = ClientInternalState::WaitingForEpochKeyUpdate(pending_update);

            let connection_update_bytes =
                SignalingMessageOut::ConnectionUpdate(ConnectionUpdateOut {
                    update_requested: false.into(),
                    mls_commit: connection_update.into(),
                })
                .tls_serialize_detached()?;

            // If an update was requested, the client just sends the update as
            // response instead of the epoch key update
            response_bytes = connection_update_bytes;
        } else {
            self.internal_state =
                ClientInternalState::WaitingForEpochKeyUpdateReturn(traffic_secrets.server_secret);
        }

        Ok((traffic_secrets.client_secret, response_bytes))
    }

    pub(in crate::mls_handshake) fn mls_session(&self) -> &MlsSession {
        &self.mls_session
    }
}

impl HandshakeState for ClientHandshakeState {
    fn mls_session(&self) -> &MlsSession {
        &self.mls_session
    }
}
