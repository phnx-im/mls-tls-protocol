// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::prelude::{
    tls_codec::{Deserialize as _, Serialize as _},
    BasicCredential, Credential, MlsMessageOut, SignaturePublicKey,
};
use openmls_basic_credential::SignatureKeyPair;
use serde::{Deserialize, Serialize};
use std::mem;

use crate::{
    mls_handshake::messages::{ConnectionUpdateIn, ServerHelloIn},
    tls_aead::SecretUpdate,
};

use super::{mls_group::MlsSession, *};

pub(in crate::mls_handshake) struct ClientHandshake {}

impl ClientHandshake {
    #[cfg(test)]
    pub(in crate::mls_handshake) fn start_from_seed(
        connection: &mut Connection,
        server_verifying_key: SignaturePublicKey,
        profile_id: Uuid,
    ) -> Result<(WaitingForServerHello, Vec<u8>, SignatureKeyPair), HandshakeError> {
        use crate::authentication::LEAF_SIGNATURE_SCHEME;

        let leaf_signer = SignatureKeyPair::new(LEAF_SIGNATURE_SCHEME).unwrap();

        let (waiting_for_server_hello, client_hello_bytes) =
            Self::start(connection, &leaf_signer, server_verifying_key, profile_id)?;

        Ok((waiting_for_server_hello, client_hello_bytes, leaf_signer))
    }

    pub(in crate::mls_handshake) fn start(
        connection: &Connection,
        own_signature_keypair: &SignatureKeyPair,
        server_verifying_key: SignaturePublicKey,
        profile_id: Uuid,
    ) -> Result<(WaitingForServerHello, Vec<u8>), HandshakeError> {
        let provider = Provider::from(connection);
        let basic_credential = BasicCredential::new(profile_id.as_bytes().to_vec());
        let credential = Credential::from(basic_credential);
        let credential_with_key = CredentialWithKey {
            credential: credential.clone(),
            signature_key: own_signature_keypair.public().into(),
        };
        let key_package_bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(
                CIPHERSUITE,
                &provider,
                own_signature_keypair,
                credential_with_key,
            )?;
        let client_hello = ClientHelloOut {
            key_package: key_package_bundle.key_package().clone().into(),
        };
        let handshake_message =
            MlsTlsHandshakeOut::from(HandshakePayloadOut::ClientHello(client_hello));
        let message_bytes = handshake_message.tls_serialize_detached()?;
        Ok((
            WaitingForServerHello {
                server_verifying_key,
                profile_id,
            },
            message_bytes,
        ))
    }
}

pub(in crate::mls_handshake) struct WaitingForServerHello {
    profile_id: Uuid,
    server_verifying_key: SignaturePublicKey,
}

impl WaitingForServerHello {
    pub(in crate::mls_handshake) fn receive_server_hello(
        self,
        connection: &Connection,
        message_bytes: &[u8],
    ) -> Result<(ClientHandshakeState, TrafficSecrets), HandshakeError> {
        let server_hello = ServerHelloIn::tls_deserialize_exact(message_bytes)?;

        let MlsMessageBodyIn::Welcome(welcome) = server_hello.welcome.extract() else {
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
        let staged_welcome =
            StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None)
                .map_err(|_| HandshakeError::ServerHelloError)?;

        if staged_welcome
            .welcome_sender()
            .map_err(|_| VerificationError::LibraryError)?
            .signature_key()
            != &self.server_verifying_key
        {
            return Err(VerificationError::UnexpectedVerifyingKey.into());
        }
        let client_group = staged_welcome
            .into_group(&provider)
            .map_err(|_| HandshakeError::ServerHelloError)?;

        let mls_session = MlsSession::new(
            client_group.group_id().clone(),
            client_group.epoch().as_u64(),
        );

        let traffic_secrets = export_traffic_secrets(&provider, &client_group)?;

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
    mls_message: MlsMessageOut,
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
pub(in crate::mls_handshake) struct ClientHandshakeState {
    pub(crate) profile_id: Uuid,
    mls_session: MlsSession,
    internal_state: ClientInternalState,
}

impl ClientHandshakeState {
    pub fn epoch(&self) -> u64 {
        self.mls_session.epoch
    }

    #[allow(dead_code)]
    pub(in crate::mls_handshake) fn resume(
        &mut self,
        connection: &mut Connection,
        leaf_signer: &SignatureKeyPair,
    ) -> Result<(TrafficSecrets, Vec<u8>), HandshakeError> {
        // If we want to resume and we haven't gotten a confirmation from the
        // server regarding our most recent update, we just resume use that
        // update for the resumption.
        let (mls_message, traffic_secrets) = match mem::take(&mut self.internal_state) {
            // If we're waiting for a server to confirm its own update we also
            // do a fresh update, because if the server hasn't gotten our epoch
            // confirmation, it will take this update as confirmation.
            ClientInternalState::WaitingForEpochKeyUpdateReturn(_)
            // If the state is "Running", we just do a fresh update
            | ClientInternalState::Running => {
                let mls_message = self
                    .mls_session
                    .update(connection, leaf_signer)
                    .map_err(|e| HandshakeError::ResumptionError(e.into()))?;

                let traffic_secrets = self.mls_session.merge_update(connection)?;

                (mls_message, traffic_secrets)
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
        leaf_signer: &SignatureKeyPair,
        update_requested: bool,
    ) -> Result<(ClientSecret, Vec<u8>), HandshakeError> {
        if self.is_waiting_for_response() {
            return Err(HandshakeError::WaitingForResponse);
        }
        let mls_message = self.mls_session.update(connection, leaf_signer)?;
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

        Ok((traffic_secrets.client_secret, message_bytes))
    }

    pub(in crate::mls_handshake) fn receive_signaling_message(
        &mut self,
        connection: &mut Connection,
        leaf_signer: &SignatureKeyPair,
        message_bytes: &[u8],
    ) -> Result<(Option<SecretUpdate>, Option<Vec<u8>>), HandshakeError> {
        let signaling_message = SignalingMessageIn::tls_deserialize_exact(message_bytes)?;

        let incoming_message_type = signaling_message.message_type();

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
        leaf_signer: &SignatureKeyPair,
        connection_update: ConnectionUpdateIn,
    ) -> Result<(ClientSecret, Vec<u8>), HandshakeError> {
        let (mut traffic_secrets, mls_session, _) =
            MlsSession::process_mls_update(connection, connection_update.mls_commit, false)?;

        self.mls_session = mls_session;

        let mut response_bytes = self.create_epoch_key_update(connection)?;

        if connection_update.update_requested.into() {
            let connection_update = self.mls_session.update(connection, leaf_signer)?;

            let new_traffic_secrets = self.mls_session.merge_update(connection)?;

            // If the server requests an update, the previous traffic secrets
            // are overwritten by the new traffic secrets after the client has
            // performed its update.
            traffic_secrets = new_traffic_secrets;

            let pending_update = PendingUpdate {
                mls_message: connection_update.clone(),
                traffic_secrets: traffic_secrets.clone(),
            };

            self.internal_state = ClientInternalState::WaitingForEpochKeyUpdate(pending_update);

            let connection_update_bytes =
                SignalingMessageOut::ConnectionUpdate(ConnectionUpdateOut {
                    update_requested: false.into(),
                    mls_commit: connection_update,
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
