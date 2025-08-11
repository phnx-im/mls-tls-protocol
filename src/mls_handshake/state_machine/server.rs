// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use hpqmls::authentication::HpqSignatureKeyPair;

use crate::{
    handshake::ClientIdentity,
    mls_handshake::messages::{ClientHelloIn, ConnectionUpdateIn, ResumptionIn},
};

use super::*;

pub(in crate::mls_handshake) struct ServerHandshake;

impl ServerHandshake {
    pub(in crate::mls_handshake) fn start(
        connection: &mut Connection,
        leaf_signer: &HpqSignatureKeyPair,
        message_bytes: &[u8],
    ) -> Result<
        (
            ServerHandshakeState,
            TrafficSecrets,
            ClientIdentity,
            Vec<u8>,
        ),
        HandshakeError,
    > {
        let message = MlsTlsHandshakeIn::tls_deserialize_exact(message_bytes)?;
        message.check_version()?;
        match message.payload {
            HandshakePayloadIn::ClientHello(client_hello) => {
                Self::process_client_hello(connection, leaf_signer, client_hello)
            }
            HandshakePayloadIn::Resumption(resumption) => {
                Self::process_resumption(connection, resumption)
            }
        }
    }

    fn process_client_hello(
        connection: &mut Connection,
        leaf_signer: &HpqSignatureKeyPair,
        client_hello: ClientHelloIn,
    ) -> Result<
        (
            ServerHandshakeState,
            TrafficSecrets,
            ClientIdentity,
            Vec<u8>,
        ),
        HandshakeError,
    > {
        let Some(key_package_in) = client_hello.key_package.into_key_package() else {
            return Err(HandshakeError::UnexpectedMessage {
                expected: "KeyPackage",
                actual: "Unknown",
            });
        };

        let (mls_session, traffic_secrets, client_identity, welcome) =
            MlsSession::create_server_session(connection, leaf_signer, key_package_in)?;

        let message = ServerHelloOut { welcome };

        let message_bytes = message.tls_serialize_detached()?;

        let state = ServerHandshakeState {
            mls_session,
            internal_state: ServerInternalState::Running,
        };

        Ok((state, traffic_secrets, client_identity, message_bytes))
    }

    pub(in crate::mls_handshake) fn process_resumption(
        connection: &Connection,
        resumption: ResumptionIn,
    ) -> Result<
        (
            ServerHandshakeState,
            TrafficSecrets,
            ClientIdentity,
            Vec<u8>,
        ),
        HandshakeError,
    > {
        let (traffic_secrets, session_id, client_identity) =
            MlsSession::process_mls_update(connection, resumption.commit, true)?;

        let state = ServerHandshakeState {
            mls_session: session_id,
            internal_state: ServerInternalState::Running,
        };

        let connection_confirmation = state.create_connection_confirmation(connection)?;

        Ok((
            state,
            traffic_secrets,
            client_identity,
            connection_confirmation,
        ))
    }
}

pub(in crate::mls_handshake) struct ServerHandshakeState {
    pub(in crate::mls_handshake) mls_session: MlsSession,
    internal_state: ServerInternalState,
}

#[derive(Default)]
enum ServerInternalState {
    #[default]
    Running,
    WaitingForUpdate,
}

impl HandshakeState for ServerHandshakeState {
    fn mls_session(&self) -> &MlsSession {
        &self.mls_session
    }
}

impl ServerHandshakeState {
    pub(in crate::mls_handshake) fn epoch(&self) -> u64 {
        self.mls_session.t_epoch
    }

    fn is_waiting_for_response(&self) -> bool {
        matches!(self.internal_state, ServerInternalState::WaitingForUpdate)
    }

    pub(in crate::mls_handshake) fn update(
        &mut self,
        connection: &mut Connection,
        leaf_signer: &HpqSignatureKeyPair,
        update_requested: bool,
        pq: bool,
    ) -> Result<Vec<u8>, HandshakeError> {
        if self.is_waiting_for_response() {
            return Err(HandshakeError::WaitingForResponse);
        }
        let mls_message = self.mls_session.update(connection, leaf_signer, pq)?;

        let connection_update = SignalingMessageOut::ConnectionUpdate(ConnectionUpdateOut {
            update_requested: update_requested.into(),
            mls_commit: mls_message,
        });

        let message_bytes = connection_update.tls_serialize_detached()?;

        self.internal_state = ServerInternalState::WaitingForUpdate;

        Ok(message_bytes)
    }

    pub(in crate::mls_handshake) fn receive_signaling_message(
        &mut self,
        connection: &mut Connection,
        leaf_signer: &HpqSignatureKeyPair,
        message_bytes: &[u8],
    ) -> Result<(TrafficSecrets, Option<Vec<u8>>), HandshakeError> {
        let signaling_message = SignalingMessageIn::tls_deserialize_exact(message_bytes)?;

        let incoming_message_type = signaling_message.message_type();

        match signaling_message {
            SignalingMessageIn::ConnectionUpdate(connection_update) => {
                let (traffic_secrets, message_bytes) =
                    self.process_update(connection, leaf_signer, connection_update)?;
                Ok((traffic_secrets, Some(message_bytes)))
            }
            SignalingMessageIn::ConnectionConfirmation(_) => {
                // Servers never receive ConnectionConfirmations
                Err(HandshakeError::UnexpectedMessage {
                    expected: "None",
                    actual: "ConnectionConfirmation",
                })
            }
            SignalingMessageIn::EpochKeyUpdate(epoch_key_update) => {
                if !matches!(self.internal_state, ServerInternalState::WaitingForUpdate) {
                    return Err(HandshakeError::UnexpectedMessage {
                        expected: "None",
                        actual: incoming_message_type,
                    });
                }
                let traffic_secrets = self.mls_session.merge_update(connection)?;

                self.process_epoch_key_update(connection, epoch_key_update)?;
                let message_bytes = self.create_epoch_key_update(connection)?;
                self.internal_state = ServerInternalState::Running;
                Ok((traffic_secrets, Some(message_bytes)))
            }
            SignalingMessageIn::KeyUpdate(_key_update) => todo!(),
        }
    }

    fn process_update(
        &mut self,
        connection: &mut Connection,
        leaf_signer: &HpqSignatureKeyPair,
        connection_update: ConnectionUpdateIn,
    ) -> Result<(TrafficSecrets, Vec<u8>), HandshakeError> {
        println!("Processing connection update");
        let (traffic_secrets, mls_session, _client_identity) =
            MlsSession::process_mls_update(connection, connection_update.mls_commit, true)?;
        println!("Done processing MLS update");

        // Client updates override any internal state, so after receiving one,
        // we're no longer waiting for anything
        self.internal_state = ServerInternalState::Running;

        self.mls_session = mls_session;

        let mut response_bytes = self.create_epoch_key_update(connection)?;

        if connection_update.update_requested.into() {
            let pq = false; // For now, only T update can be requested
            let mls_commit = self.mls_session.update(connection, leaf_signer, pq)?;

            // We're sending an update, so we're now waiting for a response
            self.internal_state = ServerInternalState::WaitingForUpdate;

            let connection_update_bytes =
                SignalingMessageOut::ConnectionUpdate(ConnectionUpdateOut {
                    update_requested: false.into(),
                    mls_commit,
                })
                .tls_serialize_detached()?;

            response_bytes = connection_update_bytes;
        }

        Ok((traffic_secrets, response_bytes))
    }

    fn create_connection_confirmation(
        &self,
        connection: &Connection,
    ) -> Result<Vec<u8>, HandshakeError> {
        let epoch_key_update = self.mls_session().create_epoch_key_update(connection)?;

        let message_bytes = SignalingMessageOut::ConnectionConfirmation(epoch_key_update)
            .tls_serialize_detached()?;

        Ok(message_bytes)
    }
}
