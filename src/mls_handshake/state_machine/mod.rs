// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{ExportSecretError, GroupId, MlsGroup, MlsGroupJoinConfig, StagedWelcome},
    prelude::{
        tls_codec::{self, Deserialize, Serialize},
        Capabilities, Ciphersuite, CredentialWithKey, KeyPackage, KeyPackageNewError,
        LeafNodeParameters, MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent,
        ProtocolMessage, Sender,
    },
};
use openmls_sqlite_storage::Connection;
use openmls_traits::OpenMlsProvider;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    authentication::VerificationError,
    mls_handshake::messages::{ClientHelloOut, ServerHelloOut, SignalingMessageIn},
    tls_aead::{ClientSecret, ServerSecret, TrafficSecrets},
};

use super::{
    messages::{
        ConnectionUpdateOut, EpochKeyUpdate, HandshakePayloadIn, HandshakePayloadOut,
        MlsTlsHandshakeIn, MlsTlsHandshakeOut, ProtocolVersion, ResumptionOut, SignalingMessageOut,
    },
    openmls_provider::Provider,
};

pub(super) mod client;
mod mls_group;
pub(super) mod server;
#[cfg(test)]
pub(super) mod tests;

pub(super) use mls_group::MlsSession;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_AES256GCM_SHA512_P384;
const SHARED_EXPORT_LABEL: &str = "MLS-TLS 1.0";
const CLIENT_TRAFFIC_SECRET_LABEL: &str = "Initial Client Traffic Secret";
const SERVER_TRAFFIC_SECRET_LABEL: &str = "Initial Server Traffic Secret";

fn export_label(label: &str) -> String {
    format!("{SHARED_EXPORT_LABEL}{label}")
}

fn capabilities() -> Capabilities {
    Capabilities::new(None, Some(&[CIPHERSUITE]), None, None, None)
}

fn export_traffic_secrets(
    provider: &impl OpenMlsProvider,
    group: &MlsGroup,
) -> Result<TrafficSecrets, HandshakeError> {
    let client_secret = group.export_secret(
        provider,
        &export_label(CLIENT_TRAFFIC_SECRET_LABEL),
        &[],
        group.ciphersuite().hash_length(),
    )?;

    let server_secret = group.export_secret(
        provider,
        &export_label(SERVER_TRAFFIC_SECRET_LABEL),
        &[],
        group.ciphersuite().hash_length(),
    )?;

    Ok(TrafficSecrets {
        client_secret: ClientSecret(client_secret),
        server_secret: ServerSecret(server_secret),
    })
}

type BoxedError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error(transparent)]
    CodecError(#[from] tls_codec::Error),
    #[error("Wrong protocol version")]
    WrongProtocolVersion,
    #[error("Unexpected message: Expected {expected}, got {actual}")]
    UnexpectedMessage {
        expected: &'static str,
        actual: &'static str,
    },
    #[error(transparent)]
    VerificationError(#[from] VerificationError),
    #[error("Error exporting shared secret: {0}")]
    SharedSecretError(#[from] ExportSecretError),
    #[error("Error processing ServerHello")]
    ServerHelloError,
    #[error("Provider error: {0}")]
    ProviderError(BoxedError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageNewError),
    #[error("Error processing ClientHello: {0}")]
    ClientHelloError(BoxedError),
    #[error("Invalid session id")]
    InvalidSessionId,
    #[error("Error resuming session: {0}")]
    ResumptionError(BoxedError),
    #[error("Error updating connection: {0}")]
    ConnectionUpdateError(BoxedError),
    #[error("Error confirming connection: {0}")]
    ConnectionConfirmationError(BoxedError),
    #[error("Can't update while waiting for response")]
    WaitingForResponse,
    #[error("Persistence error: {0}")]
    PersistenceError(#[from] rusqlite::Error),
    #[error("Database migration error: {0}")]
    MigrationError(#[from] refinery::Error),
    #[error("Error validating message: {0}")]
    ValidationError(String),
}

impl MlsTlsHandshakeIn {
    pub(super) fn check_version(&self) -> Result<(), HandshakeError> {
        if self.version != ProtocolVersion::default() {
            return Err(HandshakeError::WrongProtocolVersion);
        }
        Ok(())
    }
}

impl From<HandshakePayloadOut> for MlsTlsHandshakeOut {
    fn from(payload: HandshakePayloadOut) -> Self {
        Self {
            version: ProtocolVersion::default(),
            payload,
        }
    }
}

trait HandshakeState {
    fn mls_session(&self) -> &MlsSession;

    fn create_epoch_key_update(&self, connection: &Connection) -> Result<Vec<u8>, HandshakeError> {
        let epoch_key_update = self.mls_session().create_epoch_key_update(connection)?;

        let message_bytes =
            SignalingMessageOut::EpochKeyUpdate(epoch_key_update).tls_serialize_detached()?;

        Ok(message_bytes)
    }

    fn process_epoch_key_update(
        &self,
        connection: &Connection,
        key_update: EpochKeyUpdate,
    ) -> Result<(), HandshakeError> {
        self.mls_session()
            .process_epoch_key_update(connection, key_update)
    }
}

pub(crate) fn initialize_storage(connection: &mut Connection) -> Result<(), HandshakeError> {
    let mut provider = Provider::from(connection);
    provider.initialize_storage()?;
    Ok(())
}
