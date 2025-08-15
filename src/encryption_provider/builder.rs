// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio::net::TcpStream;

pub use hpqmls::extension::PqtMode;

use crate::{
    encryption_provider::{
        update_policy::{CombinedUpdatePolicy, UpdatePolicy},
        EncryptionProvider, EncryptionProviderError, ProtectedHandshakeState,
        UnprotectedHandshakeState,
    },
    pre_handshake::PreHandshake,
};

#[derive(Debug, Default)]
pub struct EncryptionProviderBuilder {
    pqt_mode: PqtMode,
    update_policy: CombinedUpdatePolicy,
}

impl EncryptionProviderBuilder {
    pub fn new() -> Self {
        Self {
            pqt_mode: PqtMode::default(),
            update_policy: CombinedUpdatePolicy::default(),
        }
    }

    pub fn with_pqt_mode(mut self, mode: PqtMode) -> Self {
        self.pqt_mode = mode;
        self
    }

    pub fn with_pq_update_policy(mut self, policy: UpdatePolicy) -> Self {
        self.update_policy.pq_policy = Some(policy);
        self
    }

    pub fn with_t_update_policy(mut self, policy: UpdatePolicy) -> Self {
        self.update_policy.t_policy = policy;
        self
    }

    pub fn build<const IS_SERVER: bool>(
        self,
        socket: TcpStream,
    ) -> Result<EncryptionProvider<UnprotectedHandshakeState, IS_SERVER>, EncryptionProviderError>
    {
        EncryptionProvider::new_from_stream(socket, self.update_policy)
    }

    pub async fn build_with_pre_handshake<const IS_SERVER: bool, Ph: PreHandshake>(
        self,
        socket: TcpStream,
        pre_handshake: Ph,
    ) -> Result<EncryptionProvider<ProtectedHandshakeState, IS_SERVER>, EncryptionProviderError>
    {
        EncryptionProvider::new_with_pre_handshake(socket, self.update_policy, pre_handshake).await
    }
}

impl<const IS_SERVER: bool, State> EncryptionProvider<State, IS_SERVER> {
    pub fn builder() -> EncryptionProviderBuilder {
        EncryptionProviderBuilder::default()
    }
}
