// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{Borrow, Codec, Connection, OpenMlsProvider, RustCrypto, SqliteStorageProvider};

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

pub struct Provider<ConnectionRef: Borrow<Connection>> {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, ConnectionRef>,
}

impl Provider<&'_ mut Connection> {
    pub fn initialize_storage(&mut self) -> Result<(), refinery::Error> {
        self.storage.initialize()
    }
}

impl<'a> From<&'a mut Connection> for Provider<&'a mut Connection> {
    fn from(connection: &'a mut Connection) -> Self {
        let storage = SqliteStorageProvider::new(connection);
        Self {
            crypto: RustCrypto::default(),
            storage,
        }
    }
}

impl<'a> From<&'a Connection> for Provider<&'a Connection> {
    fn from(connection: &'a Connection) -> Self {
        let storage = SqliteStorageProvider::new(connection);
        Self {
            crypto: RustCrypto::default(),
            storage,
        }
    }
}

impl<ConnectionRef: Borrow<Connection>> OpenMlsProvider for Provider<ConnectionRef> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, ConnectionRef>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
