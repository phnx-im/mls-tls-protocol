// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls_sqlite_storage::Connection;
use rusqlite::{params, types::FromSql, OptionalExtension, ToSql};
use uuid::Uuid;

use super::{ClientHandshakeState, HandshakeError};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum ClientHandshakeVersion {
    #[default]
    V1,
}

impl ToSql for ClientHandshakeVersion {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok((*self as u8).into())
    }
}

impl FromSql for ClientHandshakeVersion {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let version = value.as_i64()? as u8;
        match version {
            0 => Ok(Self::V1),
            _ => Err(rusqlite::types::FromSqlError::Other(
                "Invalid version".into(),
            )),
        }
    }
}

impl ToSql for ClientHandshakeState {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let blob = serde_json::to_vec(self)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        Ok(blob.into())
    }
}

impl FromSql for ClientHandshakeState {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let blob = value.as_blob()?;
        let pending_update: ClientHandshakeState = serde_json::from_slice(blob)
            .map_err(|e| rusqlite::types::FromSqlError::Other(Box::new(e)))?;
        Ok(pending_update)
    }
}

impl ClientHandshakeState {
    pub(super) fn create_table(connection: &Connection) -> Result<(), HandshakeError> {
        connection.execute(
            "CREATE TABLE IF NOT EXISTS handshake_states (
                profile_id BLOB PRIMARY KEY,
                version INTEGER NOT NULL,
                handshake_state BLOB
            )",
            [],
        )?;
        Ok(())
    }

    pub(super) fn store(&self, connection: &Connection) -> Result<(), HandshakeError> {
        connection.execute(
            "INSERT INTO handshake_states (profile_id, version, handshake_state)
            VALUES (?, ?, ?)",
            params![self.profile_id, ClientHandshakeVersion::default(), self],
        )?;
        Ok(())
    }

    pub(super) fn load(
        connection: &Connection,
        profile_id: Uuid,
    ) -> Result<Option<Self>, HandshakeError> {
        let mut stmt = connection.prepare(
            "SELECT (handshake_state, version) FROM handshake_states WHERE profile_id = ?",
        )?;
        let result = stmt
            .query_row([profile_id], |row| {
                let state = row.get(0)?;
                let version: ClientHandshakeVersion = row.get(1)?;
                if version != ClientHandshakeVersion::default() {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }

                Ok(state)
            })
            .optional()?;
        Ok(result)
    }

    pub(super) fn store_update(&self, connection: &Connection) -> Result<(), rusqlite::Error> {
        connection.execute(
            "UPDATE handshake_states SET handshake_state = ? WHERE profile_id = ?",
            params![self, self.profile_id],
        )?;
        Ok(())
    }

    /// Delete the handshake state and the underlying MLS group state from the database.
    pub(super) fn delete(&self, connection: &mut Connection) -> Result<(), HandshakeError> {
        if let Some(state) = Self::load(connection, self.profile_id)? {
            state.mls_session().delete(connection)?;

            connection.execute(
                "DELETE FROM handshake_states WHERE profile_id = ?",
                params![self.profile_id],
            )?;
        }
        Ok(())
    }

    /// Delete all handshake states with old versions from the database, along
    /// with their underlying MLS group states.
    #[allow(dead_code)]
    pub fn delete_old_versions(connection: &mut Connection) -> Result<(), HandshakeError> {
        // Fetch the old states
        let old_states: Vec<ClientHandshakeState> = connection
            .prepare("SELECT handshake_state FROM handshake_states WHERE version != ?")?
            .query_map([ClientHandshakeVersion::default()], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;

        // Delete the corresponding MLS groups
        for state in old_states {
            state.mls_session().delete(connection)?;
        }

        // Delete the old states
        connection.execute(
            "DELETE FROM handshake_states WHERE version != ?",
            params![ClientHandshakeVersion::default()],
        )?;
        Ok(())
    }
}
