// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Wrong credential type")]
    WrongCredentialType,
    #[error("Unexpected verifying key")]
    UnexpectedVerifyingKey,
    #[error("Library error")]
    LibraryError,
}
