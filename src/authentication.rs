// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#[cfg(test)]
use openmls::prelude::SignatureScheme;
use thiserror::Error;

#[cfg(test)]
pub(super) const LEAF_SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ECDSA_SECP384R1_SHA384;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Wrong credential type")]
    WrongCredentialType,
    #[error("Unexpected verifying key")]
    UnexpectedVerifyingKey,
    #[error("Library error")]
    LibraryError,
}
