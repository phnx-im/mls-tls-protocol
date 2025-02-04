// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Authentication
//!
//! This module constains structs and functions to facilitate authentication in
//! the MLS-TLS protocol.

use chrono::{DateTime, Datelike, DurationRound, Months, TimeDelta, Timelike, Utc};
use ecdsa::signature;
use hex::FromHex;
use leaf_certificate::LeafCertificateSigner;
use openmls_traits::signatures::Signer;
use pkcs8::{der::asn1::GeneralizedTime, AssociatedOid};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};
use root_certificate::{RootCertificate, RootCertificateSigner, SERVER_ROOT_IDENTITY};
use std::str::FromStr;
use thiserror::Error;
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile, RequestBuilder},
    der::asn1::BitString,
    name::Name,
    request::CertReq,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifier, SubjectPublicKeyInfo, SubjectPublicKeyInfoOwned},
    time::{Time, Validity},
    Certificate,
};

pub mod leaf_certificate;
pub mod root_certificate;

#[cfg(test)]
mod tests;

pub const SEED_LEN: usize = 32;
pub const DEFAULT_VALIDITY_SECS: u64 = 365 * 24 * 60 * 60;

// Helper function for the demonstrator
pub fn certificates_from_seed(
    seed: String,
    leaf_identity: impl ToString,
) -> Result<(RootCertificate, LeafCertificateSigner), CertificateError> {
    let seed_phrase = <[u8; 32]>::from_hex(seed)?;
    let mut rng = ChaCha20Rng::from_seed(seed_phrase);

    let root_signer =
        RootCertificateSigner::new_with_time_and_rng(Utc::now(), &mut rng, SERVER_ROOT_IDENTITY)?;

    let leaf_signer =
        root_signer.issue_new_leaf_with_time_and_rng(leaf_identity, Utc::now(), &mut OsRng)?;

    Ok((root_signer.into_certificate(), leaf_signer))
}

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error(transparent)]
    FailedToBuildCertificate(#[from] x509_cert::builder::Error),
    #[error(transparent)]
    CryptoError(#[from] openmls_traits::types::CryptoError),
    #[error(transparent)]
    RandomnessError(#[from] rand_core::Error),
    #[error(transparent)]
    EncodingError(#[from] pkcs8::der::Error),
    #[error("Invalid system time")]
    InvalidSystemTime,
    #[error("Library error")]
    LibraryError,
    #[error("Invalid seed phrase: {0}")]
    InvalidSeedPhrase(#[from] hex::FromHexError),
}

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error(transparent)]
    EncodingError(#[from] pkcs8::der::Error),
    #[error(transparent)]
    InvalidSignature(#[from] signature::Error),
    #[error("Certificate validity is out of range")]
    Expired,
    #[error("Verifying key mismatch")]
    KeyMismatch,
    #[error("Unexpected identity: Expected {expected}, got {actual}")]
    UnexpectedIdentity { expected: String, actual: String },
    #[error("Library error")]
    LibraryError,
}

/// Helper function to convert a chrono DateTime to a DER Time.
fn try_chrono_to_der_time(time: DateTime<Utc>) -> Result<Time, pkcs8::der::Error> {
    let der_time = Time::GeneralTime(GeneralizedTime::from_date_time(
        x509_cert::der::DateTime::new(
            time.year() as u16,
            time.month() as u8,
            time.day() as u8,
            time.hour() as u8,
            time.minute() as u8,
            time.second() as u8,
        )?,
    ));
    Ok(der_time)
}

/// Helper function to convert a chrono DateTime to a DER Time.
fn try_der_time_to_chrono(time: Time) -> Result<DateTime<Utc>, VerificationError> {
    let der_date_time = match time {
        Time::GeneralTime(general_time) => general_time.to_date_time(),
        Time::UtcTime(utc_time) => utc_time.to_date_time(),
    };
    let der_unix_duration = der_date_time.unix_duration();
    DateTime::<Utc>::from_timestamp(
        der_unix_duration.as_secs() as i64,
        der_unix_duration.subsec_nanos(),
    )
    .ok_or(VerificationError::Expired)
}
