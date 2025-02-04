// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use ecdsa::{der::Signature, signature::Verifier, VerifyingKey, ECDSA_SHA256_OID};
use openmls::prelude::{BasicCredential, CredentialWithKey, SignatureScheme};
use p384::NistP384;
use pkcs8::der::{Decode, Encode};
use std::ops::Deref;

use super::{
    leaf_certificate::{LeafCertificateSigner, LeafCsrSigner},
    *,
};

pub(crate) const SERVER_ROOT_IDENTITY: &str = "server_root";

#[cfg(test)]
pub(super) const ROOT_SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ECDSA_SECP384R1_SHA384;

#[derive(Debug, Clone, PartialEq)]
pub struct RootCertificate(pub(crate) Certificate);

impl Deref for RootCertificate {
    type Target = Certificate;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl RootCertificate {
    pub fn deserialize(bytes: &[u8]) -> Result<Self, CertificateError> {
        let certificate = Certificate::from_der(bytes)?;
        Ok(Self(certificate))
    }

    pub fn serialize(&self) -> Result<Vec<u8>, CertificateError> {
        self.0.to_der().map_err(CertificateError::EncodingError)
    }

    pub(crate) fn verify_leaf_certificate(
        &self,
        now: DateTime<Utc>,
        leaf_certificate: &Certificate,
    ) -> Result<(), VerificationError> {
        // Verify signature
        let verifying_key_bytes = self
            .0
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(VerificationError::LibraryError)?;
        let verifying_key = VerifyingKey::<NistP384>::from_sec1_bytes(verifying_key_bytes)
            .map_err(|_| VerificationError::LibraryError)?;
        let leaf_certificate_tbs = leaf_certificate.tbs_certificate.to_der()?;
        let signature = Signature::from_bytes(
            leaf_certificate
                .signature
                .as_bytes()
                .ok_or(VerificationError::LibraryError)?,
        )?;
        verifying_key.verify(leaf_certificate_tbs.as_slice(), &signature)?;

        // Verify validity
        let not_before =
            try_der_time_to_chrono(leaf_certificate.tbs_certificate.validity.not_before)?;
        let not_after =
            try_der_time_to_chrono(leaf_certificate.tbs_certificate.validity.not_after)?;
        if now < not_before || now > not_after {
            return Err(VerificationError::Expired);
        }

        Ok(())
    }

    /// Verifies that the credential is signed by this root certificate. Also
    /// verifies that the verifying key in the [`CredentialWithKey`] is matches
    /// that contained in the credential.
    pub(crate) fn verify_openmls_credential(
        &self,
        credential_with_key: &CredentialWithKey,
        expected_identity: Option<&str>,
    ) -> Result<(), VerificationError> {
        let basic_credential = BasicCredential::try_from(credential_with_key.credential.clone())
            .map_err(|_| VerificationError::LibraryError)?;
        let leaf_certificate = Certificate::from_der(basic_credential.identity())?;
        let now = Utc::now();
        self.verify_leaf_certificate(now, &leaf_certificate)?;

        if let Some(expected_identity) = expected_identity {
            let certificate_subject = leaf_certificate.tbs_certificate.subject.to_string();
            let expected_subject = format!("CN={}", expected_identity);
            if certificate_subject != expected_subject {
                return Err(VerificationError::UnexpectedIdentity {
                    expected: expected_subject,
                    actual: certificate_subject,
                });
            }
        }

        // Check that the public key in the certificate matches the public key
        // in the credential.
        let leaf_certificate_public_key = leaf_certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(VerificationError::LibraryError)?;

        if leaf_certificate_public_key != credential_with_key.signature_key.as_slice() {
            return Err(VerificationError::KeyMismatch);
        }

        Ok(())
    }
}

/// Signing key and certificate mean to issue leaf certificates.
#[derive(Clone)]
pub struct RootCertificateSigner {
    pub(crate) certificate: RootCertificate,
    pub(crate) signing_key: p384::ecdsa::SigningKey,
}

impl RootCertificateSigner {
    /// Create a new root certificate, explicitly providing rng and time.
    pub fn new_with_time_and_rng(
        now: DateTime<Utc>,
        mut rng: &mut (impl CryptoRng + RngCore),
        subject: impl ToString,
    ) -> Result<Self, CertificateError> {
        let profile = Profile::Root;

        let serial_number_bytes = rng.next_u64().to_le_bytes();
        let serial_number = SerialNumber::new(&serial_number_bytes)?;
        let today = now
            .duration_trunc(TimeDelta::days(1))
            .map_err(|_| CertificateError::InvalidSystemTime)?;
        let today_plus_one_year = now
            .duration_trunc(TimeDelta::days(1))
            .map_err(|_| CertificateError::InvalidSystemTime)?
            .checked_add_months(Months::new(12))
            .ok_or(CertificateError::InvalidSystemTime)?;
        let validity = Validity {
            not_before: try_chrono_to_der_time(today)?,
            not_after: try_chrono_to_der_time(today_plus_one_year)?,
        };
        let subject = Name::from_str(&format!("CN={}", subject.to_string()))?;

        // Build the public key info
        let ecdsa_algorithm = AlgorithmIdentifier {
            oid: ECDSA_SHA256_OID,
            parameters: Some(NistP384::OID.into()),
        };
        let signing_key = p384::ecdsa::SigningKey::random(&mut rng);

        let subject_public_key_info: SubjectPublicKeyInfoOwned = SubjectPublicKeyInfo {
            algorithm: ecdsa_algorithm.clone(),
            subject_public_key: BitString::from_bytes(
                signing_key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes(),
            )?,
        };

        let certificate = CertificateBuilder::new(
            profile,
            serial_number,
            validity,
            subject,
            subject_public_key_info,
            &signing_key,
        )?
        .build_with_rng::<ecdsa::der::Signature<NistP384>>(&mut rng)?;

        let root_cert = Self {
            certificate: RootCertificate(certificate),
            signing_key,
        };

        Ok(root_cert)
    }

    // Convenience function to issue a new leaf certificate. Should later only
    // be used in tests.
    pub fn issue_new_leaf_with_time_and_rng(
        &self,
        identifier: impl ToString,
        now: DateTime<Utc>,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<LeafCertificateSigner, CertificateError> {
        let csr_signer = LeafCsrSigner::new_with_rng(identifier, rng)?;

        let certificate = self.sign_csr_with_time_and_rng(now, rng, &csr_signer.csr)?;

        let leaf_signer =
            LeafCertificateSigner::from_csr_signer_and_credential(csr_signer, certificate);

        Ok(leaf_signer)
    }

    /// Sign a certificate signing request explicitly providing the time and
    /// rng.
    pub(crate) fn sign_csr_with_time_and_rng(
        &self,
        now: DateTime<Utc>,
        rng: &mut (impl CryptoRng + RngCore),
        csr: &CertReq,
    ) -> Result<Certificate, CertificateError> {
        let issuer = self.certificate.0.tbs_certificate.issuer.clone();

        // Extract the subject and public key from the CSR
        let subject = csr.info.subject.clone();
        let subject_public_key_info = csr.info.public_key.clone();

        let profile = Profile::Leaf {
            issuer,
            enable_key_agreement: true,
            enable_key_encipherment: false,
        };
        let random_serial_number_bytes = rng.next_u64().to_le_bytes();
        let serial_number = SerialNumber::new(&random_serial_number_bytes)?;
        let today = now
            .duration_trunc(TimeDelta::days(1))
            .map_err(|_| CertificateError::InvalidSystemTime)?;
        let today_plus_one_year = now
            .duration_trunc(TimeDelta::days(1))
            .map_err(|_| CertificateError::InvalidSystemTime)?
            .checked_add_months(Months::new(1))
            .ok_or(CertificateError::InvalidSystemTime)?;
        let validity = Validity {
            not_before: try_chrono_to_der_time(today)?,
            not_after: try_chrono_to_der_time(today_plus_one_year)?,
        };

        let certificate = CertificateBuilder::new(
            profile,
            serial_number,
            validity,
            subject,
            subject_public_key_info,
            &self.signing_key,
        )?
        .build_with_rng::<ecdsa::der::Signature<NistP384>>(rng)?;

        Ok(certificate)
    }

    pub fn into_certificate(self) -> RootCertificate {
        self.certificate
    }
}

impl Signer for RootCertificateSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, openmls_traits::signatures::SignerError> {
        let signature_bytes = <p384::ecdsa::SigningKey as ecdsa::signature::Signer<
            ecdsa::Signature<NistP384>,
        >>::sign(&self.signing_key, payload)
        .to_vec();
        Ok(signature_bytes)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_SECP256R1_SHA256
    }
}
