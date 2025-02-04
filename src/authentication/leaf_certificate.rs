// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::prelude::{BasicCredential, CredentialWithKey, SignatureScheme};
use p384::{ecdsa::SigningKey, NistP384};
use pkcs8::der::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::*;

/// Signer for a (leaf) certificate signing request (CSR).
pub(crate) struct LeafCsrSigner {
    pub(super) csr: CertReq,
    signing_key: SigningKey,
}

#[cfg(test)]
pub(super) const LEAF_SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ECDSA_SECP384R1_SHA384;

impl LeafCsrSigner {
    /// Create a new leaf certificate signing request (CSR) signer explicitly
    /// providing the rng.
    pub(crate) fn new_with_rng(
        subject: impl ToString,
        mut rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, x509_cert::builder::Error> {
        let subject = Name::from_str(&format!("CN={}", subject.to_string()))?;
        let req_signer = ecdsa::SigningKey::random(&mut rng);

        let csr = RequestBuilder::new(subject, &req_signer)?
            .build_with_rng::<ecdsa::der::Signature<NistP384>>(&mut rng)?;

        let leaf_csr_signer = Self {
            csr,
            signing_key: req_signer,
        };

        Ok(leaf_csr_signer)
    }
}

/// Signer for a leaf certificate signed by a root certificate.
pub struct LeafCertificateSigner {
    pub(crate) certificate: Certificate,
    pub(crate) signing_key: SigningKey,
}

#[derive(Serialize, Deserialize)]
struct SerializableCertificateAndSigner {
    certificate: Vec<u8>,
    signer: Vec<u8>,
}

impl LeafCertificateSigner {
    /// Create a new leaf certificate signer from a certificate signing request
    /// signer and the signed certificate.
    pub(crate) fn from_csr_signer_and_credential(
        csr_signer: LeafCsrSigner,
        certificate: Certificate,
    ) -> Self {
        Self {
            certificate,
            signing_key: csr_signer.signing_key,
        }
    }

    pub(crate) fn mls_credential_with_key(&self) -> Result<CredentialWithKey, CertificateError> {
        let credential = BasicCredential::new(self.certificate.to_der()?).into();

        let signature_key = self
            .signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .into();

        Ok(CredentialWithKey {
            credential,
            signature_key,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, CertificateError> {
        let serialized_cert = self.certificate.to_der()?;
        let serialized_signer = self.signing_key.to_bytes();

        let serializable = SerializableCertificateAndSigner {
            certificate: serialized_cert,
            signer: serialized_signer.to_vec(),
        };

        serde_json::to_vec(&serializable).map_err(|_| CertificateError::LibraryError)
    }

    pub fn deserialize(serialized: &[u8]) -> Result<Self, CertificateError> {
        let deserialized: SerializableCertificateAndSigner =
            serde_json::from_slice(serialized).map_err(|_| CertificateError::LibraryError)?;

        let certificate = Certificate::from_der(&deserialized.certificate)?;
        let signing_key = SigningKey::from_slice(&deserialized.signer)
            .map_err(|_| CertificateError::LibraryError)?;

        Ok(Self {
            certificate,
            signing_key,
        })
    }
}

impl Signer for LeafCertificateSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, openmls_traits::signatures::SignerError> {
        let signature_bytes = <SigningKey as ecdsa::signature::Signer<
            ecdsa::Signature<NistP384>,
        >>::sign(&self.signing_key, payload)
        .to_der()
        .as_bytes()
        .to_vec();
        Ok(signature_bytes)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_SECP384R1_SHA384
    }
}
