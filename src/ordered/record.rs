// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::ops::Range;

use aes_gcm::{aead::AeadInOut, Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384, Sha512};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use super::buf::{PacketBuf, TAG_LEN};
use super::wire::{
    inner_plaintext, protected_plaintext_limit, validate_content, ContentType, OuterType,
    RecordHeader, WireError, HEADER_LEN,
};

const IV_LEN: usize = 12;
const AES_GCM_LIMIT: u64 = 23_726_566; // floor(2^24.5), RFC 8446 section 5.5.
const CONTROL_RESERVE: u64 = 19;

#[derive(Clone, Copy)]
pub(super) enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn expand(self, secret: &[u8], label: &[u8], out: &mut [u8]) -> Result<(), RecordError> {
        if secret.len() != self.size() || out.len() > self.size() {
            return Err(RecordError::Key);
        }
        match self {
            Self::Sha256 => expand::<Hmac<Sha256>>(secret, label, out),
            Self::Sha384 => expand::<Hmac<Sha384>>(secret, label, out),
            Self::Sha512 => expand::<Hmac<Sha512>>(secret, label, out),
        }
    }
}

fn expand<M: KeyInit + Mac>(
    secret: &[u8],
    label: &[u8],
    out: &mut [u8],
) -> Result<(), RecordError> {
    const PREFIX: &[u8] = b"tls13 ";
    let mut mac = <M as KeyInit>::new_from_slice(secret).map_err(|_| RecordError::Key)?;
    mac.update(&(out.len() as u16).to_be_bytes());
    mac.update(&[(PREFIX.len() + label.len()) as u8]);
    mac.update(PREFIX);
    mac.update(label);
    // Empty context and the HKDF block counter. A key or IV fits in one block.
    mac.update(&[0, 1]);
    let mut block = mac.finalize().into_bytes();
    out.copy_from_slice(&block[..out.len()]);
    block.as_mut_slice().zeroize();
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum Algorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Algorithm {
    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    fn record_limit(self) -> u64 {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => AES_GCM_LIMIT,
            Self::ChaCha20Poly1305 => u64::MAX,
        }
    }
}

enum Cipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl Cipher {
    fn new(algorithm: Algorithm, key: &[u8]) -> Result<Self, RecordError> {
        match algorithm {
            Algorithm::Aes128Gcm => Aes128Gcm::new_from_slice(key).map(Self::Aes128),
            Algorithm::Aes256Gcm => Aes256Gcm::new_from_slice(key).map(Self::Aes256),
            Algorithm::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key).map(Self::ChaCha),
        }
        .map_err(|_| RecordError::Key)
    }

    fn seal(
        &self,
        nonce: &[u8; IV_LEN],
        header: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; TAG_LEN], RecordError> {
        let nonce = nonce.into();
        let body = body.into();
        match self {
            Self::Aes128(cipher) => cipher.encrypt_inout_detached(nonce, header, body),
            Self::Aes256(cipher) => cipher.encrypt_inout_detached(nonce, header, body),
            Self::ChaCha(cipher) => cipher.encrypt_inout_detached(nonce, header, body),
        }
        .map(Into::into)
        .map_err(|_| RecordError::Authentication)
    }

    fn open(
        &self,
        nonce: &[u8; IV_LEN],
        header: &[u8],
        body: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), RecordError> {
        let nonce = nonce.into();
        let body = body.into();
        let tag = tag.into();
        match self {
            Self::Aes128(cipher) => cipher.decrypt_inout_detached(nonce, header, body, tag),
            Self::Aes256(cipher) => cipher.decrypt_inout_detached(nonce, header, body, tag),
            Self::ChaCha(cipher) => cipher.decrypt_inout_detached(nonce, header, body, tag),
        }
        .map_err(|_| RecordError::Authentication)
    }
}

pub(super) struct TrafficKey {
    cipher: Cipher,
    iv: Zeroizing<[u8; IV_LEN]>,
    limit: u64,
}

impl TrafficKey {
    pub(super) fn derive(
        hash: Hash,
        algorithm: Algorithm,
        secret: &[u8],
    ) -> Result<Self, RecordError> {
        let mut key = Zeroizing::new([0; 32]);
        let key = &mut key[..algorithm.key_len()];
        let mut iv = Zeroizing::new([0; IV_LEN]);
        hash.expand(secret, b"key", key)?;
        hash.expand(secret, b"iv", &mut *iv)?;
        Ok(Self {
            cipher: Cipher::new(algorithm, key)?,
            iv,
            limit: algorithm.record_limit(),
        })
    }

    fn nonce(&self, sequence: u64) -> Zeroizing<[u8; IV_LEN]> {
        let mut nonce = Zeroizing::new(*self.iv);
        for (byte, mask) in nonce[IV_LEN - 8..].iter_mut().zip(sequence.to_be_bytes()) {
            *byte ^= mask;
        }
        nonce
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum RecordError {
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("invalid traffic secret or key")]
    Key,
    #[error("record authentication failed")]
    Authentication,
    #[error("send key is reserved for control records")]
    Reserve,
    #[error("record key is exhausted or retired")]
    Exhausted,
    #[error("insufficient record buffer space")]
    NoRoom,
}

#[derive(Clone, Copy)]
pub(super) enum Purpose {
    Application,
    PreHandshake,
    Commit,
    EpochKeyUpdate,
    EndOfEarlyData,
    Close,
}

impl Purpose {
    fn content(self, outer: OuterType) -> Result<ContentType, WireError> {
        match (self, outer) {
            (Self::Application, OuterType::Data) => Ok(ContentType::Data),
            (Self::PreHandshake, OuterType::Handshake)
            | (Self::Commit | Self::EpochKeyUpdate | Self::EndOfEarlyData, OuterType::Data) => {
                Ok(ContentType::Handshake)
            }
            (Self::Close, OuterType::Handshake | OuterType::Data) => Ok(ContentType::Alert),
            (
                Self::Application | Self::Commit | Self::EpochKeyUpdate | Self::EndOfEarlyData,
                OuterType::Handshake,
            )
            | (Self::PreHandshake, OuterType::Data) => Err(WireError::Type),
        }
    }

    fn reserved_after(self) -> u64 {
        match self {
            Self::Application => CONTROL_RESERVE,
            Self::Commit => 2,
            Self::PreHandshake | Self::EpochKeyUpdate | Self::EndOfEarlyData => 1,
            Self::Close => 0,
        }
    }
}

pub(super) struct Sealer {
    key: Option<TrafficKey>,
    outer: OuterType,
    sequence: u64,
}

impl Sealer {
    pub(super) fn new(key: TrafficKey, outer: OuterType) -> Self {
        Self {
            key: Some(key),
            outer,
            sequence: 0,
        }
    }

    pub(super) fn seal(
        &mut self,
        purpose: Purpose,
        packet: &mut PacketBuf<'_>,
        padding: usize,
    ) -> Result<(), RecordError> {
        let key = self.key.as_ref().ok_or(RecordError::Exhausted)?;
        if self.sequence >= key.limit {
            return Err(RecordError::Exhausted);
        }
        if self.sequence >= key.limit.saturating_sub(purpose.reserved_after()) {
            return Err(RecordError::Reserve);
        }
        let content = purpose.content(self.outer)?;
        let content_len = packet.bytes().len();
        let plaintext_len = content_len
            .checked_add(1)
            .and_then(|len| len.checked_add(padding))
            .filter(|&len| len <= protected_plaintext_limit(self.outer))
            .ok_or(WireError::TooLong)?;
        validate_content(content, packet.bytes())?;

        let tail = 1 + padding + TAG_LEN;
        let frame = packet
            .frame_mut(HEADER_LEN, tail)
            .ok_or(RecordError::NoRoom)?;
        let (header, body) = frame.split_at_mut(HEADER_LEN);
        header.copy_from_slice(
            &RecordHeader {
                kind: self.outer,
                len: plaintext_len + TAG_LEN,
            }
            .encode()?,
        );
        let (plaintext, tag) = body.split_at_mut(plaintext_len);
        plaintext[content_len] = content as u8;
        plaintext[content_len + 1..].fill(0);
        match key
            .cipher
            .seal(&key.nonce(self.sequence), header, plaintext)
        {
            Ok(encrypted_tag) => tag.copy_from_slice(&encrypted_tag),
            Err(error) => {
                self.key = None;
                body.zeroize();
                return Err(error);
            }
        }
        self.sequence = self.sequence.checked_add(1).ok_or(RecordError::Exhausted)?;
        if let Purpose::Close = purpose {
            self.key = None;
        }
        packet.include_frame(HEADER_LEN, tail);
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Opened {
    pub(super) content: ContentType,
    pub(super) payload: Range<usize>,
    pub(super) consumed: usize,
}

pub(super) struct Opener {
    key: Option<TrafficKey>,
    outer: OuterType,
    sequence: u64,
}

impl Opener {
    pub(super) fn new(key: TrafficKey, outer: OuterType) -> Self {
        Self {
            key: Some(key),
            outer,
            sequence: 0,
        }
    }

    pub(super) fn open(&mut self, input: &mut [u8]) -> Result<Option<Opened>, RecordError> {
        let result = self.open_record(input);
        match &result {
            Ok(Some(opened)) if opened.content == ContentType::Alert => self.key = None,
            Err(_) => self.key = None,
            Ok(_) => {}
        }
        result
    }

    fn open_record(&mut self, input: &mut [u8]) -> Result<Option<Opened>, RecordError> {
        let key = self.key.as_ref().ok_or(RecordError::Exhausted)?;
        if input.len() < HEADER_LEN {
            return Ok(None);
        }
        let header = RecordHeader::decode(input, true)?;
        if header.kind != self.outer {
            return Err(WireError::Type.into());
        }
        let plaintext_len = header
            .len
            .checked_sub(TAG_LEN)
            .ok_or(WireError::Truncated)?;
        if plaintext_len == 0 {
            return Err(WireError::Invalid.into());
        }
        if plaintext_len > protected_plaintext_limit(header.kind) {
            return Err(WireError::TooLong.into());
        }
        let consumed = HEADER_LEN + header.len;
        let Some(record) = input.get_mut(..consumed) else {
            return Ok(None);
        };
        let (aad, body) = record.split_at_mut(HEADER_LEN);
        let (plaintext, tag) = body.split_at_mut(plaintext_len);
        let tag: &[u8; TAG_LEN] = (&*tag).try_into().map_err(|_| WireError::Truncated)?;
        let next = self.sequence.checked_add(1).ok_or(RecordError::Exhausted)?;
        let result = key
            .cipher
            .open(&key.nonce(self.sequence), aad, plaintext, tag)
            .and_then(|()| Ok(inner_plaintext(header.kind, plaintext)?));
        match result {
            Ok((content, len)) => {
                self.sequence = next;
                plaintext[len..].zeroize();
                Ok(Some(Opened {
                    content,
                    payload: HEADER_LEN..HEADER_LEN + len,
                    consumed,
                }))
            }
            Err(error) => {
                plaintext.zeroize();
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests;
