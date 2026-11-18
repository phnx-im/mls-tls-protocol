// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sans-IO MLS-TLS types for the ordered two-party MLS profile.
//!
//! The application owns sockets, time, authorization, jobs, and durable
//! storage. Drive sessions through [`Engine`] and give each TCP connection a
//! single mutable [`StreamConnection`] owner.
//!
//! The ordered API currently validates configuration and defines the
//! application contract. Protocol operations report an error until their
//! implementation is available. Depend on this crate with
//! `default-features = false` for the ordered API alone.

mod ordered;

pub use ordered::*;

#[cfg(feature = "legacy")]
pub mod authentication;
#[cfg(feature = "legacy")]
pub mod encryption_provider;
#[cfg(feature = "legacy")]
pub mod handshake;
#[cfg(feature = "legacy")]
pub mod mls_handshake;
#[cfg(feature = "legacy")]
pub mod pre_handshake;
#[cfg(feature = "legacy")]
pub mod tls_aead;

#[cfg(feature = "legacy")]
pub use apqmls::authentication::{
    ApqSignatureKeyPair, ApqSignatureScheme, ApqSigner, ApqStorageId,
};
