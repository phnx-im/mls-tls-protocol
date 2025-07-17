// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/// # MLS-TLS Protocol
/// This crate provides an implementation of the MLS-TLS protocol
/// Currently only TLS application data encoding is implemented
/// as a submodule
pub mod authentication;
pub mod encryption_provider;
pub mod handshake;
pub mod mls_handshake;
pub mod pre_handshake;
pub mod tls_aead;
