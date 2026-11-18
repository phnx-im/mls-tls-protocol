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
//! implementation is available.

mod ordered;

pub use ordered::*;
