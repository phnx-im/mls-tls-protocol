// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sans-IO MLS-TLS types for the ordered two-party MLS profile.
//!
//! The application owns sockets, time, authorization, jobs, and durable
//! storage. Drive sessions through [`Engine`] and give each TCP connection a
//! single mutable [`StreamConnection`] owner.
//!
//! The ordered API currently validates configuration. Session and record
//! processing are still under development. The guides below describe the
//! intended TCP integration.

#![doc = include_str!("../docs/architecture.md")]
#![doc = include_str!("../docs/storage.md")]

mod ordered;

pub use ordered::*;
