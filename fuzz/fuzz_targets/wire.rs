// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

fn main() {
    afl::fuzz!(|data: &[u8]| mls_tls_protocol::fuzz_wire(data));
}
