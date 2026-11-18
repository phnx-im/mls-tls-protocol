// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::component::{GroupInfo, LeafInfo};
use super::handshake::{clear_record, HandshakeType, Protection, Reassembly};
use super::pre_handshake::{open_payload, server_start, ClientStart, Config};
use super::profile::MlsMessage;
use super::{inner_plaintext, ContentType, OuterType, RecordHeader, HEADER_LEN};

#[doc(hidden)]
pub fn fuzz_wire(data: &[u8]) {
    let Some((&mode, input)) = data.split_first() else {
        return;
    };
    match mode % 6 {
        0 => {
            let _ = RecordHeader::decode(input, true);
            let mut rest = input;
            let mut reassembly = Reassembly::default();
            while let Ok(Some(fragment)) = clear_record(rest) {
                if reassembly
                    .push(
                        Protection::Clear,
                        ContentType::Handshake,
                        fragment,
                        decode_handshake,
                    )
                    .is_err()
                {
                    break;
                }
                rest = &rest[HEADER_LEN + fragment.len()..];
            }
        }
        1 => {
            let mut reassembly = Reassembly::default();
            for byte in input.chunks(1) {
                if reassembly
                    .push(
                        Protection::Epoch(1),
                        ContentType::Handshake,
                        byte,
                        decode_handshake,
                    )
                    .is_err()
                {
                    break;
                }
            }
        }
        2 => {
            let _ = MlsMessage::decode(input);
        }
        3 => {
            let _ = LeafInfo::decode(input);
            let _ = GroupInfo::decode(input);
        }
        4 => {
            let _ = ClientStart::decode(input);
            let _ = Config::decode(input);
            let _ = open_payload(input);
        }
        _ => {
            let _ = inner_plaintext(OuterType::Data, input);
            let _ = inner_plaintext(OuterType::Handshake, input);
        }
    }
}

fn decode_handshake(message: super::handshake::Handshake<'_>) -> Result<(), super::WireError> {
    match message.kind {
        HandshakeType::MlsMessage => {
            let _ = MlsMessage::decode(message.body)?;
        }
        HandshakeType::ClientStart => {
            let _ = ClientStart::decode(message.body)?;
        }
        HandshakeType::ServerStart => {
            let _ = server_start(message.body)?;
        }
        HandshakeType::EndOfEarlyData => {}
    }
    Ok(())
}
