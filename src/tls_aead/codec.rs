// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_util::{
    bytes::{BufMut, Bytes, BytesMut},
    codec::{Decoder, Encoder},
};

use crate::tls_aead::{TLS_APP_DATA, TLS_HDR_SIZE, TLS_VERSION};

pub struct TlsPacketIn {
    pub header: BytesMut,
    pub data: BytesMut,
}

impl TlsPacketIn {
    pub fn msg_type(&self) -> u8 {
        self.header[0]
    }

    #[cfg(test)]
    pub fn version(&self) -> u16 {
        u16::from_be_bytes(self.header[1..3].try_into().unwrap())
    }
}

pub struct TlsFrameCodec;

impl Decoder for TlsFrameCodec {
    type Item = TlsPacketIn;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < TLS_HDR_SIZE {
            return Ok(None);
        }

        let length = u16::from_be_bytes(
            src[3..5]
                .try_into()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        );
        if src.len() < length as usize + TLS_HDR_SIZE {
            return Ok(None);
        }

        Ok(Some(TlsPacketIn {
            header: src.split_to(TLS_HDR_SIZE),
            data: src.split_to(length as usize),
        }))
    }
}

impl Encoder<Bytes> for TlsFrameCodec {
    type Error = std::io::Error;

    fn encode(&mut self, data: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let length = data.len() as u16;
        dst.reserve(TLS_HDR_SIZE + length as usize);
        dst.put_u8(TLS_APP_DATA);
        dst.put_u16(TLS_VERSION);
        dst.put_u16(length);
        dst.put_slice(&data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_aead::TLS_APP_DATA;
    use tokio_util::codec::Decoder;

    #[test]
    fn test_tls_frame_codec() {
        let mut codec = TlsFrameCodec {};
        let mut buf = BytesMut::new();
        buf.put_u8(TLS_APP_DATA);
        buf.put_u16(TLS_VERSION);
        buf.put_u16(5);
        buf.put_slice(b"hello");
        let buf2 = buf.clone();

        let packet = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(packet.msg_type(), TLS_APP_DATA);
        assert_eq!(packet.version(), TLS_VERSION);
        assert_eq!(packet.data.iter().as_slice(), b"hello");

        let mut buf3 = BytesMut::new();
        codec.encode(packet.data.freeze(), &mut buf3).unwrap();
        assert_eq!(buf2, buf3);
    }
}
