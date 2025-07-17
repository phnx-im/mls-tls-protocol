// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
};

use futures::{ready, Sink, Stream};
use thiserror::Error;
use tokio_util::bytes::{Bytes, BytesMut};

use crate::tls_aead::{codec::TlsPacketIn, SecretUpdate};

use super::{TlsAeadCodec, TlsAeadCodecError};

#[derive(Debug, Error)]
pub enum TlsAeadSinkError {
    #[error(transparent)]
    EncryptionError(#[from] TlsAeadCodecError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("Poisoned lock error")]
    PoisonedLockError,
}

pub(crate) struct TlsAeadSink<S> {
    inner: S,
    cipher: Arc<Mutex<TlsAeadCodec>>,
}

impl<S> TlsAeadSink<S> {
    pub(crate) fn new(inner: S, cipher: Arc<Mutex<TlsAeadCodec>>) -> Self {
        Self { inner, cipher }
    }

    pub(crate) fn update_traffic_secrets(
        &mut self,
        traffic_secrets: SecretUpdate,
        is_server: bool,
    ) -> Result<(), TlsAeadSinkError> {
        self.cipher
            .lock()
            .map_err(|_| TlsAeadSinkError::PoisonedLockError)?
            .update_traffic_secrets(traffic_secrets, is_server)?;
        Ok(())
    }
}

impl<S> Sink<Bytes> for TlsAeadSink<S>
where
    S: Sink<Bytes, Error = std::io::Error> + Unpin,
{
    type Error = TlsAeadSinkError;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_ready(cx)
            .map_err(From::from)
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let sink = self.get_mut();
        let mut cipher = sink
            .cipher
            .lock()
            .map_err(|_| TlsAeadSinkError::PoisonedLockError)?;

        let ciphertexts = cipher.encrypt(&item)?;
        drop(cipher); // Release the lock before sending
        for ciphertext in ciphertexts {
            Pin::new(&mut sink.inner).start_send(ciphertext.into())?;
        }
        Ok(())
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_flush(cx)
            .map_err(From::from)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_close(cx)
            .map_err(From::from)
    }
}

pub(crate) struct TlsAeadStream<S> {
    inner: S,
    cipher: Arc<Mutex<TlsAeadCodec>>,
}

impl<S> TlsAeadStream<S> {
    pub(crate) fn new(inner: S, cipher: Arc<Mutex<TlsAeadCodec>>) -> Self {
        Self { inner, cipher }
    }

    pub(crate) fn update_traffic_secrets(
        &mut self,
        traffic_secrets: SecretUpdate,
        is_server: bool,
    ) -> Result<(), TlsAeadSinkError> {
        self.cipher
            .lock()
            .map_err(|_| TlsAeadSinkError::PoisonedLockError)?
            .update_traffic_secrets(traffic_secrets, is_server)?;
        Ok(())
    }
}

impl<S> Stream for TlsAeadStream<S>
where
    S: Stream<Item = Result<TlsPacketIn, std::io::Error>> + Unpin,
{
    type Item = Result<TlsPacketIn, TlsAeadSinkError>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match ready!(Pin::new(&mut this.inner).poll_next(cx)) {
            Some(Ok(packet)) => {
                let mut cipher = this
                    .cipher
                    .lock()
                    .map_err(|_| TlsAeadSinkError::PoisonedLockError)?;
                match cipher.decrypt(&packet.data, &packet.header) {
                    Ok(plaintext) => {
                        let packet = TlsPacketIn {
                            header: packet.header,
                            data: BytesMut::from(plaintext.as_slice()),
                        };
                        Poll::Ready(Some(Ok(packet)))
                    }
                    Err(e) => Poll::Ready(Some(Err(e.into()))),
                }
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            None => Poll::Ready(None),
        }
    }
}
