// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
};

use futures::{ready, Sink, Stream};
use thiserror::Error;
use tokio_util::bytes::{Bytes, BytesMut};

use crate::tls_aead::{codec::TlsPacketIn, SecretUpdate};

use super::{TlsAeadCodec, TlsAeadCodecError};

#[derive(Debug, Error)]
pub enum TlsAeadSinkError {
    #[error(transparent)]
    EncryptionFailed(#[from] TlsAeadCodecError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("Poisoned lock error")]
    PoisonedLock,
    #[error("Backpressure: cannot send more data until previous plaintext is processed")]
    Backpressure,
}

impl<T> From<PoisonError<T>> for TlsAeadSinkError {
    fn from(_: PoisonError<T>) -> Self {
        TlsAeadSinkError::PoisonedLock
    }
}

pub(crate) struct TlsAeadSink<S> {
    inner: S,
    cipher: Arc<Mutex<TlsAeadCodec>>,
    buffer: VecDeque<Bytes>,
}

impl<S> TlsAeadSink<S> {
    pub(crate) fn new(inner: S, cipher: Arc<Mutex<TlsAeadCodec>>) -> Self {
        Self {
            inner,
            cipher,
            buffer: VecDeque::new(),
        }
    }

    pub(crate) fn update_traffic_secrets(
        &mut self,
        traffic_secrets: SecretUpdate,
        is_server: bool,
    ) -> Result<(), TlsAeadSinkError> {
        self.cipher
            .lock()?
            .update_traffic_secrets(traffic_secrets, is_server)?;
        Ok(())
    }

    fn try_empty_buffer(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), TlsAeadSinkError>>
    where
        S: Sink<Bytes, Error = std::io::Error> + Unpin,
    {
        ready!(Pin::new(&mut self.inner).poll_ready(cx))?;
        while let Some(item) = self.buffer.pop_front() {
            Pin::new(&mut self.inner).start_send(item)?;
            if !self.buffer.is_empty() {
                ready!(Pin::new(&mut self.inner).poll_ready(cx))?;
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S> Sink<Bytes> for TlsAeadSink<S>
where
    S: Sink<Bytes, Error = std::io::Error> + Unpin,
{
    type Error = TlsAeadSinkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().try_empty_buffer(cx)?);
        Pin::new(&mut self.inner)
            .poll_ready(cx)
            .map_err(TlsAeadSinkError::IoError)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let this = self.get_mut();

        debug_assert!(
            this.buffer.is_empty(),
            "Buffer should be empty before sending new data"
        );

        let mut cipher = this.cipher.lock()?;
        cipher.encrypt(&item, &mut this.buffer)?;

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().try_empty_buffer(cx)?);
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(TlsAeadSinkError::IoError)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().try_empty_buffer(cx)?);
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(TlsAeadSinkError::IoError)
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
            .map_err(|_| TlsAeadSinkError::PoisonedLock)?
            .update_traffic_secrets(traffic_secrets, is_server)?;
        Ok(())
    }
}

impl<S> Stream for TlsAeadStream<S>
where
    S: Stream<Item = Result<TlsPacketIn, std::io::Error>> + Unpin,
{
    type Item = Result<TlsPacketIn, TlsAeadSinkError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match ready!(Pin::new(&mut this.inner).poll_next(cx)) {
            Some(Ok(packet)) => {
                let mut cipher = this
                    .cipher
                    .lock()
                    .map_err(|_| TlsAeadSinkError::PoisonedLock)?;
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
