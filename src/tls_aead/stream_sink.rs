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
    pending_plaintext: Option<Bytes>,
}

impl<S> TlsAeadSink<S> {
    pub(crate) fn new(inner: S, cipher: Arc<Mutex<TlsAeadCodec>>) -> Self {
        Self {
            inner,
            cipher,
            buffer: VecDeque::new(),
            pending_plaintext: None,
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
}

impl<S> Sink<Bytes> for TlsAeadSink<S>
where
    S: Sink<Bytes, Error = std::io::Error> + Unpin,
{
    type Error = TlsAeadSinkError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();

        // Only allow `start_send()` if no pending plaintext is waiting to be processed
        if this.pending_plaintext.is_some() {
            return Poll::Pending;
        }

        // Ask inner sink if it's ready
        Pin::new(&mut this.inner)
            .poll_ready(cx)
            .map_err(TlsAeadSinkError::IoError)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let this = self.get_mut();
        if this.pending_plaintext.is_some() {
            // Should have called `poll_ready` first
            return Err(TlsAeadSinkError::Backpressure);
        }
        this.pending_plaintext = Some(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();

        // If we have pending plaintext to encrypt, do it now
        if let Some(plaintext) = this.pending_plaintext.take() {
            let mut cipher = this.cipher.lock()?;
            let ciphertexts = cipher.encrypt(&plaintext)?.into_iter().map(Bytes::from);
            this.buffer.extend(ciphertexts);
        }

        // Drive out buffered ciphertexts
        while let Some(fragment) = this.buffer.pop_front() {
            ready!(Pin::new(&mut this.inner).poll_ready(cx))?;
            Pin::new(&mut this.inner).start_send(fragment)?;
        }

        // Ensure the inner sink is fully flushed
        Pin::new(&mut this.inner)
            .poll_flush(cx)
            .map_err(TlsAeadSinkError::IoError)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx)?);
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
