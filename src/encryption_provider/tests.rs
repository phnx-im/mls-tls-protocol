// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::Utc;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpListener;
use tracing::{span, Instrument, Level};

use crate::{
    authentication::root_certificate::{RootCertificateSigner, SERVER_ROOT_IDENTITY},
    encryption_provider::update_policy::{TimeBasedUpdatePolicy, TrafficBasedUpdatePolicy},
};

use super::*;

#[derive(Debug, Clone, PartialEq)]
struct InitialPayload(Vec<u8>);

async fn handle_new_connection(
    server_tcp_socket: TcpStream,
    serialized_root_certificate: Vec<u8>,
    serialized_server_signer: Vec<u8>,
    initial_payload: InitialPayload,
    update_policy: UpdatePolicy,
    connection: Arc<Mutex<Connection>>,
    global_test_time: Arc<Mutex<DateTime<Utc>>>,
) -> bool {
    let server_encryption_provider =
        EncryptionProvider::<_, true>::new_from_stream(server_tcp_socket, update_policy).unwrap();
    let (mut encryption_provider, _) = server_encryption_provider
        .handshake(
            connection,
            serialized_root_certificate,
            serialized_server_signer,
        )
        .await
        .unwrap();
    tracing::info!("Sending initial payload");
    encryption_provider
        .send_bytes(initial_payload.0, Utc::now())
        .await
        .unwrap();
    while let Some(bytes) = encryption_provider.read_bytes().await.unwrap() {
        let response = String::from_utf8(bytes).unwrap().to_uppercase();
        let now = *global_test_time.lock().await;
        encryption_provider
            .send_bytes(response.as_bytes().to_vec(), now)
            .await
            .unwrap();
        if response == "FINAL FIN" {
            return true;
        }
    }
    false
}

async fn server_task(
    server_listener: TcpListener,
    serialized_root_certificate: Vec<u8>,
    serialized_server_signer: Vec<u8>,
    initial_payload: InitialPayload,
    update_policy: UpdatePolicy,
    global_test_time: Arc<Mutex<DateTime<Utc>>>,
) {
    let mut connection = Connection::open_in_memory().unwrap();
    EncryptionProvider::<InitialProviderState, true>::initialize_storage(&mut connection).unwrap();
    let connection = Arc::new(Mutex::new(connection));
    let mut final_connection = false;
    while !final_connection {
        let (server_tcp_socket, _) = server_listener.accept().await.unwrap();
        final_connection = handle_new_connection(
            server_tcp_socket,
            serialized_root_certificate.clone(),
            serialized_server_signer.clone(),
            initial_payload.clone(),
            update_policy.clone(),
            connection.clone(),
            global_test_time.clone(),
        )
        .await;
    }
}

async fn send_test_message(
    encryption_provider: &mut EncryptionProvider<EstablishedState, false>,
    update_policy: &mut UpdatePolicy,
    message: &str,
    now: DateTime<Utc>,
) -> Vec<u8> {
    let update_was_due = update_policy.update_is_due(now);
    let epoch_before = encryption_provider.epoch();
    encryption_provider
        .send_bytes(message.as_bytes().to_vec(), now)
        .await
        .unwrap();
    if update_was_due {
        let epoch_after = encryption_provider.epoch();
        assert_eq!(epoch_before + 1, epoch_after);
        update_policy.reset(now);
    } else {
        // Can't say much about the else case, since the server might have
        // performed an update in the meantime.
    }
    update_policy.increment_bytes_transferred(message.len() as u64);
    encryption_provider.read_bytes().await.unwrap()
}

async fn client_task(
    server_addr: SocketAddr,
    serialized_root_certificate: Vec<u8>,
    serialized_client_signer: Vec<u8>,
    initial_payload: InitialPayload,
    mut update_policy: UpdatePolicy,
    global_test_time: Arc<Mutex<DateTime<Utc>>>,
) {
    let mut connection = Connection::open_in_memory().unwrap();
    EncryptionProvider::<InitialProviderState, false>::initialize_storage(&mut connection).unwrap();
    let connection = Arc::new(Mutex::new(connection));
    let client_tcp_socket = TcpStream::connect(server_addr).await.unwrap();
    let client_encryption_provider =
        EncryptionProvider::<_, false>::new_from_stream(client_tcp_socket, update_policy.clone())
            .unwrap();
    let mut encryption_provider = client_encryption_provider
        .handshake(
            connection.clone(),
            serialized_root_certificate.clone(),
            serialized_client_signer.clone(),
        )
        .await
        .unwrap();
    let received_initial_payload = InitialPayload(encryption_provider.read_bytes().await.unwrap());
    assert_eq!(initial_payload, received_initial_payload);
    let messages = vec![
        "hello", "world", "this", "is", "a", "test", "message", "fin",
    ];
    for message in messages.into_iter() {
        let mut test_time = *global_test_time.lock().await;
        test_time += Duration::from_secs(2);
        let response = send_test_message(
            &mut encryption_provider,
            &mut update_policy,
            message,
            test_time,
        )
        .await;
        assert_eq!(message.to_uppercase().as_bytes().to_vec(), response);
    }

    // shut down the connection s.t. we can resume
    encryption_provider.shutdown().await.unwrap();

    let client_tcp_socket = TcpStream::connect(server_addr).await.unwrap();
    let encryption_provider =
        EncryptionProvider::<_, false>::new_from_stream(client_tcp_socket, update_policy.clone())
            .unwrap();
    let mut encryption_provider = encryption_provider
        .handshake(
            connection,
            serialized_root_certificate,
            serialized_client_signer,
        )
        .await
        .unwrap();

    // We wait for the initial payload to be received. We probably won't need
    // this in the future
    tracing::info!("Waiting for initial payload");
    let _initial_payload = encryption_provider.read_bytes().await.unwrap();

    let messages = vec![
        "hello",
        "world",
        "this",
        "is",
        "another",
        "test",
        "message",
        "final fin",
    ];
    for message in messages.into_iter() {
        let mut test_time = *global_test_time.lock().await;
        test_time += Duration::from_secs(2);
        tracing::info!("Sending message: {}", message);
        let response = send_test_message(
            &mut encryption_provider,
            &mut update_policy,
            message,
            test_time,
        )
        .await;
        assert_eq!(message.to_uppercase().as_bytes().to_vec(), response);
    }
}

#[tokio::test]
async fn encryption_provider() {
    tracing_subscriber::fmt::init();

    let seed_passphrase = [0u8; 32];
    let now = Utc::now();
    let rng = &mut ChaCha20Rng::from_seed(seed_passphrase);

    let root_signer = RootCertificateSigner::new_with_time_and_rng(now, rng, SERVER_ROOT_IDENTITY)
        .expect("failed to create root signer");

    let server_signer = root_signer
        .issue_new_leaf_with_time_and_rng("server", now, rng)
        .expect("failed to create server signer");
    let client_signer = root_signer
        .issue_new_leaf_with_time_and_rng("client", now, rng)
        .expect("failed to create client signer");

    let serialized_root_certificate = root_signer.certificate.serialize().unwrap();
    let serialized_server_signer = server_signer.serialize().unwrap();
    let serialized_client_signer = client_signer.serialize().unwrap();

    let initial_payload = InitialPayload(b"Initial payload".to_vec());

    let policies = [
        (
            TimeBasedUpdatePolicy::new(Duration::from_secs(5)).into(),
            TimeBasedUpdatePolicy::new(Duration::from_secs(7)).into(),
        ),
        (
            TrafficBasedUpdatePolicy::new(80).into(),
            TrafficBasedUpdatePolicy::new(100).into(),
        ),
    ];

    for (client_policy, server_policy) in policies {
        let global_test_time = Arc::new(Mutex::new(now));

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap(); // Bind to any available port
        let addr = server_listener.local_addr().unwrap();

        // Start a server. The server will echo back the received messages in
        // uppercase. If it receives "FIN", it will close the connection. If it
        // receives "FINAL FIN", it will close the connection and stop the server.
        let server_test_time = global_test_time.clone();
        let server_root_cert_copy = serialized_root_certificate.clone();
        let server_signer_copy = serialized_server_signer.clone();
        let server_initial_payload_copy = initial_payload.clone();
        let server_task = tokio::spawn(
            async move {
                server_task(
                    server_listener,
                    server_root_cert_copy,
                    server_signer_copy,
                    server_initial_payload_copy,
                    server_policy,
                    server_test_time,
                )
                .await;
            }
            .instrument(span!(Level::INFO, "server")),
        );

        let client_root_cert_copy = serialized_root_certificate.clone();
        let client_signer_copy = serialized_client_signer.clone();
        let client_initial_payload_copy = initial_payload.clone();
        let client_task = tokio::spawn(
            async move {
                client_task(
                    addr,
                    client_root_cert_copy,
                    client_signer_copy,
                    client_initial_payload_copy,
                    client_policy,
                    global_test_time,
                )
                .await;
            }
            .instrument(span!(Level::INFO, "client")),
        );

        tokio::try_join!(client_task, server_task).unwrap();
    }
}
