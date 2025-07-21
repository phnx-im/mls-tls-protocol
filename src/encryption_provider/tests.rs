// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::Utc;
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpListener;
use tracing::{span, Instrument, Level};

use crate::{
    authentication::LEAF_SIGNATURE_SCHEME,
    encryption_provider::update_policy::{TimeBasedUpdatePolicy, TrafficBasedUpdatePolicy},
    pre_handshake::{psk::Psk, x25519::X25519Handshake},
};

use super::*;

#[derive(Debug, Clone)]
enum HandshakeEncryption {
    Off,
    Psk(Psk),
    X25519(X25519Handshake),
}

#[derive(Debug, Clone, PartialEq)]
struct InitialPayload(Vec<u8>);

async fn handle_new_connection(
    server_tcp_socket: TcpStream,
    server_signer: SignatureKeyPair,
    initial_payload: InitialPayload,
    update_policy: UpdatePolicy,
    connection: Arc<Mutex<Connection>>,
    global_test_time: Arc<Mutex<DateTime<Utc>>>,
    handshake_encryption: HandshakeEncryption,
) -> bool {
    tracing::info!("Handling new connection");
    let (mut encryption_provider, _) = match handshake_encryption {
        HandshakeEncryption::Off => {
            EncryptionProvider::<UnprotectedHandshakeState, true>::new_from_stream(
                server_tcp_socket,
                update_policy,
            )
            .unwrap()
            .handshake(connection, server_signer)
            .await
        }
        HandshakeEncryption::Psk(psk) => {
            EncryptionProvider::<_, true>::new_with_pre_handshake(
                server_tcp_socket,
                update_policy,
                psk,
            )
            .await
            .unwrap()
            .handshake(connection, server_signer)
            .await
        }
        HandshakeEncryption::X25519(handshake) => {
            EncryptionProvider::<_, true>::new_with_pre_handshake(
                server_tcp_socket,
                update_policy,
                handshake,
            )
            .await
            .unwrap()
            .handshake(connection, server_signer)
            .await
        }
    }
    .unwrap();
    tracing::info!("Completed handshake");
    encryption_provider
        .send_bytes(initial_payload.0, Utc::now())
        .await
        .unwrap();
    tracing::info!("Waiting for response");
    while let Some(bytes) = encryption_provider.read_bytes().await.unwrap() {
        tracing::info!("Received bytes, preparing response");
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
    tracing::info!("Done");
    false
}

async fn server_task(
    server_listener: TcpListener,
    server_signer: SignatureKeyPair,
    initial_payload: InitialPayload,
    update_policy: UpdatePolicy,
    global_test_time: Arc<Mutex<DateTime<Utc>>>,
    handshake_encryption: HandshakeEncryption,
) {
    let mut connection = Connection::open_in_memory().unwrap();
    EncryptionProvider::<UnprotectedHandshakeState, true>::initialize_storage(&mut connection)
        .unwrap();
    let connection = Arc::new(Mutex::new(connection));
    let mut final_connection = false;
    while !final_connection {
        let (server_tcp_socket, _) = server_listener.accept().await.unwrap();
        final_connection = handle_new_connection(
            server_tcp_socket,
            server_signer.clone(),
            initial_payload.clone(),
            update_policy.clone(),
            connection.clone(),
            global_test_time.clone(),
            handshake_encryption.clone(),
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
    client_signer: SignatureKeyPair,
    server_verifying_key: Vec<u8>,
    initial_payload: InitialPayload,
    mut update_policy: UpdatePolicy,
    global_test_time: Arc<Mutex<DateTime<Utc>>>,
    handshake_encryption: HandshakeEncryption,
) {
    tracing::info!("Connecting to server");
    let mut connection = Connection::open_in_memory().unwrap();
    EncryptionProvider::<UnprotectedHandshakeState, false>::initialize_storage(&mut connection)
        .unwrap();
    let connection = Arc::new(Mutex::new(connection));
    let client_tcp_socket = TcpStream::connect(server_addr).await.unwrap();

    tracing::info!(
        "Spawning client encryption provider with handshake encryption: {:?}",
        handshake_encryption
    );
    let mut encryption_provider = spawn_client_encryption_provider(
        handshake_encryption.clone(),
        client_tcp_socket,
        update_policy.clone(),
        connection.clone(),
        client_signer.clone(),
        server_verifying_key.clone(),
    )
    .await;
    tracing::info!("Completed handshake");
    let received_initial_payload = InitialPayload(encryption_provider.read_bytes().await.unwrap());
    tracing::info!("Received initial payload");
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

    tracing::info!("Reconnecting to server");
    let mut encryption_provider = spawn_client_encryption_provider(
        handshake_encryption,
        client_tcp_socket,
        update_policy.clone(),
        connection,
        client_signer,
        server_verifying_key,
    )
    .await;

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

    let now = Utc::now();

    let server_signer = SignatureKeyPair::new(LEAF_SIGNATURE_SCHEME).unwrap();
    let client_signer = SignatureKeyPair::new(LEAF_SIGNATURE_SCHEME).unwrap();

    let initial_payload = InitialPayload(b"Initial payload".to_vec());

    let policies: [(UpdatePolicy, UpdatePolicy); 2] = [
        (
            TimeBasedUpdatePolicy::new(Duration::from_secs(5)).into(),
            TimeBasedUpdatePolicy::new(Duration::from_secs(7)).into(),
        ),
        (
            TrafficBasedUpdatePolicy::new(80).into(),
            TrafficBasedUpdatePolicy::new(100).into(),
        ),
    ];

    let handshake_encryption_options = [
        HandshakeEncryption::Off,
        HandshakeEncryption::Psk(Psk::new(b"test_psk".to_vec())),
        HandshakeEncryption::X25519(X25519Handshake),
    ];

    for (client_policy, server_policy) in policies {
        for handshake_encryption in handshake_encryption_options.clone() {
            let global_test_time = Arc::new(Mutex::new(now));

            let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap(); // Bind to any available port
            start_tasks(
                server_listener,
                server_signer.clone(),
                client_signer.clone(),
                initial_payload.clone(),
                server_policy.clone(),
                client_policy.clone(),
                global_test_time,
                handshake_encryption,
            )
            .await;
        }
    }
}

async fn start_tasks(
    server_listener: TcpListener,
    server_signer: SignatureKeyPair,
    client_signer: SignatureKeyPair,
    initial_payload: InitialPayload,
    server_policy: UpdatePolicy,
    client_policy: UpdatePolicy,
    global_test_time: Arc<Mutex<DateTime<Utc>>>,
    handshake_encryption: HandshakeEncryption,
) {
    let addr = server_listener.local_addr().unwrap();
    let server_verifying_key = server_signer.public().to_vec();
    let server_task = tokio::spawn(
        server_task(
            server_listener,
            server_signer,
            initial_payload.clone(),
            server_policy.clone(),
            global_test_time.clone(),
            handshake_encryption.clone(),
        )
        .instrument(span!(Level::INFO, "server")),
    );

    let client_task = tokio::spawn(
        client_task(
            addr,
            client_signer,
            server_verifying_key,
            initial_payload,
            client_policy,
            global_test_time,
            handshake_encryption,
        )
        .instrument(span!(Level::INFO, "client")),
    );

    tokio::try_join!(server_task, client_task).unwrap();
}

async fn spawn_client_encryption_provider(
    handshake_encryption: HandshakeEncryption,
    client_tcp_socket: TcpStream,
    update_policy: UpdatePolicy,
    connection: Arc<Mutex<Connection>>,
    client_signer: SignatureKeyPair,
    server_verifying_key: Vec<u8>,
) -> EncryptionProvider<EstablishedState, false> {
    match handshake_encryption {
        HandshakeEncryption::Off => {
            EncryptionProvider::<UnprotectedHandshakeState, false>::new_from_stream(
                client_tcp_socket,
                update_policy.clone(),
            )
            .unwrap()
            .handshake(
                connection.clone(),
                client_signer.clone(),
                &server_verifying_key,
            )
            .await
        }
        HandshakeEncryption::Psk(psk) => {
            EncryptionProvider::<_, false>::new_with_pre_handshake(
                client_tcp_socket,
                update_policy.clone(),
                psk,
            )
            .await
            .unwrap()
            .handshake(
                connection.clone(),
                client_signer.clone(),
                &server_verifying_key,
            )
            .await
        }
        HandshakeEncryption::X25519(handshake) => {
            EncryptionProvider::<_, false>::new_with_pre_handshake(
                client_tcp_socket,
                update_policy.clone(),
                handshake,
            )
            .await
            .unwrap()
            .handshake(
                connection.clone(),
                client_signer.clone(),
                &server_verifying_key,
            )
            .await
        }
    }
    .unwrap()
}
