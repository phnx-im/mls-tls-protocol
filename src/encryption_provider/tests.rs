// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use apqmls::{authentication::ApqSigner, extension::PqtMode};
use chrono::Utc;
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpListener;
use tracing::{span, Instrument, Level};

use crate::{
    encryption_provider::update_policy::{
        TimeBasedUpdatePolicy, TrafficBasedUpdatePolicy, UpdatePolicy,
    },
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

#[expect(clippy::too_many_arguments)]
async fn handle_new_connection(
    server_tcp_socket: TcpStream,
    server_t_signer: ApqSignatureKeyPair,
    server_pq_signer: ApqSignatureKeyPair,
    initial_payload: InitialPayload,
    update_policy: CombinedUpdatePolicy,
    connection: Arc<Mutex<Connection>>,
    global_test_time: Arc<Mutex<DateTime<Utc>>>,
    handshake_encryption: HandshakeEncryption,
    expected_client_id: Uuid,
) -> bool {
    tracing::info!("Handling new connection");
    let (mut encryption_provider, client_id) = match handshake_encryption {
        HandshakeEncryption::Off => {
            EncryptionProvider::<UnprotectedHandshakeState, true>::new_from_stream(
                server_tcp_socket,
                update_policy,
            )
            .unwrap()
            .handshake(connection, server_t_signer, server_pq_signer)
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
            .handshake(connection, server_t_signer, server_pq_signer)
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
            .handshake(connection, server_t_signer, server_pq_signer)
            .await
        }
    }
    .unwrap();

    assert_eq!(client_id.0, expected_client_id.as_bytes());

    tracing::debug!("Completed handshake, sending initial payload");
    encryption_provider
        .send_bytes(initial_payload.0, Utc::now())
        .await
        .unwrap();
    tracing::debug!("Waiting for response");
    while let Some(bytes) = encryption_provider.read_bytes().await.unwrap() {
        tracing::debug!("Received bytes, preparing response");
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
    tracing::info!("Connection closed");
    false
}

#[expect(clippy::too_many_arguments)]
async fn server_task(
    server_listener: TcpListener,
    server_t_signer: ApqSignatureKeyPair,
    server_pq_signer: ApqSignatureKeyPair,
    initial_payload: InitialPayload,
    update_policy: CombinedUpdatePolicy,
    global_test_time: Arc<Mutex<DateTime<Utc>>>,
    handshake_encryption: HandshakeEncryption,
    expected_client_id: Uuid,
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
            server_t_signer.clone(),
            server_pq_signer.clone(),
            initial_payload.clone(),
            update_policy.clone(),
            connection.clone(),
            global_test_time.clone(),
            handshake_encryption.clone(),
            expected_client_id,
        )
        .await;
    }
}

async fn send_test_message(
    encryption_provider: &mut EncryptionProvider<EstablishedState, false>,
    update_policy: &mut CombinedUpdatePolicy,
    message: &str,
    now: DateTime<Utc>,
) -> Vec<u8> {
    let update_was_due = update_policy.update_is_due(now);
    let epoch_before = if update_policy.pq_policy.is_some() {
        encryption_provider.pq_epoch()
    } else {
        encryption_provider.t_epoch()
    };
    encryption_provider
        .send_bytes(message.as_bytes().to_vec(), now)
        .await
        .unwrap();
    if update_was_due {
        let epoch_after = if update_policy.pq_policy.is_some() {
            encryption_provider.pq_epoch()
        } else {
            encryption_provider.t_epoch()
        };
        assert_eq!(epoch_before + 1, epoch_after);
        update_policy.reset_t(now);
    } else {
        // Can't say much about the else case, since the server might have
        // performed an update in the meantime.
    }
    update_policy.increment_bytes_transferred(message.len() as u64);
    encryption_provider.read_bytes().await.unwrap()
}

#[expect(clippy::too_many_arguments)]
async fn client_task(
    server_addr: SocketAddr,
    client_signer: ApqSignatureKeyPair,
    client_id: Uuid,
    server_verifying_key: Vec<u8>,
    initial_payload: InitialPayload,
    mut update_policy: CombinedUpdatePolicy,
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
        client_id,
        server_verifying_key.clone(),
    )
    .await;
    tracing::debug!("Completed handshake, waiting for initial payload");
    let received_initial_payload = InitialPayload(encryption_provider.read_bytes().await.unwrap());
    tracing::debug!("Received initial payload");
    assert_eq!(initial_payload, received_initial_payload);
    let messages = vec![
        "hello",
        "world",
        "this",
        "is",
        "a",
        "test",
        "message",
        "final fin",
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

    //let client_tcp_socket = TcpStream::connect(server_addr).await.unwrap();

    //tracing::info!("Reconnecting to server");
    //let mut encryption_provider = spawn_client_encryption_provider(
    //    handshake_encryption,
    //    client_tcp_socket,
    //    update_policy.clone(),
    //    connection,
    //    client_signer,
    //    client_id,
    //    server_verifying_key,
    //)
    //.await;

    //// We wait for the initial payload to be received. We probably won't need
    //// this in the future
    //tracing::info!("Waiting for initial payload");
    //let _initial_payload = encryption_provider.read_bytes().await.unwrap();

    //let messages = vec![
    //    "hello",
    //    "world",
    //    "this",
    //    "is",
    //    "another",
    //    "test",
    //    "message",
    //    "final fin",
    //];
    //for message in messages.into_iter() {
    //    let mut test_time = *global_test_time.lock().await;
    //    test_time += Duration::from_secs(2);
    //    tracing::info!("Sending message: {}", message);
    //    let response = send_test_message(
    //        &mut encryption_provider,
    //        &mut update_policy,
    //        message,
    //        test_time,
    //    )
    //    .await;
    //    assert_eq!(message.to_uppercase().as_bytes().to_vec(), response);
    //}
}

#[tokio::test]
async fn encryption_provider() {
    tracing_subscriber::fmt::init();

    let server_t_signer =
        ApqSignatureKeyPair::new(PqtMode::ConfOnly.default_ciphersuite().into()).unwrap();
    let server_pq_signer =
        ApqSignatureKeyPair::new(PqtMode::ConfAndAuth.default_ciphersuite().into()).unwrap();

    for mode in [PqtMode::ConfOnly, PqtMode::ConfAndAuth] {
        let now = Utc::now();

        let client_signer = ApqSignatureKeyPair::new(mode.default_ciphersuite().into()).unwrap();
        let client_id = Uuid::new_v4();

        let initial_payload = InitialPayload(b"Initial payload".to_vec());

        fn into_t(policy: impl Into<UpdatePolicy>) -> CombinedUpdatePolicy {
            let policy = policy.into();
            CombinedUpdatePolicy {
                t_policy: policy,
                pq_policy: None,
            }
        }

        fn into_pq(policy: impl Into<UpdatePolicy>) -> CombinedUpdatePolicy {
            let policy = policy.into();
            CombinedUpdatePolicy {
                t_policy: policy.clone(),
                pq_policy: Some(policy),
            }
        }

        let client_time_based_policy = TimeBasedUpdatePolicy::new(Duration::from_secs(5));
        let server_time_based_policy = TimeBasedUpdatePolicy::new(Duration::from_secs(7));
        let client_traffic_based_policy = TrafficBasedUpdatePolicy::new(80);
        let server_traffic_based_policy = TrafficBasedUpdatePolicy::new(100);
        let policies: [(CombinedUpdatePolicy, CombinedUpdatePolicy); 4] = [
            (
                into_t(client_time_based_policy.clone()),
                into_t(server_time_based_policy.clone()),
            ),
            (
                into_pq(client_time_based_policy.clone()),
                into_pq(server_time_based_policy.clone()),
            ),
            (
                into_t(client_traffic_based_policy.clone()),
                into_t(server_traffic_based_policy.clone()),
            ),
            (
                into_pq(client_traffic_based_policy.clone()),
                into_pq(server_traffic_based_policy.clone()),
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
                    server_t_signer.clone(),
                    server_pq_signer.clone(),
                    client_signer.clone(),
                    client_id,
                    initial_payload.clone(),
                    server_policy.clone(),
                    client_policy.clone(),
                    global_test_time,
                    handshake_encryption,
                    mode,
                )
                .await;
            }
        }
    }
}

#[expect(clippy::too_many_arguments)]
async fn start_tasks(
    server_listener: TcpListener,
    server_t_signer: ApqSignatureKeyPair,
    server_pq_signer: ApqSignatureKeyPair,
    client_signer: ApqSignatureKeyPair,
    client_id: Uuid,
    initial_payload: InitialPayload,
    server_policy: CombinedUpdatePolicy,
    client_policy: CombinedUpdatePolicy,
    global_test_time: Arc<Mutex<DateTime<Utc>>>,
    handshake_encryption: HandshakeEncryption,
    mode: PqtMode,
) {
    let addr = server_listener.local_addr().unwrap();
    let server_verifying_key = match mode {
        PqtMode::ConfOnly => server_t_signer.verifying_key().to_bytes(),
        PqtMode::ConfAndAuth => server_pq_signer.verifying_key().to_bytes(),
    };
    let server_task = tokio::spawn(
        server_task(
            server_listener,
            server_t_signer,
            server_pq_signer,
            initial_payload.clone(),
            server_policy.clone(),
            global_test_time.clone(),
            handshake_encryption.clone(),
            client_id,
        )
        .instrument(span!(Level::INFO, "server")),
    );

    let client_task = tokio::spawn(
        client_task(
            addr,
            client_signer,
            client_id,
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
    update_policy: CombinedUpdatePolicy,
    connection: Arc<Mutex<Connection>>,
    client_signer: ApqSignatureKeyPair,
    client_id: Uuid,
    server_verifying_key: Vec<u8>,
) -> EncryptionProvider<EstablishedState, false> {
    match handshake_encryption {
        HandshakeEncryption::Off => {
            EncryptionProvider::<UnprotectedHandshakeState, false>::new_from_stream(
                client_tcp_socket,
                update_policy,
            )
            .unwrap()
            .handshake(
                connection.clone(),
                client_signer.clone(),
                client_id,
                &server_verifying_key,
            )
            .await
        }
        HandshakeEncryption::Psk(psk) => {
            EncryptionProvider::<_, false>::new_with_pre_handshake(
                client_tcp_socket,
                update_policy,
                psk,
            )
            .await
            .unwrap()
            .handshake(
                connection.clone(),
                client_signer.clone(),
                client_id,
                &server_verifying_key,
            )
            .await
        }
        HandshakeEncryption::X25519(handshake) => {
            EncryptionProvider::<_, false>::new_with_pre_handshake(
                client_tcp_socket,
                update_policy,
                handshake,
            )
            .await
            .unwrap()
            .handshake(
                connection.clone(),
                client_signer.clone(),
                client_id,
                &server_verifying_key,
            )
            .await
        }
    }
    .unwrap()
}
