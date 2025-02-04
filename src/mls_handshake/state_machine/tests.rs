// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::mls_handshake::{ClientHandshake, ClientHandshakeState, SecretUpdate, ServerHandshake};

use super::*;

use openmls_sqlite_storage::Connection;

#[test]
fn handshake() {
    let seed = [0u8; 32];

    let mut client_connection = Connection::open_in_memory().unwrap();
    ClientHandshakeState::create_table(&client_connection).unwrap();
    let mut server_connection = Connection::open_in_memory().unwrap();

    initialize_storage(&mut client_connection).unwrap();
    initialize_storage(&mut server_connection).unwrap();
    let mut client_provider = Provider::from(&mut client_connection);
    client_provider.initialize_storage().unwrap();
    let mut server_provider = Provider::from(&mut server_connection);
    server_provider.initialize_storage().unwrap();

    let test_profile_id = Uuid::new_v4();

    // Test initial handshake
    let (client_state, client_hello, client_leaf_signer) =
        ClientHandshake::start_from_seed(&mut client_connection, seed, test_profile_id).unwrap();

    let (mut server_state, server_traffic_secrets, server_hello, server_leaf_signer) =
        ServerHandshake::start_from_seed(&mut server_connection, seed, &client_hello).unwrap();

    let (mut client_state, client_traffic_secrets) = client_state
        .receive_server_hello(&client_connection, &server_hello)
        .unwrap();

    assert_eq!(client_traffic_secrets, server_traffic_secrets);

    // Test connection update

    // Server updates and requests update back. Since the server requests an
    // update back, the traffic secrets will never be used, as the client will
    // immediately send an update itself after processing the server's update.
    let connection_update = server_state
        .update(&mut server_connection, &server_leaf_signer, true)
        .unwrap();

    let (client_traffic_secret, client_message_bytes) = client_state
        .receive_signaling_message(
            &mut client_connection,
            &client_leaf_signer,
            &connection_update,
        )
        .unwrap();

    // The client should return the client traffic secret
    let Some(SecretUpdate::ClientSecret(client_secret)) = client_traffic_secret else {
        panic!("Expected client traffic secret");
    };

    // The client should respond with a connection update of its own
    println!("Processing connection update");
    let (server_traffic_secrets, server_message_bytes) = server_state
        .receive_signaling_message(
            &mut server_connection,
            &server_leaf_signer,
            &client_message_bytes.unwrap(),
        )
        .unwrap();

    // The (only) message should be the epoch confirmation
    let (secret_update, client_message_bytes) = client_state
        .receive_signaling_message(
            &mut client_connection,
            &client_leaf_signer,
            &server_message_bytes.unwrap(),
        )
        .unwrap();

    // Here, the client should return the server traffic secret
    let Some(SecretUpdate::ServerSecret(server_secret)) = secret_update else {
        panic!("Expected server traffic secret");
    };

    // The client should return no messages
    assert!(client_message_bytes.is_none());

    let client_traffic_secrets = TrafficSecrets {
        client_secret: client_secret.clone(),
        server_secret: server_secret.clone(),
    };

    // Client and server should have the same traffic secrets
    assert_eq!(client_traffic_secrets, server_traffic_secrets);

    // Client updates and doesn't request an update back
    let (client_secret, connection_update) = client_state
        .update(&mut client_connection, &client_leaf_signer, false)
        .unwrap();

    let (server_traffic_secrets, server_message_bytes) = server_state
        .receive_signaling_message(
            &mut server_connection,
            &server_leaf_signer,
            &connection_update,
        )
        .unwrap();

    // The response should be the epoch confirmation
    let (secret_update, value2) = client_state
        .receive_signaling_message(
            &mut client_connection,
            &client_leaf_signer,
            &server_message_bytes.unwrap(),
        )
        .unwrap();

    // Client shouldn't return a message when processing the epoch confirmation
    assert!(value2.is_none());

    let Some(SecretUpdate::ServerSecret(server_secret)) = secret_update else {
        panic!("Expected server traffic secret");
    };

    let client_traffic_secrets = TrafficSecrets {
        client_secret: client_secret.clone(),
        server_secret: server_secret.clone(),
    };

    // Client and server should have the same traffic secrets
    assert_eq!(client_traffic_secrets, server_traffic_secrets);

    // Test resumption
    let (client_traffic_secrets, resumption) = client_state
        .resume(&mut client_connection, &client_leaf_signer)
        .unwrap();

    let (mut server_state, server_traffic_secrets, connection_confirmation, _) =
        ServerHandshake::start_from_seed(&mut server_connection, seed, &resumption).unwrap();

    let (secret_upate, messages_bytes) = client_state
        .receive_signaling_message(
            &mut client_connection,
            &client_leaf_signer,
            &connection_confirmation,
        )
        .unwrap();

    // Client shouldn't return anything
    assert!(messages_bytes.is_none());
    assert!(secret_upate.is_none());

    assert_eq!(client_traffic_secrets, server_traffic_secrets);

    // Test how both parties handle crossing updates

    // Client creates an update
    let (client_secret, connection_update) = client_state
        .update(&mut client_connection, &client_leaf_signer, false)
        .unwrap();

    // Server also creates an update
    let server_message_bytes = server_state
        .update(&mut server_connection, &server_leaf_signer, false)
        .unwrap();

    // Client processes server update
    let (secret_update, server_message_bytes) = client_state
        .receive_signaling_message(
            &mut client_connection,
            &client_leaf_signer,
            &server_message_bytes,
        )
        .unwrap();

    // Client shouldn't have returned any messages
    assert!(server_message_bytes.is_none());
    assert!(secret_update.is_none());

    // Server processes client update
    let (server_traffic_secrets, server_message_bytes) = server_state
        .receive_signaling_message(
            &mut server_connection,
            &server_leaf_signer,
            &connection_update,
        )
        .unwrap();

    // Client processes the server's response
    let (secret_update, client_message_bytes) = client_state
        .receive_signaling_message(
            &mut client_connection,
            &client_leaf_signer,
            &server_message_bytes.unwrap(),
        )
        .unwrap();

    // Client shouldn't have returned any messages
    assert!(client_message_bytes.is_none());
    // Client should have returned the server traffic secret
    let Some(SecretUpdate::ServerSecret(server_secret)) = secret_update else {
        panic!("Expected server traffic secret");
    };

    let client_traffic_secrets = TrafficSecrets {
        client_secret: client_secret.clone(),
        server_secret: server_secret.clone(),
    };

    // Client and server should have the same traffic secrets
    assert_eq!(client_traffic_secrets, server_traffic_secrets);

    // Now the client does an update, but the server doesn't receive it.
    let (client_secret, _connection_update) = client_state
        .update(&mut client_connection, &client_leaf_signer, false)
        .unwrap();

    // The server doesn't receive the client's update, but now the client wants to resume.
    let (client_traffic_secrets, resumption) = client_state
        .resume(&mut client_connection, &client_leaf_signer)
        .unwrap();

    // The client should use the same update
    assert_eq!(client_secret, client_traffic_secrets.client_secret);

    // The server receives the resumption
    let (mut _server_state, server_traffic_secrets, connection_confirmation, _) =
        ServerHandshake::start_from_seed(&mut server_connection, seed, &resumption).unwrap();

    // Secrets should match
    assert_eq!(client_traffic_secrets, server_traffic_secrets);

    // The client should process the connection confirmation
    let (secret_update, messages_bytes) = client_state
        .receive_signaling_message(
            &mut client_connection,
            &client_leaf_signer,
            &connection_confirmation,
        )
        .unwrap();

    // The client shouldn't return any messages
    assert!(messages_bytes.is_none());
    assert!(secret_update.is_none());
}
