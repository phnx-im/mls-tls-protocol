<!--
SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

## Architecture

The TCP API is sans-IO. The application owns sockets, buffers, clocks,
authorization policy, job scheduling, and the durable store. An
`Engine` owns sessions in both roles. A session holds the MLS epoch
state and can survive an interrupted TCP connection. Each
`StreamConnection` handles one connection's ordered record stream.

```text
                          Application

  Authorization       Store           Job pool         TCP socket
  request/answer     write/ack       job/result        read/write
        ^                ^                ^                ^
        |                |                |                |
        v                v                v                v
  +-----------------------------------------+       +------------------+
  | Engine                                  |       | StreamConnection |
  | sessions, epochs, deadlines, admission  |       | records and keys |
  +-----------------------------------------+       +------------------+
       |                                                ^   |
       +----------- ToConnection(handle, message) ------+   |
       <----------- ToEngine (carries handle) --------------+
                    routed by the application
```

One mutable owner drives the engine. For an outbound session, the
application supplies the server's provisioned suite and pre-handshake
configuration to `Engine::connect` and uses `Engine::open_stream` for the
first connection or a retry. Inbound sockets enter through the shared
`Admission` handle. A responder connection waits for a complete first
message before bringing it to the engine. The application bounds how many
sockets can wait for that first message.

After each engine input, the application drains `Engine::poll_output`
and schedules the next deadline. It sends `Job`s for expensive handshake
and Commit operations to a worker and returns results via
`Engine::job_done`. It answers authorization requests with
`Engine::authorize` and acknowledges durable transactions with
`Engine::store_done`. Monotonic `Instant` values come from a clock that
keeps counting during suspend. Supply wall time to `Engine::handle_timeout`
for restart accounting and to `Job::run` for MLS credential lifetime checks.

The application routes messages in order for each `ConnectionHandle`.
It delivers every `ToEngine` for that connection before reporting
`Engine::connection_closed`. The handle identifies a particular
connection, so the engine can discard messages from a retired connection
even when its session has already resumed elsewhere.

### TCP record ordering

One mutable owner reads, seals, and applies engine messages for a
connection. The record's position in the stream determines its nonce.
Write sealed records and bytes produced by the connection in the order
they were produced. An EpochKeyUpdate precedes records sealed with the
new keys. Shed load before sealing. Dropping or reordering sealed
records prevents subsequent records from opening.

Data records carry opaque application payloads. The selected application
protocol defines their framing. `PacketBuf` gives the sealer room for
record overhead around a payload. On receive, `Deliver` returns ranges
into the caller's buffer. When `read` pauses for an engine decision,
keep the unread bytes. After `apply` returns `Applied::Resume`, pass the
retained bytes to `read` again. Poll `StreamConnection::poll_to_engine` on
the transmit path as well, so a connection that only sends can report
that its send key is approaching its usage limit.

When adopting a newer connection, the engine clears the old
connection's keys via a shared key slot before sending Adopted. That
retires the old connection even if its owner is blocked on a socket
write. Its next call reports `InterruptCause::Replaced`.

### Authorization

The application binds the verified signature key and MLS credential to
an identity it trusts. The claimed identity alone is insufficient. A
signed KeyPackage can be replayed, so confirmation of epoch 1 precedes
durable responder state and replacement of an older session.

The engine asks when a session is established, when a Commit changes the
peer's signature key or credential, and at the application-supplied
reauthorization time. Reconnection carries forward the authorization of
the session. After restore, the application checks `Engine::sessions`
against its registry. It revokes access with `Engine::close_session`.
