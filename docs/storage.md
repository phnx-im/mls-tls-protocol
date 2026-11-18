<!--
SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

## Durable storage

This guide covers sessions with early data disabled.

The application treats the library's versioned records as opaque bytes.
It holds the store under an exclusive lock for the lifetime of the
engine, encrypts records at rest with a platform-protected key, and
excludes the store from backups and sync. Concurrent engines on one
store could reuse Reconnect numbers and fork the MLS epoch state.

| Record | Contents |
| --- | --- |
| `EpochRecord` | Current and pending MLS state, the current init secret, and retained values derived for each epoch. |
| `CounterRecord` | Reconnect counters, deadlines, application data, and any session that this one replaces. |
| `ResetRecord` | Current and pending epoch references, reset and channel keys, and the suite for answering a Reconnect with Reset after deletion. The store keeps the expiry alongside it. |
| `EngineRecord` | Last-alive wall time, interruption starts, and deletions that still need to complete. |

Connection keys, pre-handshake keys, candidate connections, and staged
received Commits stay in memory. Apply every `StoreWrite` atomically and
flush it before reporting it durable. Apply transactions for the same
session in order of their IDs. Writes for different sessions can complete
independently. Delete retired records as far as the medium permits.
Overwritten data can survive in flash or database journals.

### Writes before dependent outputs

The engine emits `Output::Store` and holds outputs that depend on the
write until the application calls `Engine::store_done` with its
transaction ID. An existing connection can still use keys whose state
is already durable while an update waits.

An epoch transaction includes the consumed exporter state and its
derived values. On restore, the pending epoch uses those saved values.
The engine keeps the current init secret until the pending epoch is
settled.

| Durable change | Output that waits for it |
| --- | --- |
| Initiator's accepted epoch 1 and consumed KeyPackage state | Its epoch-1 confirmation and application data. |
| Responder's confirmed epoch 1 | The established event and application data. |
| New pending epoch and its exporter results | The outgoing Commit. |
| Applied peer Commit | The EpochKeyUpdate and use of the new send keys. |
| Confirmed pending epoch and the resulting retirement of old state | The dependent confirmation, data, and epoch-change event. |
| Initiator's next Reconnect number | The ClientStart carrying that Reconnect. |
| Responder's settlement of a pending epoch during adoption | Adopted and application data under the settled epoch. |
| Initiator's settlement after Adopted | Later outputs that use or report the settled epoch. |
| Responder's session deletion and reset state | A Reset for the deleted session. |

Periodic writes of the engine's last-alive time and interruption starts
support restart accounting. They gate no wire output. Restore starts
sessions in the interrupted state. If a session has no saved
interruption start, its interruption counts from the last-alive write.
Report a snapshot or other possibly older store via
`RestoreOrigin::MayBeEarlierCopy`. A session that advanced past that
copy can be lost.

### Replacing a session

`Decision::Accept::replaces` identifies an older session of the same
identity on the same binding. Once the new session's epoch 1 is
confirmed, its first transaction records the replacement. The old
session's deletion and any reset state follow in a separate
transaction, after its earlier writes. The replacement completes once
that deletion is durable. If a crash falls between the two writes,
restore uses the marker to finish the deletion.

### Write failures

If the application gives up on a transaction, it calls
`Engine::store_failed`. A failed session write ends that session and
retires its connections. The engine records the outstanding deletion in
the engine record so restore can finish it. A failed engine-record write
pauses admission of new first messages until a later engine write
succeeds. If the store cannot record a required deletion even in the
engine record, stop the engine and repair the store before restoring it.
