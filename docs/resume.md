# Session persistence & resume (design)

Status: **design** for Phase 3b. Goal: *close the laptop / lose the network / kill the client →
reconnect → land back in the exact same live shell*, with the output you missed replayed. This is
mosh's signature feature, adapted to Moonshine's QUIC + native-passthrough model.

## Scope (v1 of resume)

**One persistent session per `mshd` process.** A single user reattaching to their own shell —
not multi-tenant. This keeps the transport changes small (no connection-ID demux to many live
connections). Concurrent multi-session is a future extension.

Resume is distinct from **roaming** (already built): roaming = QUIC connection *migration* keeps
the *same* connection alive across an IP change. Resume = the connection was fully *lost* (idle
timeout, client killed, laptop slept past the QUIC idle window) and the client establishes a
**brand-new** QUIC connection that reattaches to the surviving server-side shell.

## Server side: the session outlives the connection

Today `mshd` ties the PTY's lifetime to one `quic.Conn`; when the connection ends the process
exits and the PTY dies. Change it so the **PTY + session state outlive any single connection**:

- On first client, create the PTY and a `Session { id:[16]u8, pty, out_seq:u64, replay:RingBuffer,
  caps }`. `id` is the `session_id` already minted in `Welcome`.
- `out_seq` = total count of PTY-output bytes ever produced for this session.
- `replay` = a bounded ring buffer (e.g. 256 KiB–1 MiB) of the most recent PTY output, tracking a
  `base` = the `out_seq` value at the ring's oldest byte. Every byte read from the PTY is appended
  to `replay` (evicting the oldest) **and** sent on the data stream; `out_seq += n`.
- When the connection drops (`peerClosed`, idle, or read error) the daemon does **not** kill the
  PTY. It marks the session **detached** and keeps reading the PTY into `replay` (so a
  long-running command's output isn't lost while you're disconnected — bounded by the ring size).
  It then loops back to **accept a new QUIC connection** on the same UDP socket.
- The PTY is torn down (and the process exits) only when the shell itself exits, or after a
  detached-idle TTL (e.g. a few minutes with no client — configurable, default generous).

### Transport change: a listener that outlives connections

`quic.Server.init` currently creates the socket *and* one connection together. Refactor so the
**UDP socket persists** across connections:

- `quic.Listener` owns the persistent socket + TLS config. `Listener.accept() !*Conn` reads
  datagrams until a new client's Initial arrives, builds a fresh server `Conn` bound to the
  listener's socket, and drives its handshake. When that `Conn` dies, the daemon calls `accept()`
  again on the same `Listener` for the next connection.
- Keep the existing `Server.init` working (or express it in terms of `Listener` + one `accept`) so
  current tests and the non-resume path are unaffected.

## Client side

- Client persists its `session_id` (from `Welcome`) and a `recv_seq:u64` = total bytes received on
  the **data stream** (counted *before* predictor filtering, so client and server agree on the
  byte count).
- On an unexpected disconnect (`peerClosed` with the shell still alive, or a connect failure mid-
  session), the client automatically **reconnects**: open a new QUIC connection to the same host,
  send `Hello` with `resume_session = { session_id, last_consumed = recv_seq }`.
- On success it keeps the same terminal (raw mode stays on), replays arrive as normal data-stream
  bytes, and typing continues. Use a bounded retry/backoff; give up with a clear message after N
  attempts.

## The reattach handshake

```
client → server:  Hello { …, resume_session = { session_id, last_consumed } }
server:
   if session_id matches the live session:
       Welcome { …, session_id (same) }              // accepted
       replay data stream from `last_consumed`:
          if last_consumed >= base:  send replay[last_consumed - base ..]
          else:                      send whole ring (client lost some scrollback) + note
       resume live relay
   else (unknown/expired id):
       Reject { reason = stale_resume }              // client starts a fresh session
```

`last_consumed > out_seq` (client claims more than exists) → treat as protocol error / fresh
session. `last_consumed == out_seq` → nothing to replay, just resume.

## Sequencing details

- The data stream still carries **raw PTY bytes** (no per-byte envelope) — native passthrough is
  preserved. Sequence numbers are pure **byte counts**, maintained independently on each side:
  server `out_seq` (bytes produced), client `recv_seq` (bytes received). They align because QUIC
  delivers the data stream reliably and in order *within* a connection; across a reconnect we
  reconcile via `last_consumed`.
- Keystrokes (client→server) are best-effort on resume: anything typed while disconnected is lost
  (the shell never saw it). That's the same contract as mosh. No input replay.

## Testing (acceptance)

In-process, no real network (extend the transport tests):
1. Start a `Listener` + client; establish a session running a shell; send `printf one`; confirm
   the client received `one` and note `recv_seq`.
2. Simulate disconnect: drop the client `Conn` (deinit) WITHOUT killing the server session; have
   the server keep reading the PTY. Push more output while detached (`printf two`) — it lands in
   the replay buffer.
3. New client `Conn`; `Hello` with `resume_session = { same id, last_consumed = recv_seq }`.
4. Assert: server accepts (same `session_id` in `Welcome`), replays the missed `two`, and a
   subsequent `printf three` flows to the new client. The shell is the *same* process (test by
   setting a shell variable before disconnect and echoing it after — it must survive).
5. Stale/unknown `session_id` → `Reject{stale_resume}` and the client can start fresh.
6. All existing tests still pass; no leaks; clean shutdown still works.

## Non-goals (later)

Multi-session daemon, input replay, cross-device handoff, encrypted at-rest replay buffer.
