# Moonshine wire protocol (`MSH/0.1`)

Status: **draft, versioned from day 1.** This document is the source of truth; code in
`src/proto/` must match it. Breaking changes bump the version and are negotiated (see §2).

Moonshine runs over a single **QUIC connection** (ngtcp2 + OpenSSL 3 TLS 1.3). QUIC already
provides encryption, reliability, congestion control, multiplexed streams, and connection
migration, so this protocol only defines the application framing carried inside QUIC streams.

## 1. Streams

QUIC stream IDs are assigned by role. Moonshine uses a small fixed set of long-lived streams
plus room to grow:

| Stream            | Type            | Direction        | Purpose                                              |
|-------------------|-----------------|------------------|------------------------------------------------------|
| **Control** (0)   | client-bidi     | both             | Handshake, capability negotiation, resize, lifecycle |
| **Term-in**       | client-uni      | client → server  | User keystrokes → server PTY                          |
| **Term-out**      | server-uni      | server → client  | Authoritative PTY output → local terminal            |
| (reserved)        | —               | —                | Port-forward / file-transfer channels (post-MVP)     |

The Control stream is the first client-initiated bidirectional stream. Term-in / Term-out
stream IDs are announced in the handshake (`StreamMap` frame) so we are not tied to a fixed
numbering as features are added.

Term-out carries the **raw PTY byte-stream** unchanged — this is what preserves native
scrollback/search on the client. The client never receives a screen diff; it receives the same
bytes ssh would deliver, plus the framing envelope below for sequencing/acks.

## 2. Handshake & version negotiation

All Control-stream messages are `Frame`s (§3). The handshake is:

```
client → server:  Hello   { version, capabilities, auth_method, session_resume? }
server → client:  Welcome { version, capabilities, stream_map, session_id }
                  — or —
server → client:  Reject  { reason_code, min_version, max_version }
```

- **version**: `u16 major << 8 | u16 minor` packed as `u16` — `MSH/0.1` = `0x0001`.
- Negotiation rule: both sides advertise their supported `[min,max]` range; the session uses the
  **highest common major.minor**. No common version → `Reject` with the server's supported range.
- **capabilities**: a `u64` bitmap (§4). The effective capability set is the **bitwise AND** of
  client and server bitmaps — a feature is active only if both support it. Unknown bits are
  ignored (forward-compatible).

## 3. Frame envelope

Every Control-stream message is length-prefixed and typed:

```
Frame := type:u8  length:u32(LE)  payload:[length]u8
```

- `type` — `FrameType` enum (§5). Unknown types on the Control stream are skipped using
  `length` (forward-compatible), except during the handshake where an unknown critical frame is
  a protocol error.
- `length` — payload byte count, little-endian, max `1<<20` (1 MiB) per control frame.
- Integers in payloads are little-endian. Strings are `len:u16` + UTF-8 bytes. All varints are
  explicitly sized (no LEB128) to keep the Zig codec simple and total.

Term-in / Term-out use a lighter envelope (`DataFrame`) since they are high-rate:

```
DataFrame := seq:u64(LE)  len:u32(LE)  bytes:[len]u8
```

`seq` is a per-stream monotonically increasing byte-offset-style counter used by the predictor
and the resume/replay buffer to know what the peer has consumed (see `Ack`).

## 4. Capability bitmap (`u64`)

| Bit | Name                 | Meaning                                                        |
|-----|----------------------|----------------------------------------------------------------|
| 0   | `PREDICT`            | Client-side predictive local echo is in use                    |
| 1   | `RESUME`             | Session persistence + replay-buffer resume supported           |
| 2   | `MIGRATE`            | Peer expects/permits QUIC connection migration                 |
| 3   | `COMPRESS`           | Term-out stream may be compressed (algo TBD, post-MVP)         |
| 4   | `PORTFWD`            | Port-forwarding channels supported (post-MVP)                  |
| 5..63 | reserved           | Must be 0 when sent, ignored when received                     |

## 5. Frame types

| Value | Frame        | Payload                                                          |
|-------|--------------|-----------------------------------------------------------------|
| 0x01  | `Hello`      | version:u16, capabilities:u64, auth_method:u8, resume:OptSession, auth_token:OptToken |
| 0x02  | `Welcome`    | version:u16, capabilities:u64, stream_map:StreamMap, session_id  |
| 0x03  | `Reject`     | reason_code:u16, min_version:u16, max_version:u16                |
| 0x10  | `Resize`     | cols:u16, rows:u16, xpix:u16, ypix:u16                           |
| 0x11  | `Ack`        | stream:u8, consumed_seq:u64                                      |
| 0x12  | `Ping`       | nonce:u64                                                        |
| 0x13  | `Pong`       | nonce:u64                                                        |
| 0x20  | `Shutdown`   | reason_code:u16, exit_status:i32                                 |

`StreamMap` := term_in:u64, term_out:u64 (QUIC stream IDs).
`OptSession` := present:u8; if 1 → session_id:[16]u8, last_consumed:u64.
`OptToken` := present:u8; if 1 → len:u16, bytes:[len]u8 (bootstrap auth token, 32 bytes).
`session_id` in `Welcome` := [16]u8 (opaque server-issued resume token).

### Bootstrap-over-ssh (auth_method 0x00)

`mshd --bootstrap` (launched over ssh) generates an ephemeral self-signed cert, binds an
ephemeral UDP port, and prints ONE line to stdout that the ssh channel conveys back to the
client:

```
MSH-BOOTSTRAP v=1 port=<u16> fp=<base64 SHA-256 of cert DER> token=<base64 32B>
```

The client connects QUIC to `host:port`, verifies the presented TLS cert's SHA-256 fingerprint
equals `fp` (trust pinned via the ssh-authenticated channel — abort on mismatch), and presents
`token` in `Hello.auth_token`. The server rejects (closes) unless the token matches its minted
value under a constant-time comparison. The token is one-time and the bootstrap server serves a
single session then exits.

## 6. Auth methods (`auth_method:u8`)

Matches the auth ladder. Only the *selector* is on the wire; the actual credential exchange
rides TLS 1.3 (raw public keys / cert) or an out-of-band bootstrap token.

| Value | Method               | Notes                                                       |
|-------|----------------------|-------------------------------------------------------------|
| 0x00  | `bootstrap_token`    | One-time token minted by `mshd --bootstrap` over ssh        |
| 0x01  | `ssh_pubkey`         | RFC 7250 raw ed25519 key vs `~/.ssh/authorized_keys`        |
| 0x02  | `daemon_cert`        | Standalone daemon X.509 identity                            |
| 0x03  | `underlay_trust`     | Trusted underlay (Tailscale/WireGuard); still TLS-encrypted |

## 7. Resume / roaming

1. **Migration** (same connection, new path): handled by QUIC. No app frames needed beyond an
   optional `Ping`/`Pong` to re-validate liveness. Requires `MIGRATE` capability.
2. **Resume** (connection fully lost): client reconnects and sends `Hello` with `resume`
   populated (`session_id` + `last_consumed` seq). Server validates the token, re-attaches the
   live PTY, and replays Term-out from `last_consumed`. Requires `RESUME` capability. The server
   holds a bounded replay buffer; if the client's `last_consumed` is older than the buffer tail,
   the server responds `Reject{reason=stale_resume}` and the client starts fresh.

## 8. Versioning discipline

- Adding a frame type or capability bit is **minor**-compatible (old peers skip unknown frames /
  AND-away unknown caps).
- Changing an existing frame's payload layout is **major**-breaking → bump major, negotiate.
- `src/proto/version.zig` owns the constant `current = 0x0001` and the supported range.
