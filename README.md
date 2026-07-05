# Moonshine

`msh` — a modern, joyful alternative to SSH.

SSH is a TCP byte-stream: head-of-line blocked, no roaming (a changed IP kills your session),
a slow multi-round-trip handshake, and it feels laggy because every keystroke waits a full RTT
to echo. `mosh` fixed the *feel* but broke native scrollback and over-predicts in full-screen
apps. Eternal Terminal fixed scrollback but dropped instant echo and true roaming.

Moonshine aims for all of it at once:

- **Instant keystrokes** — predictive local echo, drawn as a transient overlay.
- **Native scrollback & search** — the real remote byte-stream is passed straight to your
  terminal; the server never owns your screen.
- **Real roaming** — built on QUIC (ngtcp2 + OpenSSL 3 TLS 1.3), so changing networks doesn't
  drop your session, and a fully-lost connection resumes to the same live shell.
- **Universal, easy auth** — bootstrap over your existing `ssh`, reuse your `~/.ssh` keys, run a
  standalone daemon, or ride a Tailscale/WireGuard underlay.
- **One static binary** — Zig cross-compiles `msh` and `mshd` for macOS and Linux.

Status: **working core.** Interactive shell over QUIC with native scrollback, predictive local
echo, real host addressing, bootstrap-over-ssh authentication, and QUIC connection migration.
See [`docs/protocol.md`](docs/protocol.md) for the wire protocol and [`docs/prediction.md`](docs/prediction.md)
for the predictive-echo design.

## Usage

**Bootstrap over your existing ssh (recommended — mutual trust, no setup):**
```sh
msh --ssh [user@]host                 # runs `mshd --bootstrap` over ssh, pins its cert, connects
msh --ssh host --server-cmd "~/.local/bin/mshd --bootstrap"   # if mshd isn't on PATH remotely
```

**Direct connect over a trusted underlay (Tailscale / WireGuard / LAN):**
```sh
# on the remote device, bound to its tailnet IP:
mshd --listen 100.x.y.z:4433
# on your laptop:
msh --connect 100.x.y.z:4433
```

`mshd --listen` is "underlay-trust": it relies on the network (e.g. your tailnet) as the trust
boundary, so bind it to a private interface. `mshd --bootstrap` mints a one-time token + ephemeral
cert and requires them, giving real authentication by leaning on ssh.

## Build

Requires Zig 0.16+ and (for now) system `ngtcp2` + `openssl@3` with the QUIC TLS API.

```sh
zig build            # builds msh and mshd into zig-out/bin
zig build test       # runs the unit + integration suite
zig fmt --check src  # formatting gate
```

## Layout

- `src/proto/` — versioned wire-protocol codec
- `src/transport/` — QUIC transport (ngtcp2)
- `src/pty/` — pseudo-terminal handling
- `src/term/` — VT tracking + predictive echo
- `src/auth/` — the auth ladder
- `docs/protocol.md` — wire spec (source of truth)
