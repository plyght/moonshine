const std = @import("std");
const quic = @import("transport/quic.zig");
const Pty = @import("pty/pty.zig").Pty;
const frames = @import("proto/frames.zig");
const ver = @import("proto/version.zig");
const bootstrap = @import("auth/bootstrap.zig");
const sshkeys = @import("auth/sshkeys.zig");

// Capabilities the daemon advertises: connection migration (roaming) and
// session resume.
pub const server_caps: u64 = ver.Capabilities.MIGRATE | ver.Capabilities.RESUME;

// Stream convention (see main_msh.zig / main_mshd.zig):
//   The client opens two client-initiated bidi streams in order. The first
//   (lowest id, 0) is CONTROL, carrying `frames`-encoded messages (currently
//   Resize). The second (id 4) is DATA, carrying raw terminal bytes full-duplex.
//   The server derives DATA = CONTROL + 4 from the control stream id.
//
//   ngtcp2 will not let the server write on a client-initiated stream before it
//   has received data on it, but the server needs to push PTY output (the shell
//   prompt) before the user types. So the client primes the DATA stream with a
//   single leading marker byte (data_open_marker), which the server strips and
//   which unblocks server->client writes on that stream.

pub const data_open_marker: u8 = 0x00;

// Reject reason codes (mirrors ServerSession.sendReject callers):
//   1 = unsupported version, 2 = auth failure, 3 = stale/unknown resume id.
pub const reject_version: u16 = 1;
pub const reject_auth: u16 = 2;
pub const reject_stale_resume: u16 = 3;

pub const default_replay_cap: usize = 512 * 1024;

/// The durable half of a session: the PTY plus enough recent output to replay
/// to a reconnecting client. It outlives any single `quic.Conn` — when the
/// connection drops the daemon keeps this alive (still draining the PTY into
/// `replay`) so a brand-new connection can reattach to the same live shell.
pub const Session = struct {
    allocator: std.mem.Allocator,
    id: [16]u8 = [_]u8{0} ** 16,
    pty: *Pty,
    // out_seq = total PTY-output bytes ever produced. `replay` holds the most
    // recent `cap` of them; the oldest byte in the ring is at out_seq -
    // replay.items.len (call it `base`).
    out_seq: u64 = 0,
    cap: usize = default_replay_cap,
    replay: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator, pty: *Pty, cap: usize) Session {
        var s = Session{ .allocator = allocator, .pty = pty, .cap = cap };
        quic.randomBytes(&s.id);
        return s;
    }

    pub fn deinit(self: *Session) void {
        self.replay.deinit(self.allocator);
    }

    pub fn base(self: *const Session) u64 {
        return self.out_seq - @as(u64, self.replay.items.len);
    }

    /// Record PTY output: append to the bounded ring (evicting oldest) and bump
    /// out_seq. Does not touch any connection.
    pub fn record(self: *Session, bytes: []const u8) void {
        self.replay.appendSlice(self.allocator, bytes) catch return;
        self.out_seq += bytes.len;
        if (self.replay.items.len > self.cap) {
            const drop = self.replay.items.len - self.cap;
            std.mem.copyForwards(u8, self.replay.items[0..self.cap], self.replay.items[drop..]);
            self.replay.shrinkRetainingCapacity(self.cap);
        }
    }

    /// The bytes a client at `last_consumed` still needs. If it is behind the
    /// ring's base the whole ring is returned (some scrollback was lost).
    pub fn replaySlice(self: *const Session, last_consumed: u64) []const u8 {
        if (last_consumed >= self.out_seq) return &.{};
        const b = self.base();
        if (last_consumed >= b) return self.replay.items[@intCast(last_consumed - b)..];
        return self.replay.items;
    }
};

pub const ServerSession = struct {
    allocator: std.mem.Allocator,
    conn: *quic.Conn,
    pty: *Pty,
    control_sid: ?i64 = null,
    data_sid: ?i64 = null,
    data_writable: bool = false,
    ctrl_buf: std.ArrayList(u8) = .empty,
    pending_out: std.ArrayList(u8) = .empty,
    welcomed: bool = false,
    negotiated_caps: u64 = 0,
    negotiated_version: u16 = 0,
    session_id: [16]u8 = [_]u8{0} ** 16,
    required_token: ?bootstrap.Token = null,
    // ssh-pubkey (require-key) mode: the authorized ed25519 keys and this
    // server's own cert fingerprint (the channel-binding value the client must
    // sign). Both null unless require-key mode is enabled.
    authorized_keys: ?[]const sshkeys.PublicKey = null,
    own_cert_fp: ?bootstrap.Fingerprint = null,
    rejected: bool = false,
    // Optional durable session this connection is attached to. When set, the
    // session_id in Welcome is the durable id and resuming Hellos are honored.
    session: ?*Session = null,

    pub fn init(self: *ServerSession, allocator: std.mem.Allocator, conn: *quic.Conn, pty: *Pty) void {
        self.* = .{ .allocator = allocator, .conn = conn, .pty = pty };
        conn.setRecvHandler(self, onRecv);
    }

    pub fn deinit(self: *ServerSession) void {
        self.ctrl_buf.deinit(self.allocator);
        self.pending_out.deinit(self.allocator);
    }

    fn assign(self: *ServerSession, stream_id: i64) void {
        if (self.control_sid != null) return;
        self.control_sid = stream_id;
        self.data_sid = stream_id + 4;
    }

    /// Relay a chunk of PTY output to the client over the DATA stream. Buffers
    /// until the client has primed the data stream (see data_open_marker).
    pub fn relayPtyOutput(self: *ServerSession, bytes: []const u8) void {
        if (self.data_writable) {
            self.conn.write(self.data_sid.?, bytes) catch {};
        } else {
            self.pending_out.appendSlice(self.allocator, bytes) catch {};
        }
    }

    fn onRecv(ctx: ?*anyopaque, stream_id: i64, bytes: []const u8) void {
        const self: *ServerSession = @ptrCast(@alignCast(ctx));
        self.assign(stream_id);
        if (self.control_sid) |csid| {
            if (stream_id == csid) {
                self.handleControl(bytes);
                return;
            }
        }
        if (self.data_sid) |dsid| {
            if (stream_id == dsid) self.handleData(bytes);
        }
    }

    fn handleData(self: *ServerSession, bytes: []const u8) void {
        var rest = bytes;
        if (!self.data_writable) {
            self.data_writable = true;
            if (rest.len > 0) rest = rest[1..];
            if (self.pending_out.items.len > 0) {
                self.conn.write(self.data_sid.?, self.pending_out.items) catch {};
                self.pending_out.clearRetainingCapacity();
            }
        }
        if (rest.len > 0) _ = self.pty.write(rest) catch {};
    }

    fn handleControl(self: *ServerSession, bytes: []const u8) void {
        self.ctrl_buf.appendSlice(self.allocator, bytes) catch return;
        while (true) {
            const items = self.ctrl_buf.items;
            if (items.len < 5) break;
            const payload_len = std.mem.readInt(u32, items[1..5], .little);
            const total = 5 + @as(usize, payload_len);
            if (items.len < total) break;
            const frame = frames.decode(items[0..total]) catch {
                self.ctrl_buf.clearRetainingCapacity();
                return;
            };
            self.applyFrame(frame);
            std.mem.copyForwards(u8, self.ctrl_buf.items[0 .. items.len - total], self.ctrl_buf.items[total..items.len]);
            self.ctrl_buf.shrinkRetainingCapacity(items.len - total);
        }
    }

    fn applyFrame(self: *ServerSession, frame: frames.Frame) void {
        switch (frame) {
            .hello => |h| self.handleHello(h),
            .resize => |r| self.pty.resize(r.cols, r.rows) catch {},
            else => {},
        }
    }

    fn handleHello(self: *ServerSession, h: frames.Hello) void {
        if (self.welcomed) return;
        if (self.required_token) |want| {
            const got = h.auth_token orelse {
                self.sendReject(reject_auth);
                return;
            };
            if (!bootstrap.constantTimeEql(&want, got)) {
                self.sendReject(reject_auth);
                return;
            }
        }
        if (self.authorized_keys) |keys| {
            const fp = self.own_cert_fp orelse {
                self.sendReject(reject_auth);
                return;
            };
            const proof = h.auth_proof orelse {
                self.sendReject(reject_auth);
                return;
            };
            var authorized = false;
            for (keys) |k| {
                if (bootstrap.constantTimeEql(&k, &proof.pubkey)) authorized = true;
            }
            if (!authorized or !sshkeys.verifyChallenge(proof.pubkey, fp, proof.sig)) {
                self.sendReject(reject_auth);
                return;
            }
        }
        const client_ver = ver.Version.fromInt(h.version);
        if (!ver.supported.contains(client_ver)) {
            self.sendReject(reject_version);
            return;
        }
        const negotiated = ver.negotiate(ver.supported, .{ .min = client_ver, .max = client_ver }) orelse {
            self.sendReject(reject_version);
            return;
        };
        const eff = ver.Capabilities.effective(
            ver.Capabilities.init(server_caps),
            ver.Capabilities.init(h.capabilities),
        );

        // Resume path: a Hello carrying resume_session must match the live
        // durable session's id (and not claim more bytes than exist), else it's
        // stale and the client should start fresh.
        var replay_slice: []const u8 = &.{};
        if (h.resume_session) |rs| {
            const sess = self.session orelse {
                self.sendReject(reject_stale_resume);
                return;
            };
            if (!std.mem.eql(u8, &rs.session_id, &sess.id) or rs.last_consumed > sess.out_seq) {
                self.sendReject(reject_stale_resume);
                return;
            }
            replay_slice = sess.replaySlice(rs.last_consumed);
            self.session_id = sess.id;
        } else if (self.session) |sess| {
            self.session_id = sess.id;
        } else {
            quic.randomBytes(&self.session_id);
        }

        self.negotiated_version = negotiated.toInt();
        self.negotiated_caps = eff.bits;
        self.welcomed = true;

        const dsid: u64 = @intCast(self.data_sid orelse 4);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);
        frames.encode(&buf, self.allocator, .{ .welcome = .{
            .version = negotiated.toInt(),
            .capabilities = eff.bits,
            .stream_map = .{ .term_in = dsid, .term_out = dsid },
            .session_id = self.session_id,
        } }) catch return;
        if (self.control_sid) |csid| self.conn.write(csid, buf.items) catch {};

        // Queue any missed output ahead of live PTY bytes; relayPtyOutput
        // buffers it until the client primes the data stream (data_open_marker).
        if (replay_slice.len > 0) self.relayPtyOutput(replay_slice);
    }

    /// Tell the client the shell has exited (a clean end, distinct from a
    /// network drop) so it won't try to resume a session that no longer exists.
    pub fn sendShutdown(self: *ServerSession, exit_status: i32) void {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);
        frames.encode(&buf, self.allocator, .{ .shutdown = .{
            .reason_code = 0,
            .exit_status = exit_status,
        } }) catch return;
        if (self.control_sid) |csid| self.conn.write(csid, buf.items) catch {};
    }

    fn sendReject(self: *ServerSession, reason_code: u16) void {
        self.rejected = true;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);
        frames.encode(&buf, self.allocator, .{ .reject = .{
            .reason_code = reason_code,
            .min_version = ver.supported.min.toInt(),
            .max_version = ver.supported.max.toInt(),
        } }) catch return;
        if (self.control_sid) |csid| self.conn.write(csid, buf.items) catch {};
    }
};
