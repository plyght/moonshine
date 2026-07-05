const std = @import("std");
const quic = @import("transport/quic.zig");
const Pty = @import("pty/pty.zig").Pty;
const frames = @import("proto/frames.zig");
const ver = @import("proto/version.zig");
const bootstrap = @import("auth/bootstrap.zig");

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
    rejected: bool = false,

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
                self.sendReject(2);
                return;
            };
            if (!bootstrap.constantTimeEql(&want, got)) {
                self.sendReject(2);
                return;
            }
        }
        const client_ver = ver.Version.fromInt(h.version);
        if (!ver.supported.contains(client_ver)) {
            self.sendReject(1);
            return;
        }
        const negotiated = ver.negotiate(ver.supported, .{ .min = client_ver, .max = client_ver }) orelse {
            self.sendReject(1);
            return;
        };
        const eff = ver.Capabilities.effective(
            ver.Capabilities.init(server_caps),
            ver.Capabilities.init(h.capabilities),
        );
        quic.randomBytes(&self.session_id);
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
