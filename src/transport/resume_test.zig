const std = @import("std");
const quic = @import("quic.zig");
const Pty = @import("../pty/pty.zig").Pty;
const session = @import("../session.zig");
const ServerSession = session.ServerSession;
const Session = session.Session;
const frames = @import("../proto/frames.zig");
const ver = @import("../proto/version.zig");

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("fcntl.h");
});

const cert = "src/transport/testdata/cert.pem";
const key = "src/transport/testdata/key.pem";

// The client end of a connection: mirrors msh's stream handling closely enough
// to observe welcome/reject on control and to accumulate data-stream bytes (the
// count is the resume `last_consumed`).
const ClientEnd = struct {
    control_sid: i64,
    data_sid: i64,
    allocator: std.mem.Allocator,
    data: std.ArrayList(u8) = .empty,
    ctrl: std.ArrayList(u8) = .empty,
    welcomed: bool = false,
    rejected: bool = false,
    session_id: [16]u8 = [_]u8{0} ** 16,

    fn deinit(self: *ClientEnd) void {
        self.data.deinit(self.allocator);
        self.ctrl.deinit(self.allocator);
    }

    fn onRecv(ctx: ?*anyopaque, stream_id: i64, bytes: []const u8) void {
        const self: *ClientEnd = @ptrCast(@alignCast(ctx));
        if (stream_id == self.data_sid) {
            self.data.appendSlice(self.allocator, bytes) catch {};
            return;
        }
        if (stream_id != self.control_sid) return;
        self.ctrl.appendSlice(self.allocator, bytes) catch return;
        while (true) {
            const items = self.ctrl.items;
            if (items.len < 5) break;
            const plen = std.mem.readInt(u32, items[1..5], .little);
            const total = 5 + @as(usize, plen);
            if (items.len < total) break;
            const frame = frames.decode(items[0..total]) catch {
                self.ctrl.clearRetainingCapacity();
                return;
            };
            switch (frame) {
                .welcome => |w| {
                    self.welcomed = true;
                    self.session_id = w.session_id;
                },
                .reject => self.rejected = true,
                else => {},
            }
            std.mem.copyForwards(u8, self.ctrl.items[0 .. items.len - total], self.ctrl.items[total..items.len]);
            self.ctrl.shrinkRetainingCapacity(items.len - total);
        }
    }

    fn sendHello(self: *ClientEnd, conn: *quic.Conn, gpa: std.mem.Allocator, resume_session: ?frames.OptSession) !void {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        try frames.encode(&buf, gpa, .{ .hello = .{
            .version = ver.current.toInt(),
            .capabilities = ver.Capabilities.RESUME,
            .auth_method = .underlay_trust,
            .resume_session = resume_session,
        } });
        try conn.write(self.control_sid, buf.items);
    }
};

fn setNonblock(fd: c_int) void {
    const flags = c.fcntl(fd, c.F_GETFL, @as(c_int, 0));
    _ = c.fcntl(fd, c.F_SETFL, flags | c.O_NONBLOCK);
}

// One relay tick on the durable server side: drain the PTY into the replay ring
// and, when attached, forward it live.
fn serverTick(conn: ?*quic.Conn, ssess: ?*ServerSession, pty: *Pty, sess: *Session) void {
    var pbuf: [4096]u8 = undefined;
    const n = pty.read(&pbuf) catch 0;
    if (n > 0) {
        sess.record(pbuf[0..n]);
        if (ssess) |s| s.relayPtyOutput(pbuf[0..n]);
    }
    if (conn) |cn| cn.step() catch {};
}

// Drive both ends until `found` returns true or the iteration budget runs out.
fn driveUntil(
    client: *quic.Conn,
    conn: ?*quic.Conn,
    ssess: ?*ServerSession,
    pty: *Pty,
    sess: *Session,
    found: *const fn () bool,
) bool {
    var i: usize = 0;
    while (i < 6000) : (i += 1) {
        client.step() catch {};
        serverTick(conn, ssess, pty, sess);
        if (found()) return true;
        _ = c.usleep(500);
    }
    return found();
}

// Handshake a fresh client through the listener; returns the server-side Conn.
fn handshake(listener: *quic.Listener, client: *quic.Conn) !*quic.Conn {
    var server_conn: ?*quic.Conn = null;
    var i: usize = 0;
    while (i < 6000) : (i += 1) {
        client.step() catch {};
        if (server_conn == null) {
            server_conn = try listener.pollAccept();
        } else {
            server_conn.?.step() catch {};
        }
        if (client.handshakeCompleted() and server_conn != null and server_conn.?.handshakeCompleted()) {
            return server_conn.?;
        }
        _ = c.usleep(500);
    }
    return error.HandshakeTimeout;
}

var g_client: ?*ClientEnd = null;
fn clientHasData(needle: []const u8) bool {
    const cl = g_client orelse return false;
    return std.mem.indexOf(u8, cl.data.items, needle) != null;
}

test "session replay ring returns the bytes missed since last_consumed" {
    const allocator = std.testing.allocator;
    var pty = try Pty.open(allocator);
    defer pty.close();

    // Small cap so we can exercise eviction and the base offset.
    var sess = Session.init(allocator, &pty, 16);
    defer sess.deinit();

    sess.record("abcdefghij"); // out_seq=10, base=0
    try std.testing.expectEqual(@as(u64, 10), sess.out_seq);
    try std.testing.expectEqual(@as(u64, 0), sess.base());
    try std.testing.expectEqualStrings("cdefghij", sess.replaySlice(2));
    try std.testing.expectEqualStrings("", sess.replaySlice(10));

    sess.record("klmnopqrst"); // out_seq=20, ring holds last 16 (bytes 4..20), base=4
    try std.testing.expectEqual(@as(u64, 20), sess.out_seq);
    try std.testing.expectEqual(@as(u64, 4), sess.base());
    // last_consumed within the ring: exact tail.
    try std.testing.expectEqualStrings("qrst", sess.replaySlice(16));
    // last_consumed older than base: whole ring (lost scrollback).
    try std.testing.expectEqual(@as(usize, 16), sess.replaySlice(0).len);
}

test "resume reattaches to the same live shell and replays missed output" {
    const allocator = std.testing.allocator;

    const listener = try quic.Listener.init(allocator, "127.0.0.1", 0, cert, key);
    defer listener.deinit();
    const port = listener.localPort();

    var pty = try Pty.open(allocator);
    defer pty.close();
    const argv = [_][]const u8{"/bin/sh"};
    const env = [_][]const u8{ "PATH=/usr/bin:/bin", "PS1=", "TERM=dumb" };
    try pty.spawnShell(&argv, &env, .{ .cols = 80, .rows = 24 });
    setNonblock(pty.master);

    var sess = Session.init(allocator, &pty, session.default_replay_cap);
    defer sess.deinit();

    // ---- client 1: fresh attach ----
    const client1 = try quic.Client.connect(allocator, "127.0.0.1", port, "localhost");
    var sc1 = try handshake(listener, client1);

    var end1 = ClientEnd{ .control_sid = try client1.openStream(), .data_sid = try client1.openStream(), .allocator = allocator };
    defer end1.deinit();
    client1.setRecvHandler(&end1, ClientEnd.onRecv);
    g_client = &end1;

    var ss1: ServerSession = undefined;
    ss1.init(allocator, sc1, &pty);
    ss1.session = &sess;

    try end1.sendHello(client1, allocator, null);
    try client1.write(end1.data_sid, &[_]u8{session.data_open_marker});

    try std.testing.expect(driveUntil(client1, sc1, &ss1, &pty, &sess, struct {
        fn f() bool {
            return (g_client.?.welcomed);
        }
    }.f));
    try std.testing.expectEqualSlices(u8, &sess.id, &end1.session_id);

    // Set a shell variable and emit a marker; wait until we see the marker.
    try client1.write(end1.data_sid, "PERSIST=hello_resume\n");
    try client1.write(end1.data_sid, "printf MARK1\n");
    try std.testing.expect(driveUntil(client1, sc1, &ss1, &pty, &sess, struct {
        fn f() bool {
            return clientHasData("MARK1");
        }
    }.f));

    // Everything consumed so far is our resume point.
    const last_consumed: u64 = end1.data.items.len;

    // Produce more output and confirm it was generated (it now lives in the ring
    // as well); this is what a reconnecting client must have replayed.
    try client1.write(end1.data_sid, "printf MISSEDBYTES\n");
    try std.testing.expect(driveUntil(client1, sc1, &ss1, &pty, &sess, struct {
        fn f() bool {
            return clientHasData("MISSEDBYTES");
        }
    }.f));

    // ---- disconnect: drop the connection, keep the durable session ----
    ss1.deinit();
    client1.deinit();
    sc1.deinit();
    g_client = null;

    // ---- client 2: resume with the same id from last_consumed ----
    const client2 = try quic.Client.connect(allocator, "127.0.0.1", port, "localhost");
    var sc2 = try handshake(listener, client2);

    var end2 = ClientEnd{ .control_sid = try client2.openStream(), .data_sid = try client2.openStream(), .allocator = allocator };
    defer end2.deinit();
    client2.setRecvHandler(&end2, ClientEnd.onRecv);
    g_client = &end2;

    var ss2: ServerSession = undefined;
    ss2.init(allocator, sc2, &pty);
    ss2.session = &sess;
    defer ss2.deinit();

    try end2.sendHello(client2, allocator, .{ .session_id = sess.id, .last_consumed = last_consumed });
    try client2.write(end2.data_sid, &[_]u8{session.data_open_marker});

    try std.testing.expect(driveUntil(client2, sc2, &ss2, &pty, &sess, struct {
        fn f() bool {
            return g_client.?.welcomed;
        }
    }.f));
    // Same session id echoed back — this is a resume, not a fresh session.
    try std.testing.expectEqualSlices(u8, &sess.id, &end2.session_id);

    // The bytes produced while we were away are replayed to the new connection.
    try std.testing.expect(driveUntil(client2, sc2, &ss2, &pty, &sess, struct {
        fn f() bool {
            return clientHasData("MISSEDBYTES");
        }
    }.f));

    // Proof the shell PROCESS survived: the variable set on connection 1 is
    // still there for connection 2 to echo. A fresh shell would print nothing.
    try client2.write(end2.data_sid, "echo $PERSIST\n");
    try std.testing.expect(driveUntil(client2, sc2, &ss2, &pty, &sess, struct {
        fn f() bool {
            return clientHasData("hello_resume");
        }
    }.f));

    client2.deinit();
    sc2.deinit();
    g_client = null;
}

test "resume with an unknown session id is rejected" {
    const allocator = std.testing.allocator;

    const listener = try quic.Listener.init(allocator, "127.0.0.1", 0, cert, key);
    defer listener.deinit();
    const port = listener.localPort();

    var pty = try Pty.open(allocator);
    defer pty.close();
    const argv = [_][]const u8{"/bin/sh"};
    const env = [_][]const u8{ "PATH=/usr/bin:/bin", "PS1=", "TERM=dumb" };
    try pty.spawnShell(&argv, &env, .{ .cols = 80, .rows = 24 });
    setNonblock(pty.master);

    var sess = Session.init(allocator, &pty, session.default_replay_cap);
    defer sess.deinit();

    const client = try quic.Client.connect(allocator, "127.0.0.1", port, "localhost");
    defer client.deinit();
    var sc = try handshake(listener, client);
    defer sc.deinit();

    var end = ClientEnd{ .control_sid = try client.openStream(), .data_sid = try client.openStream(), .allocator = allocator };
    defer end.deinit();
    client.setRecvHandler(&end, ClientEnd.onRecv);
    g_client = &end;

    var ss: ServerSession = undefined;
    ss.init(allocator, sc, &pty);
    ss.session = &sess;
    defer ss.deinit();

    // A session id that does not match the live session.
    const bogus = [_]u8{0xEE} ** 16;
    try end.sendHello(client, allocator, .{ .session_id = bogus, .last_consumed = 0 });

    try std.testing.expect(driveUntil(client, sc, &ss, &pty, &sess, struct {
        fn f() bool {
            return g_client.?.rejected;
        }
    }.f));
    try std.testing.expect(!end.welcomed);
    g_client = null;
}
