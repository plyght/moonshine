const std = @import("std");
const quic = @import("quic.zig");
const Pty = @import("../pty/pty.zig").Pty;
const session = @import("../session.zig");
const ServerSession = session.ServerSession;
const frames = @import("../proto/frames.zig");
const ver = @import("../proto/version.zig");
const sshkeys = @import("../auth/sshkeys.zig");
const bootstrap = @import("../auth/bootstrap.zig");

const c = @cImport({
    @cInclude("unistd.h");
});

const cert_path = "src/transport/testdata/cert.pem";
const key_path = "src/transport/testdata/key.pem";

const ClientState = struct {
    control_sid: i64,
    data_sid: i64,
    ctrl_buf: std.ArrayList(u8) = .empty,
    data_buf: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,
    welcomed: bool = false,
    rejected: bool = false,

    fn onRecv(ctx: ?*anyopaque, stream_id: i64, bytes: []const u8) void {
        const self: *ClientState = @ptrCast(@alignCast(ctx));
        if (stream_id == self.data_sid) {
            self.data_buf.appendSlice(self.allocator, bytes) catch {};
            return;
        }
        if (stream_id != self.control_sid) return;
        self.ctrl_buf.appendSlice(self.allocator, bytes) catch return;
        while (true) {
            const items = self.ctrl_buf.items;
            if (items.len < 5) break;
            const plen = std.mem.readInt(u32, items[1..5], .little);
            const total = 5 + @as(usize, plen);
            if (items.len < total) break;
            const frame = frames.decode(items[0..total]) catch break;
            switch (frame) {
                .welcome => self.welcomed = true,
                .reject => self.rejected = true,
                else => {},
            }
            std.mem.copyForwards(u8, self.ctrl_buf.items[0 .. items.len - total], self.ctrl_buf.items[total..items.len]);
            self.ctrl_buf.shrinkRetainingCapacity(items.len - total);
        }
    }
};

const Outcome = struct { welcomed: bool, rejected: bool, saw_ready: bool };

// Drive one full require-key session in-process: hand the server the given
// authorized_keys, have the client sign the server's cert fingerprint with
// `secret`, and report whether the session was welcomed/rejected.
fn runSession(allocator: std.mem.Allocator, authorized: []const sshkeys.PublicKey, secret: sshkeys.SecretKeyBytes) !Outcome {
    var server = try quic.Server.init(allocator, "127.0.0.1", 0, cert_path, key_path);
    defer server.deinit();
    const port = server.localPort();

    var client = try quic.Client.connect(allocator, "127.0.0.1", port, "localhost");
    defer client.deinit();

    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        try client.step();
        try server.step();
        if (client.handshakeCompleted() and server.handshakeCompleted()) break;
        _ = c.usleep(1000);
    }
    try std.testing.expect(client.handshakeCompleted() and server.handshakeCompleted());

    const control_sid = try client.openStream();
    const data_sid = try client.openStream();

    var state = ClientState{ .control_sid = control_sid, .data_sid = data_sid, .allocator = allocator };
    defer state.ctrl_buf.deinit(allocator);
    defer state.data_buf.deinit(allocator);
    client.setRecvHandler(&state, ClientState.onRecv);

    var pty = try Pty.open(allocator);
    defer pty.close();
    var sess: ServerSession = undefined;
    sess.init(allocator, server, &pty);
    sess.authorized_keys = authorized;
    var own_fp = try bootstrap.fingerprintFromPemFile(cert_path);
    sess.own_cert_fp = own_fp;
    defer sess.deinit();

    // Channel binding: the client signs the server cert fingerprint it observes.
    var peer_fp: bootstrap.Fingerprint = undefined;
    try std.testing.expect(client.peerFingerprint(&peer_fp));
    try std.testing.expectEqualSlices(u8, &own_fp, &peer_fp);
    const sig = try sshkeys.signChallenge(secret, peer_fp);
    const proof = frames.AuthProof{ .pubkey = sshkeys.publicFromSecret(secret), .sig = sig };

    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try frames.encode(&hello, allocator, .{ .hello = .{
        .version = ver.current.toInt(),
        .capabilities = 0,
        .auth_method = .ssh_pubkey,
        .resume_session = null,
        .auth_proof = proof,
    } });
    try client.write(control_sid, hello.items);
    try client.write(data_sid, &[_]u8{session.data_open_marker});
    try client.step();

    const argv = [_][]const u8{ "/bin/sh", "-c", "printf ready; exit 0" };
    const env = [_][]const u8{"PATH=/usr/bin:/bin"};
    try pty.spawnShell(&argv, &env, .{ .cols = 80, .rows = 24 });

    var pbuf: [4096]u8 = undefined;
    i = 0;
    while (i < 2000) : (i += 1) {
        if (!sess.rejected) {
            const n = pty.read(&pbuf) catch 0;
            if (n > 0) sess.relayPtyOutput(pbuf[0..n]);
        }
        try server.step();
        try client.step();
        if (state.welcomed and std.mem.indexOf(u8, state.data_buf.items, "ready") != null) break;
        if (state.rejected) break;
        _ = c.usleep(1000);
    }

    return .{
        .welcomed = state.welcomed,
        .rejected = state.rejected,
        .saw_ready = std.mem.indexOf(u8, state.data_buf.items, "ready") != null,
    };
}

test "require-key: authorized identity completes, non-authorized rejected" {
    const a = std.testing.allocator;

    const secret = try sshkeys.loadPrivateKey(a, "src/auth/testdata/id_ed25519");
    const other = try sshkeys.loadPrivateKey(a, "src/auth/testdata/other_ed25519");

    var authorized = std.ArrayList(sshkeys.PublicKey).empty;
    defer authorized.deinit(a);
    try sshkeys.loadAuthorizedKeys(a, "src/auth/testdata/authorized_keys", &authorized);
    try std.testing.expectEqual(@as(usize, 1), authorized.items.len);

    const good = try runSession(a, authorized.items, secret);
    try std.testing.expect(good.welcomed);
    try std.testing.expect(!good.rejected);
    try std.testing.expect(good.saw_ready);

    const bad = try runSession(a, authorized.items, other);
    try std.testing.expect(bad.rejected);
    try std.testing.expect(!bad.welcomed);
}
