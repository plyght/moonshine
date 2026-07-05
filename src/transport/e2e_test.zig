const std = @import("std");
const quic = @import("quic.zig");
const Pty = @import("../pty/pty.zig").Pty;
const session = @import("../session.zig");
const ServerSession = session.ServerSession;

const c = @cImport({
    @cInclude("unistd.h");
});

const Collector = struct {
    data_sid: i64,
    buf: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,

    fn onRecv(ctx: ?*anyopaque, stream_id: i64, bytes: []const u8) void {
        const self: *Collector = @ptrCast(@alignCast(ctx));
        if (stream_id == self.data_sid) {
            self.buf.appendSlice(self.allocator, bytes) catch {};
        }
    }
};

test "end-to-end pty output over quic data stream" {
    const allocator = std.testing.allocator;

    var server = try quic.Server.init(allocator, "127.0.0.1", 0, "src/transport/testdata/cert.pem", "src/transport/testdata/key.pem");
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

    var collector = Collector{ .data_sid = data_sid, .allocator = allocator };
    defer collector.buf.deinit(allocator);
    client.setRecvHandler(&collector, Collector.onRecv);

    try client.write(control_sid, &[_]u8{ 0x10, 8, 0, 0, 0, 80, 0, 24, 0, 0, 0, 0, 0 });
    try client.write(data_sid, &[_]u8{session.data_open_marker});
    try client.step();

    var pty = try Pty.open(allocator);
    defer pty.close();

    var sess: ServerSession = undefined;
    sess.init(allocator, server, &pty);
    defer sess.deinit();

    const argv = [_][]const u8{ "/bin/sh", "-c", "printf ready; exit 0" };
    const env = [_][]const u8{"PATH=/usr/bin:/bin"};
    try pty.spawnShell(&argv, &env, .{ .cols = 80, .rows = 24 });

    var pbuf: [4096]u8 = undefined;
    i = 0;
    while (i < 2000) : (i += 1) {
        const n = pty.read(&pbuf) catch 0;
        if (n > 0) sess.relayPtyOutput(pbuf[0..n]);
        try server.step();
        try client.step();
        if (std.mem.indexOf(u8, collector.buf.items, "ready") != null) break;
        _ = c.usleep(1000);
    }

    try std.testing.expect(std.mem.indexOf(u8, collector.buf.items, "ready") != null);
}
