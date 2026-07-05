const std = @import("std");
const quic = @import("quic.zig");

const c = @cImport({
    @cInclude("unistd.h");
});

const Sink = struct {
    sid: i64,
    buf: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,

    fn onRecv(ctx: ?*anyopaque, stream_id: i64, bytes: []const u8) void {
        const self: *Sink = @ptrCast(@alignCast(ctx));
        if (stream_id == self.sid) self.buf.appendSlice(self.allocator, bytes) catch {};
    }
};

fn pump(client: *quic.Conn, server: *quic.Conn, cap: usize) !void {
    var i: usize = 0;
    while (i < cap) : (i += 1) {
        try client.step();
        try server.step();
        _ = c.usleep(1000);
    }
}

test "roamer decides to migrate only when the preferred IP actually changed" {
    const a: u32 = 0x0100007f; // 127.0.0.1 in network order
    const b: u32 = 0x0101a8c0; // 192.168.1.1 in network order
    try std.testing.expect(quic.Roamer.decide(a, b));
    try std.testing.expect(!quic.Roamer.decide(a, a));
    try std.testing.expect(!quic.Roamer.decide(a, 0)); // unknown/invalid preferred
}

test "quic connection survives client migration to a new local port" {
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

    // Let the handshake confirm so unused connection IDs are available for
    // migration (NEW_CONNECTION_ID frames must be exchanged first).
    try pump(client, server, 50);

    const sid = try client.openStream();

    var sink = Sink{ .sid = sid, .allocator = allocator };
    defer sink.buf.deinit(allocator);
    server.setRecvHandler(&sink, Sink.onRecv);

    const first = "before-migration";
    try client.write(sid, first);
    i = 0;
    while (i < 2000) : (i += 1) {
        try client.step();
        try server.step();
        if (std.mem.indexOf(u8, sink.buf.items, first) != null) break;
        _ = c.usleep(1000);
    }
    try std.testing.expect(std.mem.indexOf(u8, sink.buf.items, first) != null);

    const old_port = client.localPort();
    try client.migrate();
    try std.testing.expect(client.localPort() != old_port);

    // Drive path validation to completion on the new path.
    try pump(client, server, 100);

    const second = "after-migration";
    try client.write(sid, second);
    i = 0;
    while (i < 2000) : (i += 1) {
        try client.step();
        try server.step();
        if (std.mem.indexOf(u8, sink.buf.items, second) != null) break;
        _ = c.usleep(1000);
    }
    try std.testing.expect(std.mem.indexOf(u8, sink.buf.items, second) != null);
}
