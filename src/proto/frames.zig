const std = @import("std");
const ver = @import("version.zig");

pub const max_frame_len: u32 = 1 << 20;

pub const FrameType = enum(u8) {
    hello = 0x01,
    welcome = 0x02,
    reject = 0x03,
    resize = 0x10,
    ack = 0x11,
    ping = 0x12,
    pong = 0x13,
    shutdown = 0x20,
    _,
};

pub const AuthMethod = enum(u8) {
    bootstrap_token = 0x00,
    ssh_pubkey = 0x01,
    daemon_cert = 0x02,
    underlay_trust = 0x03,
    _,
};

pub const StreamMap = struct {
    term_in: u64,
    term_out: u64,
};

pub const OptSession = struct {
    session_id: [16]u8,
    last_consumed: u64,
};

pub const Hello = struct {
    version: u16,
    capabilities: u64,
    auth_method: AuthMethod,
    resume_session: ?OptSession,
    auth_token: ?[]const u8 = null,
};

pub const Welcome = struct {
    version: u16,
    capabilities: u64,
    stream_map: StreamMap,
    session_id: [16]u8,
};

pub const Reject = struct {
    reason_code: u16,
    min_version: u16,
    max_version: u16,
};

pub const Resize = struct {
    cols: u16,
    rows: u16,
    xpix: u16,
    ypix: u16,
};

pub const Ack = struct {
    stream: u8,
    consumed_seq: u64,
};

pub const Ping = struct {
    nonce: u64,
};

pub const Pong = struct {
    nonce: u64,
};

pub const Shutdown = struct {
    reason_code: u16,
    exit_status: i32,
};

pub const Unknown = struct {
    type: u8,
    payload: []const u8,
};

pub const Frame = union(enum) {
    hello: Hello,
    welcome: Welcome,
    reject: Reject,
    resize: Resize,
    ack: Ack,
    ping: Ping,
    pong: Pong,
    shutdown: Shutdown,
    unknown: Unknown,
};

pub const DataFrame = struct {
    seq: u64,
    bytes: []const u8,
};

pub const DecodeError = error{
    Truncated,
    FrameTooLarge,
};

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn remaining(r: Reader) usize {
        return r.buf.len - r.pos;
    }

    fn take(r: *Reader, n: usize) DecodeError![]const u8 {
        if (r.remaining() < n) return error.Truncated;
        const s = r.buf[r.pos .. r.pos + n];
        r.pos += n;
        return s;
    }

    fn u8_(r: *Reader) DecodeError!u8 {
        return (try r.take(1))[0];
    }

    fn int(r: *Reader, comptime T: type) DecodeError!T {
        const n = @sizeOf(T);
        const s = try r.take(n);
        return std.mem.readInt(T, s[0..n], .little);
    }

    fn arr16(r: *Reader) DecodeError![16]u8 {
        const s = try r.take(16);
        var out: [16]u8 = undefined;
        @memcpy(&out, s);
        return out;
    }
};

const Buf = std.ArrayList(u8);

fn putInt(w: *Buf, a: std.mem.Allocator, comptime T: type, v: T) !void {
    var tmp: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &tmp, v, .little);
    try w.appendSlice(a, &tmp);
}

fn encodeStreamMap(w: *Buf, a: std.mem.Allocator, sm: StreamMap) !void {
    try putInt(w, a, u64, sm.term_in);
    try putInt(w, a, u64, sm.term_out);
}

fn decodeStreamMap(r: *Reader) !StreamMap {
    return .{ .term_in = try r.int(u64), .term_out = try r.int(u64) };
}

fn encodeOptSession(w: *Buf, a: std.mem.Allocator, opt: ?OptSession) !void {
    if (opt) |s| {
        try w.append(a, 1);
        try w.appendSlice(a, &s.session_id);
        try putInt(w, a, u64, s.last_consumed);
    } else {
        try w.append(a, 0);
    }
}

fn decodeOptSession(r: *Reader) !?OptSession {
    const present = try r.u8_();
    if (present == 0) return null;
    return .{ .session_id = try r.arr16(), .last_consumed = try r.int(u64) };
}

fn encodeAuthToken(w: *Buf, a: std.mem.Allocator, tok: ?[]const u8) !void {
    if (tok) |t| {
        try w.append(a, 1);
        try putInt(w, a, u16, @intCast(t.len));
        try w.appendSlice(a, t);
    } else {
        try w.append(a, 0);
    }
}

fn decodeAuthToken(r: *Reader) !?[]const u8 {
    if (r.remaining() == 0) return null;
    const present = try r.u8_();
    if (present == 0) return null;
    const len = try r.int(u16);
    return try r.take(len);
}

fn encodePayload(w: *Buf, a: std.mem.Allocator, frame: Frame) !void {
    switch (frame) {
        .hello => |h| {
            try putInt(w, a, u16, h.version);
            try putInt(w, a, u64, h.capabilities);
            try w.append(a, @intFromEnum(h.auth_method));
            try encodeOptSession(w, a, h.resume_session);
            try encodeAuthToken(w, a, h.auth_token);
        },
        .welcome => |m| {
            try putInt(w, a, u16, m.version);
            try putInt(w, a, u64, m.capabilities);
            try encodeStreamMap(w, a, m.stream_map);
            try w.appendSlice(a, &m.session_id);
        },
        .reject => |m| {
            try putInt(w, a, u16, m.reason_code);
            try putInt(w, a, u16, m.min_version);
            try putInt(w, a, u16, m.max_version);
        },
        .resize => |m| {
            try putInt(w, a, u16, m.cols);
            try putInt(w, a, u16, m.rows);
            try putInt(w, a, u16, m.xpix);
            try putInt(w, a, u16, m.ypix);
        },
        .ack => |m| {
            try w.append(a, m.stream);
            try putInt(w, a, u64, m.consumed_seq);
        },
        .ping => |m| try putInt(w, a, u64, m.nonce),
        .pong => |m| try putInt(w, a, u64, m.nonce),
        .shutdown => |m| {
            try putInt(w, a, u16, m.reason_code);
            try putInt(w, a, i32, m.exit_status);
        },
        .unknown => |u| try w.appendSlice(a, u.payload),
    }
}

fn frameTypeByte(frame: Frame) u8 {
    return switch (frame) {
        .hello => @intFromEnum(FrameType.hello),
        .welcome => @intFromEnum(FrameType.welcome),
        .reject => @intFromEnum(FrameType.reject),
        .resize => @intFromEnum(FrameType.resize),
        .ack => @intFromEnum(FrameType.ack),
        .ping => @intFromEnum(FrameType.ping),
        .pong => @intFromEnum(FrameType.pong),
        .shutdown => @intFromEnum(FrameType.shutdown),
        .unknown => |u| u.type,
    };
}

pub fn encode(w: *Buf, a: std.mem.Allocator, frame: Frame) !void {
    var payload: Buf = .empty;
    defer payload.deinit(a);
    try encodePayload(&payload, a, frame);
    if (payload.items.len > max_frame_len) return error.FrameTooLarge;
    try w.append(a, frameTypeByte(frame));
    try putInt(w, a, u32, @intCast(payload.items.len));
    try w.appendSlice(a, payload.items);
}

pub fn decode(buf: []const u8) !Frame {
    var r = Reader{ .buf = buf };
    const t = try r.u8_();
    const length = try r.int(u32);
    if (length > max_frame_len) return error.FrameTooLarge;
    const payload = try r.take(length);
    var pr = Reader{ .buf = payload };
    const ft: FrameType = @enumFromInt(t);
    switch (ft) {
        .hello => return .{ .hello = .{
            .version = try pr.int(u16),
            .capabilities = try pr.int(u64),
            .auth_method = @enumFromInt(try pr.u8_()),
            .resume_session = try decodeOptSession(&pr),
            .auth_token = try decodeAuthToken(&pr),
        } },
        .welcome => return .{ .welcome = .{
            .version = try pr.int(u16),
            .capabilities = try pr.int(u64),
            .stream_map = try decodeStreamMap(&pr),
            .session_id = try pr.arr16(),
        } },
        .reject => return .{ .reject = .{
            .reason_code = try pr.int(u16),
            .min_version = try pr.int(u16),
            .max_version = try pr.int(u16),
        } },
        .resize => return .{ .resize = .{
            .cols = try pr.int(u16),
            .rows = try pr.int(u16),
            .xpix = try pr.int(u16),
            .ypix = try pr.int(u16),
        } },
        .ack => return .{ .ack = .{
            .stream = try pr.u8_(),
            .consumed_seq = try pr.int(u64),
        } },
        .ping => return .{ .ping = .{ .nonce = try pr.int(u64) } },
        .pong => return .{ .pong = .{ .nonce = try pr.int(u64) } },
        .shutdown => return .{ .shutdown = .{
            .reason_code = try pr.int(u16),
            .exit_status = try pr.int(i32),
        } },
        _ => return .{ .unknown = .{ .type = t, .payload = payload } },
    }
}

pub fn encodeData(w: *Buf, a: std.mem.Allocator, df: DataFrame) !void {
    if (df.bytes.len > std.math.maxInt(u32)) return error.FrameTooLarge;
    try putInt(w, a, u64, df.seq);
    try putInt(w, a, u32, @intCast(df.bytes.len));
    try w.appendSlice(a, df.bytes);
}

pub fn decodeData(buf: []const u8) !DataFrame {
    var r = Reader{ .buf = buf };
    const seq = try r.int(u64);
    const len = try r.int(u32);
    const bytes = try r.take(len);
    return .{ .seq = seq, .bytes = bytes };
}

const testing = std.testing;

fn roundTrip(a: std.mem.Allocator, frame: Frame) !Frame {
    var w: Buf = .empty;
    defer w.deinit(a);
    try encode(&w, a, frame);
    return decode(w.items);
}

test "round-trip hello with resume" {
    const a = testing.allocator;
    const f: Frame = .{ .hello = .{
        .version = 0x0001,
        .capabilities = ver.Capabilities.PREDICT | ver.Capabilities.RESUME,
        .auth_method = .ssh_pubkey,
        .resume_session = .{ .session_id = [_]u8{7} ** 16, .last_consumed = 4242 },
    } };
    const got = try roundTrip(a, f);
    try testing.expectEqual(f.hello.version, got.hello.version);
    try testing.expectEqual(f.hello.capabilities, got.hello.capabilities);
    try testing.expectEqual(f.hello.auth_method, got.hello.auth_method);
    try testing.expectEqualSlices(u8, &f.hello.resume_session.?.session_id, &got.hello.resume_session.?.session_id);
    try testing.expectEqual(@as(u64, 4242), got.hello.resume_session.?.last_consumed);
}

test "round-trip hello without resume" {
    const a = testing.allocator;
    const f: Frame = .{ .hello = .{
        .version = 0x0001,
        .capabilities = 0,
        .auth_method = .bootstrap_token,
        .resume_session = null,
    } };
    const got = try roundTrip(a, f);
    try testing.expect(got.hello.resume_session == null);
}

test "round-trip hello with auth token" {
    const a = testing.allocator;
    const token = [_]u8{0x5A} ** 32;
    const f: Frame = .{ .hello = .{
        .version = 0x0001,
        .capabilities = 0,
        .auth_method = .bootstrap_token,
        .resume_session = null,
        .auth_token = &token,
    } };
    // decode borrows slices from the encode buffer, so keep it alive across asserts.
    var w: Buf = .empty;
    defer w.deinit(a);
    try encode(&w, a, f);
    const got = try decode(w.items);
    try testing.expect(got.hello.auth_token != null);
    try testing.expectEqualSlices(u8, &token, got.hello.auth_token.?);
    try testing.expect(got.hello.resume_session == null);
}

test "round-trip hello without auth token" {
    const a = testing.allocator;
    const f: Frame = .{ .hello = .{
        .version = 0x0001,
        .capabilities = 0,
        .auth_method = .underlay_trust,
        .resume_session = null,
        .auth_token = null,
    } };
    const got = try roundTrip(a, f);
    try testing.expect(got.hello.auth_token == null);
}

test "round-trip hello with resume and auth token" {
    const a = testing.allocator;
    const token = [_]u8{0x11} ** 32;
    const f: Frame = .{ .hello = .{
        .version = 0x0001,
        .capabilities = ver.Capabilities.RESUME,
        .auth_method = .bootstrap_token,
        .resume_session = .{ .session_id = [_]u8{3} ** 16, .last_consumed = 99 },
        .auth_token = &token,
    } };
    var w: Buf = .empty;
    defer w.deinit(a);
    try encode(&w, a, f);
    const got = try decode(w.items);
    try testing.expectEqual(@as(u64, 99), got.hello.resume_session.?.last_consumed);
    try testing.expectEqualSlices(u8, &token, got.hello.auth_token.?);
}

test "round-trip welcome" {
    const a = testing.allocator;
    const f: Frame = .{ .welcome = .{
        .version = 0x0001,
        .capabilities = ver.Capabilities.MIGRATE,
        .stream_map = .{ .term_in = 4, .term_out = 7 },
        .session_id = [_]u8{0xAB} ** 16,
    } };
    const got = try roundTrip(a, f);
    try testing.expectEqual(@as(u64, 4), got.welcome.stream_map.term_in);
    try testing.expectEqual(@as(u64, 7), got.welcome.stream_map.term_out);
    try testing.expectEqualSlices(u8, &f.welcome.session_id, &got.welcome.session_id);
}

test "round-trip reject" {
    const a = testing.allocator;
    const f: Frame = .{ .reject = .{ .reason_code = 3, .min_version = 0x0001, .max_version = 0x0102 } };
    const got = try roundTrip(a, f);
    try testing.expectEqual(f.reject, got.reject);
}

test "round-trip resize" {
    const a = testing.allocator;
    const f: Frame = .{ .resize = .{ .cols = 80, .rows = 24, .xpix = 640, .ypix = 480 } };
    const got = try roundTrip(a, f);
    try testing.expectEqual(f.resize, got.resize);
}

test "round-trip ack" {
    const a = testing.allocator;
    const f: Frame = .{ .ack = .{ .stream = 2, .consumed_seq = 999999 } };
    const got = try roundTrip(a, f);
    try testing.expectEqual(f.ack, got.ack);
}

test "round-trip ping pong" {
    const a = testing.allocator;
    const p: Frame = .{ .ping = .{ .nonce = 0xDEADBEEF } };
    try testing.expectEqual(@as(u64, 0xDEADBEEF), (try roundTrip(a, p)).ping.nonce);
    const q: Frame = .{ .pong = .{ .nonce = 0xCAFE } };
    try testing.expectEqual(@as(u64, 0xCAFE), (try roundTrip(a, q)).pong.nonce);
}

test "round-trip shutdown" {
    const a = testing.allocator;
    const f: Frame = .{ .shutdown = .{ .reason_code = 1, .exit_status = -5 } };
    const got = try roundTrip(a, f);
    try testing.expectEqual(f.shutdown, got.shutdown);
}

test "unknown frame type preserved" {
    const a = testing.allocator;
    var w: Buf = .empty;
    defer w.deinit(a);
    try w.append(a, 0x7F);
    try putInt(&w, a, u32, 3);
    try w.appendSlice(a, &[_]u8{ 1, 2, 3 });
    const got = try decode(w.items);
    try testing.expectEqual(@as(u8, 0x7F), got.unknown.type);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, got.unknown.payload);
}

test "data frame round-trip" {
    const a = testing.allocator;
    var w: Buf = .empty;
    defer w.deinit(a);
    const payload = "keystrokes";
    try encodeData(&w, a, .{ .seq = 12345, .bytes = payload });
    const got = try decodeData(w.items);
    try testing.expectEqual(@as(u64, 12345), got.seq);
    try testing.expectEqualSlices(u8, payload, got.bytes);
}

test "truncated frame returns error" {
    const a = testing.allocator;
    var w: Buf = .empty;
    defer w.deinit(a);
    const f: Frame = .{ .ping = .{ .nonce = 42 } };
    try encode(&w, a, f);
    try testing.expectError(error.Truncated, decode(w.items[0 .. w.items.len - 2]));
    try testing.expectError(error.Truncated, decode(w.items[0..2]));
}

test "truncated data frame returns error" {
    const a = testing.allocator;
    var w: Buf = .empty;
    defer w.deinit(a);
    try encodeData(&w, a, .{ .seq = 1, .bytes = "abcd" });
    try testing.expectError(error.Truncated, decodeData(w.items[0 .. w.items.len - 1]));
}
