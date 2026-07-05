const std = @import("std");
const sshkeys = @import("sshkeys.zig");

const c = @cImport({
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
    @cInclude("sys/stat.h");
});

pub const Fingerprint = [32]u8;

pub const Error = error{
    Mismatch,
    OutOfMemory,
    IoFailed,
};

const hex_chars = "0123456789abcdef";

pub fn hexEncode(fp: Fingerprint, out: *[64]u8) void {
    for (fp, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0f];
    }
}

fn hexDecode(s: []const u8, out: *Fingerprint) bool {
    if (s.len != 64) return false;
    for (0..32) |i| {
        const hi = std.fmt.charToDigit(s[i * 2], 16) catch return false;
        const lo = std.fmt.charToDigit(s[i * 2 + 1], 16) catch return false;
        out[i] = (@as(u8, hi) << 4) | lo;
    }
    return true;
}

pub const Result = enum { new, match, mismatch };

/// Look up `host` in a known_hosts text buffer. Returns the stored fingerprint,
/// or null if the host is unknown.
pub fn lookup(contents: []const u8, host: []const u8, out: *Fingerprint) bool {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        const h = fields.next() orelse continue;
        if (!std.mem.eql(u8, h, host)) continue;
        const fp_hex = fields.next() orelse continue;
        if (hexDecode(fp_hex, out)) return true;
    }
    return false;
}

/// Trust-on-first-use check against a known_hosts file at `path`.
///   - unknown host  -> append `host fp` and return .new
///   - known + equal  -> return .match
///   - known + differ -> return .mismatch (caller must refuse)
/// A missing file is treated as empty (first use).
pub fn check(allocator: std.mem.Allocator, path: []const u8, host: []const u8, fp: Fingerprint) Error!Result {
    const contents: []u8 = sshkeys.readFileAlloc(allocator, path, 1 << 20) catch &.{};
    defer if (contents.len > 0) allocator.free(contents);

    var stored: Fingerprint = undefined;
    if (lookup(contents, host, &stored)) {
        if (std.mem.eql(u8, &stored, &fp)) return .match;
        return .mismatch;
    }

    // Unknown: append a new pinning line. Create parent dirs (0700) as needed.
    if (std.fs.path.dirname(path)) |dir| makePath(allocator, dir) catch {};

    var hex: [64]u8 = undefined;
    hexEncode(fp, &hex);
    var lbuf: [512]u8 = undefined;
    const line = std.fmt.bufPrint(&lbuf, "{s} {s}\n", .{ host, hex[0..] }) catch return Error.IoFailed;
    appendFile(allocator, path, line) catch return Error.IoFailed;
    return .new;
}

fn makePath(allocator: std.mem.Allocator, dir: []const u8) !void {
    // Create each ancestor directory in turn (0700). Existing dirs are fine.
    var i: usize = 0;
    while (i < dir.len) : (i += 1) {
        if (dir[i] == '/' and i > 0) {
            const sub = try allocator.dupeZ(u8, dir[0..i]);
            defer allocator.free(sub);
            _ = c.mkdir(sub.ptr, 0o700);
        }
    }
    const full = try allocator.dupeZ(u8, dir);
    defer allocator.free(full);
    _ = c.mkdir(full.ptr, 0o700);
}

fn appendFile(allocator: std.mem.Allocator, path: []const u8, bytes: []const u8) !void {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    const fd = c.open(path_z.ptr, c.O_WRONLY | c.O_CREAT | c.O_APPEND, @as(c_uint, 0o600));
    if (fd < 0) return error.IoFailed;
    defer _ = c.close(fd);
    var off: usize = 0;
    while (off < bytes.len) {
        const n = c.write(fd, bytes.ptr + off, bytes.len - off);
        if (n <= 0) return error.IoFailed;
        off += @intCast(n);
    }
}

const testing = std.testing;

test "tofu first-use stores, matches, and detects mismatch" {
    const a = testing.allocator;
    var namebuf: [64]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&namebuf, "/tmp/msh-tofu-test-{d}", .{c.getpid()});
    _ = c.unlink(path.ptr);
    defer _ = c.unlink(path.ptr);

    var fp: Fingerprint = undefined;
    for (&fp, 0..) |*p, i| p.* = @intCast(i);

    try testing.expectEqual(Result.new, try check(a, path, "host.example", fp));
    try testing.expectEqual(Result.match, try check(a, path, "host.example", fp));

    var other = fp;
    other[0] ^= 0xFF;
    try testing.expectEqual(Result.mismatch, try check(a, path, "host.example", other));

    // A different host on first use is also .new and does not disturb the first.
    try testing.expectEqual(Result.new, try check(a, path, "other.example", other));
    try testing.expectEqual(Result.match, try check(a, path, "host.example", fp));
}
