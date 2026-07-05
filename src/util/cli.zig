const std = @import("std");

const c = @cImport({
    @cInclude("unistd.h");
});

pub const version = "0.1.0";

pub fn writeStdout(bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = c.write(1, bytes.ptr + off, bytes.len - off);
        if (n <= 0) break;
        off += @intCast(n);
    }
}

pub fn writeStderr(bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = c.write(2, bytes.ptr + off, bytes.len - off);
        if (n <= 0) break;
        off += @intCast(n);
    }
}

pub fn printVersion(name: []const u8) void {
    var buf: [64]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "moonshine {s} {s}\n", .{ name, version }) catch return;
    writeStdout(s);
}

pub fn isHelp(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h");
}

pub fn isVersion(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-V");
}

pub fn isVerbose(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v");
}

pub const Verbose = struct {
    on: bool = false,

    pub fn log(self: Verbose, comptime fmt: []const u8, args: anytype) void {
        if (!self.on) return;
        var buf: [512]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "msh: " ++ fmt ++ "\n", args) catch return;
        writeStderr(s);
    }

    pub fn hex12(self: Verbose, label: []const u8, fp: []const u8) void {
        if (!self.on) return;
        const n: usize = @min(fp.len, @as(usize, 6));
        var hex: [12]u8 = undefined;
        const digits = "0123456789abcdef";
        var w: usize = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const b = fp[i];
            hex[w] = digits[b >> 4];
            hex[w + 1] = digits[b & 0xf];
            w += 2;
        }
        var buf: [128]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "msh: {s} {s}\n", .{ label, hex[0..w] }) catch return;
        writeStderr(s);
    }
};
