const std = @import("std");

const c = @cImport({
    @cInclude("util.h");
    @cInclude("termios.h");
    @cInclude("sys/ioctl.h");
    @cInclude("unistd.h");
    @cInclude("signal.h");
    @cInclude("stdlib.h");
    @cInclude("sys/wait.h");
    @cInclude("errno.h");
});

pub const Winsize = struct {
    cols: u16,
    rows: u16,
    xpix: u16 = 0,
    ypix: u16 = 0,

    fn toC(self: Winsize) c.struct_winsize {
        return .{
            .ws_col = self.cols,
            .ws_row = self.rows,
            .ws_xpixel = self.xpix,
            .ws_ypixel = self.ypix,
        };
    }
};

pub const Error = error{
    OpenPtyFailed,
    ForkFailed,
    IoctlFailed,
    ReadFailed,
    WriteFailed,
    OutOfMemory,
};

pub const Pty = struct {
    allocator: std.mem.Allocator,
    master: c_int,
    slave: c_int,
    child: c.pid_t = -1,

    pub fn open(allocator: std.mem.Allocator) Error!Pty {
        var master: c_int = -1;
        var slave: c_int = -1;
        if (c.openpty(&master, &slave, null, null, null) != 0) {
            return Error.OpenPtyFailed;
        }
        return .{
            .allocator = allocator,
            .master = master,
            .slave = slave,
            .child = -1,
        };
    }

    pub fn spawnShell(
        self: *Pty,
        argv: []const []const u8,
        env: []const []const u8,
        initial_size: Winsize,
    ) Error!void {
        const c_argv = try dupArgv(self.allocator, argv);
        defer freeCStrings(self.allocator, c_argv);
        const c_env = try dupEnv(self.allocator, env);
        defer freeCStrings(self.allocator, c_env);

        var ws = initial_size.toC();

        const pid = c.fork();
        if (pid < 0) return Error.ForkFailed;

        if (pid == 0) {
            _ = c.setsid();
            _ = c.ioctl(self.slave, c.TIOCSCTTY, @as(c_int, 0));
            _ = c.ioctl(self.slave, c.TIOCSWINSZ, &ws);
            _ = c.dup2(self.slave, 0);
            _ = c.dup2(self.slave, 1);
            _ = c.dup2(self.slave, 2);
            if (self.slave > 2) _ = c.close(self.slave);
            _ = c.close(self.master);
            _ = c.execve(c_argv[0].?, c_argv.ptr, c_env.ptr);
            c._exit(127);
        }

        self.child = pid;
        _ = c.close(self.slave);
        self.slave = -1;
    }

    pub fn read(self: *Pty, buf: []u8) Error!usize {
        const n = c.read(self.master, buf.ptr, buf.len);
        if (n < 0) return Error.ReadFailed;
        return @intCast(n);
    }

    pub fn write(self: *Pty, bytes: []const u8) Error!usize {
        const n = c.write(self.master, bytes.ptr, bytes.len);
        if (n < 0) return Error.WriteFailed;
        return @intCast(n);
    }

    pub fn resize(self: *Pty, cols: u16, rows: u16) Error!void {
        var ws: c.struct_winsize = .{
            .ws_col = cols,
            .ws_row = rows,
            .ws_xpixel = 0,
            .ws_ypixel = 0,
        };
        if (c.ioctl(self.master, c.TIOCSWINSZ, &ws) != 0) {
            return Error.IoctlFailed;
        }
    }

    pub fn close(self: *Pty) void {
        if (self.master >= 0) {
            _ = c.close(self.master);
            self.master = -1;
        }
        if (self.slave >= 0) {
            _ = c.close(self.slave);
            self.slave = -1;
        }
        if (self.child > 0) {
            var status: c_int = 0;
            const r = c.waitpid(self.child, &status, c.WNOHANG);
            if (r == 0) {
                _ = c.kill(self.child, c.SIGTERM);
                _ = c.waitpid(self.child, &status, 0);
            }
            self.child = -1;
        }
    }
};

fn defaultShell() []const u8 {
    if (c.getenv("SHELL")) |s| {
        return std.mem.span(s);
    }
    return "/bin/zsh";
}

fn dupArgv(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
) Error![:null]?[*:0]u8 {
    if (argv.len == 0) {
        const sh = defaultShell();
        var list = std.ArrayList(?[*:0]u8).empty;
        errdefer freeList(allocator, &list);
        try list.append(allocator, try allocator.dupeZ(u8, sh));
        return try finishList(allocator, &list);
    }
    var list = std.ArrayList(?[*:0]u8).empty;
    errdefer freeList(allocator, &list);
    for (argv) |a| {
        try list.append(allocator, try allocator.dupeZ(u8, a));
    }
    return try finishList(allocator, &list);
}

fn dupEnv(
    allocator: std.mem.Allocator,
    env: []const []const u8,
) Error![:null]?[*:0]u8 {
    var list = std.ArrayList(?[*:0]u8).empty;
    errdefer freeList(allocator, &list);
    for (env) |e| {
        try list.append(allocator, try allocator.dupeZ(u8, e));
    }
    return try finishList(allocator, &list);
}

fn finishList(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(?[*:0]u8),
) Error![:null]?[*:0]u8 {
    try list.append(allocator, null);
    const owned = try list.toOwnedSlice(allocator);
    return owned[0 .. owned.len - 1 :null];
}

fn freeList(allocator: std.mem.Allocator, list: *std.ArrayList(?[*:0]u8)) void {
    for (list.items) |item| {
        if (item) |p| allocator.free(std.mem.span(p));
    }
    list.deinit(allocator);
}

fn freeCStrings(allocator: std.mem.Allocator, arr: [:null]?[*:0]u8) void {
    var i: usize = 0;
    while (arr[i]) |p| : (i += 1) {
        allocator.free(std.mem.span(p));
    }
    const full = arr.ptr[0 .. i + 1];
    allocator.free(full);
}

test "spawn shell, read output, reap child" {
    const allocator = std.testing.allocator;
    var pty = try Pty.open(allocator);
    defer pty.close();

    const argv = [_][]const u8{ "/bin/sh", "-c", "printf hi" };
    const env = [_][]const u8{"PATH=/usr/bin:/bin"};
    try pty.spawnShell(&argv, &env, .{ .cols = 80, .rows = 24 });

    var buf: [256]u8 = undefined;
    var seen = std.ArrayList(u8).empty;
    defer seen.deinit(allocator);

    var attempts: usize = 0;
    while (attempts < 1000) : (attempts += 1) {
        const n = pty.read(&buf) catch break;
        if (n == 0) break;
        try seen.appendSlice(allocator, buf[0..n]);
        if (std.mem.indexOf(u8, seen.items, "hi") != null) break;
    }

    try std.testing.expect(std.mem.indexOf(u8, seen.items, "hi") != null);
}

test "resize does not error" {
    const allocator = std.testing.allocator;
    var pty = try Pty.open(allocator);
    defer pty.close();

    const argv = [_][]const u8{ "/bin/sh", "-c", "sleep 0.1" };
    const env = [_][]const u8{"PATH=/usr/bin:/bin"};
    try pty.spawnShell(&argv, &env, .{ .cols = 80, .rows = 24 });

    try pty.resize(120, 40);
}
