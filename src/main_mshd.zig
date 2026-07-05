const std = @import("std");
const quic = @import("transport/quic.zig");
const Pty = @import("pty/pty.zig").Pty;
const ServerSession = @import("session.zig").ServerSession;
const bootstrap = @import("auth/bootstrap.zig");
const cli = @import("util/cli.zig");

const usage_text =
    \\mshd — the moonshine server daemon (secure interactive shell over QUIC)
    \\
    \\usage:
    \\  mshd --listen [addr:]port           serve on a trusted underlay
    \\  mshd --bootstrap                    one-time mutual-trust session (via ssh)
    \\
    \\options:
    \\  --listen [addr:]port      bind address/port (default 0.0.0.0:4433)
    \\  --bootstrap               mint a one-time token + ephemeral cert, print a
    \\                            MSH-BOOTSTRAP line, and serve exactly one session
    \\  --cert <path>             TLS certificate (PEM)
    \\  --key <path>              TLS private key (PEM)
    \\  -h, --help                show this help and exit
    \\  -V, --version             print version and exit
    \\
    \\examples:
    \\  mshd --listen 100.64.0.2:4433
    \\  mshd --bootstrap
    \\
;

// Stream convention: the client opens CONTROL (bidi id 0) then DATA (bidi id 4).
// CONTROL carries `frames`-encoded messages (Resize); DATA carries raw terminal
// bytes full-duplex. The server derives DATA = CONTROL + 4. See session.zig.

const c = @cImport({
    @cInclude("poll.h");
    @cInclude("unistd.h");
    @cInclude("errno.h");
    @cInclude("time.h");
});

fn monotonicNs() u64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(u64, @intCast(ts.tv_sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.tv_nsec));
}

const default_cert = "src/transport/testdata/cert.pem";
const default_key = "src/transport/testdata/key.pem";

fn friendlyError(err: anyerror) noreturn {
    switch (err) {
        error.MissingArg => cli.writeStderr("mshd: missing value for a flag. Try 'mshd --help'.\n"),
        error.InvalidCharacter, error.Overflow => cli.writeStderr("mshd: bad listen address or port. Try 'mshd --help'.\n"),
        else => cli.writeStderr("mshd: could not start (address in use or bad cert/key).\n"),
    }
    const code: u8 = switch (err) {
        error.MissingArg, error.InvalidCharacter, error.Overflow => 1,
        else => 2,
    };
    std.process.exit(code);
}

pub fn main(init: std.process.Init.Minimal) !void {
    {
        var scan = init.args.iterate();
        _ = scan.next();
        while (scan.next()) |arg| {
            if (cli.isHelp(arg)) {
                cli.writeStdout(usage_text);
                return;
            }
            if (cli.isVersion(arg)) {
                cli.printVersion("mshd");
                return;
            }
        }
    }

    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    run(init, gpa) catch |err| friendlyError(err);
}

fn run(init: std.process.Init.Minimal, gpa: std.mem.Allocator) !void {
    // CLI:
    //   mshd --listen [addr:]port   (underlay-trust: relies on network trust)
    //   mshd --bootstrap            (mutual trust via ssh bootstrap; requires token)
    var listen_port: u16 = 4433;
    var bind_addr: []const u8 = "0.0.0.0";
    var cert_path: []const u8 = default_cert;
    var key_path: []const u8 = default_key;
    var boot_mode = false;

    var it = init.args.iterate();
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--listen")) {
            const spec = it.next() orelse return error.MissingArg;
            if (std.mem.lastIndexOfScalar(u8, spec, ':')) |idx| {
                bind_addr = spec[0..idx];
                listen_port = try std.fmt.parseInt(u16, spec[idx + 1 ..], 10);
            } else {
                listen_port = try std.fmt.parseInt(u16, spec, 10);
            }
        } else if (std.mem.eql(u8, arg, "--bootstrap")) {
            boot_mode = true;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            cert_path = it.next() orelse return error.MissingArg;
        } else if (std.mem.eql(u8, arg, "--key")) {
            key_path = it.next() orelse return error.MissingArg;
        }
    }

    var eph: ?bootstrap.Ephemeral = null;
    defer if (eph) |*e| e.deinit();
    var required_token: ?bootstrap.Token = null;

    if (boot_mode) {
        // Ephemeral identity generated fresh per invocation; the client binds
        // trust to it via the fingerprint carried over the ssh channel.
        eph = try bootstrap.generateEphemeral(gpa);
        cert_path = eph.?.cert_path;
        key_path = eph.?.key_path;
        required_token = bootstrap.randomToken();
        bind_addr = "0.0.0.0";
        listen_port = 0;
    }

    const conn = try quic.Server.init(gpa, bind_addr, listen_port, cert_path, key_path);
    defer conn.deinit();

    if (boot_mode) {
        var line_buf: [256]u8 = undefined;
        const line = try bootstrap.formatLine(&line_buf, conn.localPort(), eph.?.fingerprint, required_token.?);
        _ = c.write(1, line.ptr, line.len);
    } else {
        var stdout_buf: [128]u8 = undefined;
        const msg = try std.fmt.bufPrint(&stdout_buf, "listening {d} (underlay-trust: relies on network trust)\n", .{conn.localPort()});
        _ = c.write(1, msg.ptr, msg.len);
    }

    // Bootstrap mode serves exactly one session; give a client ~30s to connect.
    const deadline_ns: u64 = monotonicNs() + 30 * std.time.ns_per_s;
    while (!conn.handshakeCompleted()) {
        try conn.poll(50);
        if (conn.peerClosed()) return;
        if (boot_mode and monotonicNs() > deadline_ns) return;
    }

    var pty = try Pty.open(gpa);
    defer pty.close();

    var env_list = std.ArrayList([]const u8).empty;
    defer env_list.deinit(gpa);
    for (init.environ.block.slice) |e| {
        if (e) |ptr| try env_list.append(gpa, std.mem.span(ptr));
    }
    try env_list.append(gpa, "TERM=xterm-256color");

    try pty.spawnShell(&.{}, env_list.items, .{ .cols = 80, .rows = 24 });

    var session: ServerSession = undefined;
    session.init(gpa, conn, &pty);
    session.required_token = required_token;
    defer session.deinit();

    var pfds = [_]c.struct_pollfd{
        .{ .fd = conn.socketFd(), .events = c.POLLIN, .revents = 0 },
        .{ .fd = pty.master, .events = c.POLLIN, .revents = 0 },
    };

    var buf: [16384]u8 = undefined;
    while (true) {
        pfds[0].revents = 0;
        pfds[1].revents = 0;
        _ = c.poll(&pfds, 2, 10);

        if (pfds[0].revents & (c.POLLIN | c.POLLERR | c.POLLHUP) != 0) {
            conn.step() catch break;
        }
        if (session.rejected) {
            conn.step() catch {};
            break;
        }
        if (conn.peerClosed()) break;
        if (pfds[1].revents & (c.POLLIN | c.POLLERR | c.POLLHUP) != 0) {
            const n = pty.read(&buf) catch break;
            if (n == 0) break;
            session.relayPtyOutput(buf[0..n]);
        }

        conn.step() catch break;
        if (conn.peerClosed()) break;
    }

    // The shell exited (or the peer left): tell the client immediately so it
    // doesn't wait out the idle timeout.
    conn.closeGraceful();
    conn.step() catch {};
}
