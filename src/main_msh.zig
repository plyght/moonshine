const std = @import("std");
const quic = @import("transport/quic.zig");
const frames = @import("proto/frames.zig");
const term_raw = @import("util/term_raw.zig");
const session = @import("session.zig");
const ver = @import("proto/version.zig");
const predict = @import("term/predict.zig");
const bootstrap = @import("auth/bootstrap.zig");
const cli = @import("util/cli.zig");

const default_port: u16 = 4433;

const usage_text =
    \\msh — a modern, joyful alternative to ssh (secure interactive shell over QUIC)
    \\
    \\usage:
    \\  msh [user@]host[:port]              connect over a trusted underlay
    \\  msh --connect host[:port]           same, explicit form
    \\  msh --ssh [user@]host               bootstrap over ssh (mutual trust)
    \\
    \\options:
    \\  --connect host[:port]     host to connect to (default port 4433)
    \\  --ssh [user@]host         run `mshd --bootstrap` over ssh, pin its cert, connect
    \\  --server-cmd <cmd>        remote command for --ssh (default: mshd --bootstrap)
    \\  --server-name <sni>       override the TLS SNI name (default: host)
    \\  --bootstrap-line "<line>" feed a bootstrap line directly (dev/testing)
    \\  -v, --verbose             print diagnostics to stderr
    \\  -h, --help                show this help and exit
    \\  -V, --version             print version and exit
    \\
    \\examples:
    \\  msh --ssh me@server.example.com
    \\  msh --connect 100.64.0.2:4433
    \\
;

// Stream convention: after the handshake the client opens two client-initiated
// bidi streams in order. The first (id 0) is CONTROL, carrying `frames`-encoded
// messages (Resize). The second (id 4) is DATA, carrying raw terminal bytes
// full-duplex: keystrokes client->server and PTY output server->client. Inbound
// DATA bytes are written straight to stdout to preserve native scrollback.

const c = @cImport({
    @cInclude("poll.h");
    @cInclude("unistd.h");
    @cInclude("errno.h");
    @cInclude("signal.h");
    @cInclude("sys/ioctl.h");
    @cInclude("termios.h");
    @cInclude("stdlib.h");
});

var winch_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn onWinch(_: c_int) callconv(.c) void {
    winch_flag.store(true, .seq_cst);
}

fn writeAllStdout(bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = c.write(1, bytes.ptr + off, bytes.len - off);
        if (n <= 0) break;
        off += @intCast(n);
    }
}

const Client = struct {
    data_sid: i64,
    control_sid: i64,
    allocator: std.mem.Allocator,
    ctrl_buf: std.ArrayList(u8) = .empty,
    welcomed: bool = false,
    negotiated_caps: u64 = 0,
    negotiated_version: u16 = 0,
    session_id: [16]u8 = [_]u8{0} ** 16,
    predictor: ?*predict.Predictor = null,

    fn handleControl(self: *Client, bytes: []const u8) void {
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
            switch (frame) {
                .welcome => |w| {
                    self.welcomed = true;
                    self.negotiated_caps = w.capabilities;
                    self.negotiated_version = w.version;
                    self.session_id = w.session_id;
                },
                else => {},
            }
            std.mem.copyForwards(u8, self.ctrl_buf.items[0 .. items.len - total], self.ctrl_buf.items[total..items.len]);
            self.ctrl_buf.shrinkRetainingCapacity(items.len - total);
        }
    }
};

fn onRecv(ctx: ?*anyopaque, stream_id: i64, bytes: []const u8) void {
    const self: *Client = @ptrCast(@alignCast(ctx));
    if (stream_id == self.control_sid) {
        self.handleControl(bytes);
        return;
    }
    if (stream_id == self.data_sid) {
        if (self.predictor) |p| {
            writeAllStdout(p.onAuthoritative(bytes));
        } else {
            writeAllStdout(bytes);
        }
    }
}

// Parse `[user@]host[:port]` (IPv4/hostname). The user part is accepted but
// currently unused (auth is underlay_trust for v1).
fn parseTarget(spec_in: []const u8, host: *[]const u8, port: *u16) !void {
    var spec = spec_in;
    if (std.mem.indexOfScalar(u8, spec, '@')) |at| spec = spec[at + 1 ..];
    if (std.mem.lastIndexOfScalar(u8, spec, ':')) |idx| {
        host.* = spec[0..idx];
        port.* = try std.fmt.parseInt(u16, spec[idx + 1 ..], 10);
    } else {
        host.* = spec;
    }
}

fn sendHello(conn: *quic.Conn, control_sid: i64, gpa: std.mem.Allocator, token: ?bootstrap.Token) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try frames.encode(&buf, gpa, .{ .hello = .{
        .version = ver.current.toInt(),
        .capabilities = ver.Capabilities.MIGRATE | ver.Capabilities.RESUME,
        .auth_method = if (token != null) .bootstrap_token else .underlay_trust,
        .resume_session = null,
        .auth_token = if (token) |*t| t[0..] else null,
    } });
    try conn.write(control_sid, buf.items);
}

// Spawn `ssh <ssh_target> <server_cmd>` with the child's stdout piped back, read
// the single MSH-BOOTSTRAP line, and parse it. ssh's stderr/tty are inherited so
// host-key and password prompts reach the user.
fn runSshBootstrap(gpa: std.mem.Allocator, ssh_target: []const u8, server_cmd: []const u8) !bootstrap.BootstrapLine {
    var fds: [2]c_int = undefined;
    if (c.pipe(&fds) != 0) return error.PipeFailed;

    const target_z = try gpa.dupeZ(u8, ssh_target);
    defer gpa.free(target_z);
    const cmd_z = try gpa.dupeZ(u8, server_cmd);
    defer gpa.free(cmd_z);
    const ssh_z = try gpa.dupeZ(u8, "ssh");
    defer gpa.free(ssh_z);

    var argv = [_:null]?[*:0]u8{ ssh_z.ptr, target_z.ptr, cmd_z.ptr, null };

    const pid = c.fork();
    if (pid < 0) return error.ForkFailed;
    if (pid == 0) {
        _ = c.close(fds[0]);
        _ = c.dup2(fds[1], 1);
        if (fds[1] != 1) _ = c.close(fds[1]);
        _ = c.execvp(ssh_z.ptr, @ptrCast(&argv));
        c._exit(127);
    }
    _ = c.close(fds[1]);
    defer _ = c.close(fds[0]);

    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(gpa);
    var buf: [512]u8 = undefined;
    while (true) {
        const n = c.read(fds[0], &buf, buf.len);
        if (n <= 0) break;
        try line.appendSlice(gpa, buf[0..@intCast(n)]);
        if (std.mem.indexOfScalar(u8, line.items, '\n') != null) break;
    }
    const nl = std.mem.indexOfScalar(u8, line.items, '\n') orelse return error.NoBootstrapLine;
    return bootstrap.parseLine(line.items[0..nl]);
}

fn querySize() frames.Resize {
    var ws: c.struct_winsize = std.mem.zeroes(c.struct_winsize);
    if (c.ioctl(0, c.TIOCGWINSZ, &ws) != 0 or ws.ws_col == 0) {
        return .{ .cols = 80, .rows = 24, .xpix = 0, .ypix = 0 };
    }
    return .{ .cols = ws.ws_col, .rows = ws.ws_row, .xpix = ws.ws_xpixel, .ypix = ws.ws_ypixel };
}

fn sendResize(conn: *quic.Conn, control_sid: i64, gpa: std.mem.Allocator) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try frames.encode(&buf, gpa, .{ .resize = querySize() });
    try conn.write(control_sid, buf.items);
}

fn friendlyError(err: anyerror) noreturn {
    switch (err) {
        error.MissingHost => cli.writeStderr("msh: no host given. Try 'msh --help'.\n"),
        error.MissingArg => cli.writeStderr("msh: missing value for a flag. Try 'msh --help'.\n"),
        error.CertPinMismatch => cli.writeStderr("msh: server identity mismatch — refusing to connect.\n"),
        error.NoPeerCert => cli.writeStderr("msh: server presented no certificate — refusing to connect.\n"),
        error.NoBootstrapLine, error.BadBootstrapLine => cli.writeStderr("msh: malformed bootstrap line.\n"),
        error.InvalidCharacter, error.Overflow => cli.writeStderr("msh: bad host or port. Try 'msh --help'.\n"),
        error.PipeFailed, error.ForkFailed => cli.writeStderr("msh: could not start ssh bootstrap.\n"),
        else => cli.writeStderr("msh: could not connect (network unreachable or server down).\n"),
    }
    const code: u8 = switch (err) {
        error.MissingHost, error.MissingArg, error.NoBootstrapLine, error.BadBootstrapLine, error.InvalidCharacter, error.Overflow => 1,
        else => 2,
    };
    std.process.exit(code);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var argc: usize = 0;
    var verbose = cli.Verbose{};
    {
        var scan = init.args.iterate();
        _ = scan.next();
        while (scan.next()) |arg| {
            argc += 1;
            if (cli.isHelp(arg)) {
                cli.writeStdout(usage_text);
                return;
            }
            if (cli.isVersion(arg)) {
                cli.printVersion("msh");
                return;
            }
            if (cli.isVerbose(arg)) verbose.on = true;
        }
    }
    if (argc == 0) {
        cli.writeStderr(usage_text);
        std.process.exit(1);
    }

    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    run(init, gpa, verbose) catch |err| friendlyError(err);
}

fn run(init: std.process.Init.Minimal, gpa: std.mem.Allocator, verbose: cli.Verbose) !void {
    // CLI:
    //   msh --connect host[:port]            underlay-trust (no token)
    //   msh --ssh [user@]host [--server-cmd] bootstrap over ssh (mutual trust)
    //   msh --bootstrap-line "<line>" host   feed a bootstrap line directly (dev)
    //   (default port 4433). --server-name overrides the TLS SNI name.
    var host: []const u8 = "";
    var connect_port: u16 = default_port;
    var server_name: []const u8 = "";
    var ssh_target: []const u8 = "";
    var server_cmd: []const u8 = "mshd --bootstrap";
    var boot_line_arg: []const u8 = "";

    var it = init.args.iterate();
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--connect")) {
            const spec = it.next() orelse return error.MissingArg;
            try parseTarget(spec, &host, &connect_port);
        } else if (std.mem.eql(u8, arg, "--ssh")) {
            ssh_target = it.next() orelse return error.MissingArg;
        } else if (std.mem.eql(u8, arg, "--server-cmd")) {
            server_cmd = it.next() orelse return error.MissingArg;
        } else if (std.mem.eql(u8, arg, "--bootstrap-line")) {
            boot_line_arg = it.next() orelse return error.MissingArg;
        } else if (std.mem.eql(u8, arg, "--server-name")) {
            server_name = it.next() orelse return error.MissingArg;
        } else if (arg.len > 0 and arg[0] != '-') {
            if (ssh_target.len == 0 and boot_line_arg.len == 0) {
                try parseTarget(arg, &host, &connect_port);
            } else {
                host = arg;
            }
        }
    }

    var pinned_fp: ?bootstrap.Fingerprint = null;
    var auth_token: ?bootstrap.Token = null;

    if (ssh_target.len > 0) {
        const bl = try runSshBootstrap(gpa, ssh_target, server_cmd);
        var t: []const u8 = ssh_target;
        if (std.mem.indexOfScalar(u8, t, '@')) |at| t = t[at + 1 ..];
        host = t;
        connect_port = bl.port;
        pinned_fp = bl.fingerprint;
        auth_token = bl.token;
    } else if (boot_line_arg.len > 0) {
        const bl = try bootstrap.parseLine(boot_line_arg);
        if (host.len == 0) return error.MissingHost;
        connect_port = bl.port;
        pinned_fp = bl.fingerprint;
        auth_token = bl.token;
    }

    if (host.len == 0) return error.MissingHost;
    if (server_name.len == 0) server_name = host;

    verbose.log("resolving {s}:{d} (sni={s})", .{ host, connect_port, server_name });

    const conn = try quic.Client.connect(gpa, host, connect_port, server_name);
    defer conn.deinit();

    while (!conn.handshakeCompleted()) {
        try conn.poll(50);
        if (conn.peerClosed()) return;
    }
    verbose.log("handshake complete", .{});

    // Cert pinning: the fingerprint arrived over the ssh-authenticated channel,
    // so the presented TLS cert must match it exactly or we abort.
    if (pinned_fp) |want| {
        var got: bootstrap.Fingerprint = undefined;
        if (!conn.peerFingerprint(&got)) return error.NoPeerCert;
        verbose.hex12("peer cert fingerprint", got[0..]);
        if (!bootstrap.constantTimeEql(&want, &got)) return error.CertPinMismatch;
    } else {
        var got: bootstrap.Fingerprint = undefined;
        if (conn.peerFingerprint(&got)) verbose.hex12("peer cert fingerprint", got[0..]);
    }

    const control_sid = try conn.openStream();
    const data_sid = try conn.openStream();
    verbose.log("streams opened: control={d} data={d}", .{ control_sid, data_sid });

    var client = Client{ .data_sid = data_sid, .control_sid = control_sid, .allocator = gpa };
    defer client.ctrl_buf.deinit(gpa);
    conn.setRecvHandler(&client, onRecv);

    try sendHello(conn, control_sid, gpa, auth_token);
    var hi: usize = 0;
    while (!client.welcomed and hi < 200) : (hi += 1) {
        try conn.poll(10);
        if (conn.peerClosed()) return;
    }
    if (client.welcomed) verbose.log("welcomed: version=0x{x:0>4} caps=0x{x}", .{ client.negotiated_version, client.negotiated_caps });

    try sendResize(conn, control_sid, gpa);
    try conn.write(data_sid, &[_]u8{session.data_open_marker});
    try conn.step();

    const saved = try term_raw.enableRaw(0);
    defer if (saved) |s| term_raw.restore(0, s);

    // Predictive local echo is only meaningful on an interactive tty (raw mode
    // disables kernel echo, so our prediction becomes the sole local echo and we
    // suppress the server's confirming echo). Skip it for piped/non-tty stdin.
    var predictor = predict.Predictor.init(gpa);
    defer predictor.deinit();
    if (saved != null) {
        const sz = querySize();
        predictor.setSize(sz.cols, sz.rows);
        client.predictor = &predictor;
    }

    var sa: c.struct_sigaction = std.mem.zeroes(c.struct_sigaction);
    sa.__sigaction_u.__sa_handler = onWinch;
    _ = c.sigaction(c.SIGWINCH, &sa, null);

    var pfds = [_]c.struct_pollfd{
        .{ .fd = conn.socketFd(), .events = c.POLLIN, .revents = 0 },
        .{ .fd = 0, .events = c.POLLIN, .revents = 0 },
    };

    var roamer = quic.Roamer{};
    var migrate_warned = false;

    var buf: [16384]u8 = undefined;
    var stdin_open = true;
    while (true) {
        // Detect a network path change (~once/sec, gated internally on the
        // monotonic clock) and transparently migrate. The socket fd changes on
        // a successful migration, so refresh the pollfd entry. A migration
        // failure is non-fatal: warn once and keep the existing socket.
        if (roamer.tick(conn)) |migrated| {
            if (migrated) {
                pfds[0].fd = conn.socketFd();
                verbose.log("path change: migrated connection", .{});
            }
        } else |_| {
            if (!migrate_warned) {
                const w = "msh: auto-migration failed, continuing on current path\n";
                _ = c.write(2, w.ptr, w.len);
                migrate_warned = true;
            }
        }

        pfds[0].revents = 0;
        pfds[1].revents = 0;
        _ = c.poll(&pfds, if (stdin_open) 2 else 1, 10);

        if (pfds[0].revents & (c.POLLIN | c.POLLHUP | c.POLLERR) != 0) {
            conn.step() catch break;
        }
        if (conn.peerClosed()) break;
        if (stdin_open and pfds[1].revents & (c.POLLIN | c.POLLHUP | c.POLLERR) != 0) {
            const n = c.read(0, &buf, buf.len);
            if (n <= 0) {
                stdin_open = false;
            } else {
                const ks = buf[0..@intCast(n)];
                if (client.predictor) |p| writeAllStdout(p.onInput(ks));
                conn.write(data_sid, ks) catch break;
            }
        }

        if (winch_flag.swap(false, .seq_cst)) {
            if (client.predictor) |p| {
                const sz = querySize();
                p.setSize(sz.cols, sz.rows);
            }
            sendResize(conn, control_sid, gpa) catch {};
        }

        conn.step() catch break;
        if (conn.peerClosed()) break;
    }
}
