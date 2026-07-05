const std = @import("std");
const quic = @import("transport/quic.zig");
const frames = @import("proto/frames.zig");
const term_raw = @import("util/term_raw.zig");
const session = @import("session.zig");
const ver = @import("proto/version.zig");
const predict = @import("term/predict.zig");
const bootstrap = @import("auth/bootstrap.zig");
const sshkeys = @import("auth/sshkeys.zig");
const tofu = @import("auth/tofu.zig");
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
    \\  --identity <path>         ssh ed25519 private key for pubkey auth
    \\  --server-name <sni>       override the TLS SNI name (default: host)
    \\  --bootstrap-line "<line>" feed a bootstrap line directly (dev/testing)
    \\  -v, --verbose             print diagnostics to stderr
    \\  --sim-rtt <ms>            simulate WAN round-trip latency (dev/testing)
    \\  --sim-loss <pct>          simulate packet loss percentage (dev/testing)
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
    @cInclude("fcntl.h");
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
    // Total bytes received on the DATA stream, counted BEFORE predictor
    // filtering so it matches the server's out_seq. Used as last_consumed when
    // resuming after a reconnect. Persists across reconnects.
    recv_seq: u64 = 0,
    // Set when the server sends a Shutdown frame (the shell exited): tells the
    // reconnect logic this was a clean end, not a network drop.
    server_shutdown: bool = false,

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
                .shutdown => self.server_shutdown = true,
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
        self.recv_seq += bytes.len;
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

fn sendHello(conn: *quic.Conn, control_sid: i64, gpa: std.mem.Allocator, token: ?bootstrap.Token, resume_session: ?frames.OptSession, proof: ?frames.AuthProof) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    const method: frames.AuthMethod = if (token != null) .bootstrap_token else if (proof != null) .ssh_pubkey else .underlay_trust;
    try frames.encode(&buf, gpa, .{ .hello = .{
        .version = ver.current.toInt(),
        .capabilities = ver.Capabilities.MIGRATE | ver.Capabilities.RESUME,
        .auth_method = method,
        .resume_session = resume_session,
        .auth_token = if (token) |*t| t[0..] else null,
        .auth_proof = proof,
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

// Open a fresh QUIC connection, run the handshake, verify any pinned cert,
// open the control+data streams, send Hello (optionally resuming), await
// Welcome, send the size, and prime the data stream. Used for the initial
// connect and for each auto-reconnect. Updates `client`'s stream ids in place.
fn establishSession(
    gpa: std.mem.Allocator,
    host: []const u8,
    port: u16,
    server_name: []const u8,
    pinned_fp: ?bootstrap.Fingerprint,
    token: ?bootstrap.Token,
    identity: ?sshkeys.SecretKeyBytes,
    tofu_path: ?[]const u8,
    tofu_host: []const u8,
    resume_session: ?frames.OptSession,
    client: *Client,
    verbose: cli.Verbose,
    sim_rtt: u32,
    sim_loss: f32,
) !*quic.Conn {
    const conn = try quic.Client.connect(gpa, host, port, server_name);
    errdefer conn.deinit();
    if (sim_rtt != 0 or sim_loss != 0) conn.setSim(sim_rtt, sim_loss);

    while (!conn.handshakeCompleted()) {
        try conn.poll(50);
        if (conn.peerClosed()) return error.ConnectFailed;
    }

    var peer_fp: bootstrap.Fingerprint = undefined;
    const have_peer_fp = conn.peerFingerprint(&peer_fp);

    if (pinned_fp) |want| {
        if (!have_peer_fp) return error.NoPeerCert;
        if (!bootstrap.constantTimeEql(&want, &peer_fp)) return error.CertPinMismatch;
    } else if (tofu_path) |kh_path| {
        // TOFU pinning: only when no bootstrap fingerprint already pins the cert
        // (that path is stronger). Refuse loudly on a changed identity.
        if (!have_peer_fp) return error.NoPeerCert;
        switch (tofu.check(gpa, kh_path, tofu_host, peer_fp) catch return error.TofuIoFailed) {
            .match => {},
            .new => {
                var hex: [64]u8 = undefined;
                tofu.hexEncode(peer_fp, &hex);
                var mbuf: [160]u8 = undefined;
                const m = std.fmt.bufPrint(&mbuf, "msh: new host {s}, pinned key SHA256:{s}\n", .{ tofu_host, hex[0..16] }) catch "msh: new host pinned\n";
                _ = c.write(2, m.ptr, m.len);
            },
            .mismatch => return error.TofuMismatch,
        }
    }

    // ssh-pubkey channel binding: sign the server's cert fingerprint (this
    // exact TLS session) with the identity key so the proof can't be replayed.
    var proof: ?frames.AuthProof = null;
    if (identity) |secret| {
        if (!have_peer_fp) return error.NoPeerCert;
        const sig = sshkeys.signChallenge(secret, peer_fp) catch return error.BadIdentity;
        proof = .{ .pubkey = sshkeys.publicFromSecret(secret), .sig = sig };
    }

    const control_sid = try conn.openStream();
    const data_sid = try conn.openStream();
    client.control_sid = control_sid;
    client.data_sid = data_sid;
    client.welcomed = false;
    conn.setRecvHandler(client, onRecv);

    try sendHello(conn, control_sid, gpa, token, resume_session, proof);
    var hi: usize = 0;
    while (!client.welcomed and hi < 300) : (hi += 1) {
        try conn.poll(10);
        if (conn.peerClosed()) return error.ConnectFailed;
    }
    if (!client.welcomed) return error.ConnectFailed;
    verbose.log("welcomed: version=0x{x:0>4} caps=0x{x}", .{ client.negotiated_version, client.negotiated_caps });

    try sendResize(conn, control_sid, gpa);
    try conn.write(data_sid, &[_]u8{session.data_open_marker});
    try conn.step();
    return conn;
}

fn homeDir() ?[]const u8 {
    const h = c.getenv("HOME") orelse return null;
    return std.mem.span(h);
}

// Build "$HOME/.ssh/id_ed25519"; returns null if HOME is unset or the file is
// absent. Caller owns the returned allocation.
fn defaultIdentityPath(gpa: std.mem.Allocator) ?[:0]u8 {
    const home = homeDir() orelse return null;
    const p = std.fmt.allocPrintSentinel(gpa, "{s}/.ssh/id_ed25519", .{home}, 0) catch return null;
    if (c.access(p.ptr, c.F_OK) != 0) {
        gpa.free(p);
        return null;
    }
    return p;
}

// Build "$HOME/.config/moonshine/known_hosts". Returns null (and no pinning) if
// HOME is unset. On success sets `owned` to the allocation for later free.
fn knownHostsPath(gpa: std.mem.Allocator, owned: *[]u8) ?[]const u8 {
    const home = homeDir() orelse return null;
    const p = std.fmt.allocPrint(gpa, "{s}/.config/moonshine/known_hosts", .{home}) catch return null;
    owned.* = p;
    return p;
}

fn friendlyError(err: anyerror) noreturn {
    switch (err) {
        error.MissingHost => cli.writeStderr("msh: no host given. Try 'msh --help'.\n"),
        error.MissingArg => cli.writeStderr("msh: missing value for a flag. Try 'msh --help'.\n"),
        error.CertPinMismatch => cli.writeStderr("msh: server identity mismatch — refusing to connect.\n"),
        error.TofuMismatch => cli.writeStderr(
            \\@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
            \\@    WARNING: REMOTE HOST IDENTITY HAS CHANGED!         @
            \\@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
            \\msh: the server's certificate does not match the pinned key
            \\in known_hosts. Someone could be eavesdropping (MITM), or the
            \\server key changed. Refusing to connect.
            \\
        ),
        error.EncryptedIdentity => cli.writeStderr("msh: identity key is encrypted — use an unencrypted key or --ssh bootstrap.\n"),
        error.BadIdentity => cli.writeStderr("msh: could not load the identity key.\n"),
        error.TofuIoFailed => cli.writeStderr("msh: could not read/write known_hosts.\n"),
        error.NoPeerCert => cli.writeStderr("msh: server presented no certificate — refusing to connect.\n"),
        error.NoBootstrapLine, error.BadBootstrapLine => cli.writeStderr("msh: malformed bootstrap line.\n"),
        error.InvalidCharacter, error.Overflow => cli.writeStderr("msh: bad host or port. Try 'msh --help'.\n"),
        error.PipeFailed, error.ForkFailed => cli.writeStderr("msh: could not start ssh bootstrap.\n"),
        else => cli.writeStderr("msh: could not connect (network unreachable or server down).\n"),
    }
    const code: u8 = switch (err) {
        error.MissingHost, error.MissingArg, error.NoBootstrapLine, error.BadBootstrapLine, error.InvalidCharacter, error.Overflow, error.EncryptedIdentity, error.BadIdentity => 1,
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
    var identity_path: []const u8 = "";
    var sim_rtt: u32 = 0;
    var sim_loss: f32 = 0;

    var it = init.args.iterate();
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--connect")) {
            const spec = it.next() orelse return error.MissingArg;
            try parseTarget(spec, &host, &connect_port);
        } else if (std.mem.eql(u8, arg, "--sim-rtt")) {
            sim_rtt = try std.fmt.parseInt(u32, it.next() orelse return error.MissingArg, 10);
        } else if (std.mem.eql(u8, arg, "--sim-loss")) {
            sim_loss = try std.fmt.parseFloat(f32, it.next() orelse return error.MissingArg);
        } else if (std.mem.eql(u8, arg, "--ssh")) {
            ssh_target = it.next() orelse return error.MissingArg;
        } else if (std.mem.eql(u8, arg, "--server-cmd")) {
            server_cmd = it.next() orelse return error.MissingArg;
        } else if (std.mem.eql(u8, arg, "--bootstrap-line")) {
            boot_line_arg = it.next() orelse return error.MissingArg;
        } else if (std.mem.eql(u8, arg, "--server-name")) {
            server_name = it.next() orelse return error.MissingArg;
        } else if (std.mem.eql(u8, arg, "--identity")) {
            identity_path = it.next() orelse return error.MissingArg;
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

    // ssh-pubkey identity: an explicit --identity path, else default to
    // ~/.ssh/id_ed25519 if it exists. Only used for plain --connect (no token /
    // no bootstrap pin). Loaded once and reused across reconnects.
    var identity: ?sshkeys.SecretKeyBytes = null;
    var identity_buf: ?[:0]u8 = null;
    if (pinned_fp == null and auth_token == null) {
        if (identity_path.len > 0) {
            identity = sshkeys.loadPrivateKey(gpa, identity_path) catch |e| switch (e) {
                sshkeys.Error.EncryptedKey => return error.EncryptedIdentity,
                else => return error.BadIdentity,
            };
        } else if (defaultIdentityPath(gpa)) |dp| {
            identity_buf = dp;
            identity = sshkeys.loadPrivateKey(gpa, dp) catch null;
        }
    }
    defer if (identity_buf) |b| gpa.free(b);

    // TOFU known_hosts pinning for plain --connect (no stronger bootstrap pin).
    var kh_buf: []u8 = &.{};
    const tofu_path: ?[]const u8 = if (pinned_fp == null) knownHostsPath(gpa, &kh_buf) else null;
    defer if (kh_buf.len > 0) gpa.free(kh_buf);

    verbose.log("resolving {s}:{d} (sni={s})", .{ host, connect_port, server_name });

    // Auto-reconnect (session resume) targets plain --connect (underlay-trust)
    // sessions. --ssh / --bootstrap-line sessions carry a one-time token that
    // can't be silently re-minted, so those never attempt resume — they exit
    // cleanly on disconnect instead.
    const reconnect_ok = pinned_fp == null and auth_token == null;

    var client = Client{ .data_sid = 0, .control_sid = 0, .allocator = gpa };
    defer client.ctrl_buf.deinit(gpa);

    var conn = try establishSession(gpa, host, connect_port, server_name, pinned_fp, auth_token, identity, tofu_path, host, null, &client, verbose, sim_rtt, sim_loss);
    defer conn.deinit();
    verbose.log("handshake complete", .{});

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
    outer: while (true) {
        inner: while (true) {
            // Detect a network path change (~once/sec, gated internally on the
            // monotonic clock) and transparently migrate. The socket fd changes
            // on a successful migration, so refresh the pollfd entry. A
            // migration failure is non-fatal: warn once and keep the socket.
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
                conn.step() catch break :inner;
            }
            if (conn.peerClosed()) break :inner;
            if (stdin_open and pfds[1].revents & (c.POLLIN | c.POLLHUP | c.POLLERR) != 0) {
                const n = c.read(0, &buf, buf.len);
                if (n <= 0) {
                    stdin_open = false;
                } else {
                    const ks = buf[0..@intCast(n)];
                    if (client.predictor) |p| writeAllStdout(p.onInput(ks));
                    conn.write(client.data_sid, ks) catch break :inner;
                }
            }

            if (winch_flag.swap(false, .seq_cst)) {
                if (client.predictor) |p| {
                    const sz = querySize();
                    p.setSize(sz.cols, sz.rows);
                }
                sendResize(conn, client.control_sid, gpa) catch {};
            }

            conn.step() catch break :inner;
            if (conn.peerClosed()) break :inner;
        }

        // The connection dropped. If the server told us the shell exited, or we
        // initiated the exit (stdin EOF), or this isn't a resumable session,
        // leave. Otherwise auto-reconnect to the same host and resume.
        if (client.server_shutdown or !stdin_open or !reconnect_ok) break :outer;

        verbose.log("connection lost — reconnecting to resume session", .{});
        const newc = tryReconnect(gpa, host, connect_port, server_name, identity, tofu_path, &client, verbose, sim_rtt, sim_loss) orelse {
            const w = "msh: lost connection and could not resume the session — giving up.\n";
            _ = c.write(2, w.ptr, w.len);
            break :outer;
        };
        conn.deinit();
        conn = newc;
        pfds[0].fd = conn.socketFd();
        roamer = quic.Roamer{};
    }

    // If we're leaving first (user quit / stdin EOF), let the server know so it
    // tears down the shell promptly instead of idling.
    conn.closeGraceful();
}

// Bounded reconnect with backoff. Opens a brand-new QUIC connection to the same
// host and resumes the session (Hello.resume_session = {session_id, recv_seq}).
// Returns the new connection, or null after exhausting attempts. The terminal
// stays in raw mode throughout so the resume is seamless.
fn tryReconnect(
    gpa: std.mem.Allocator,
    host: []const u8,
    port: u16,
    server_name: []const u8,
    identity: ?sshkeys.SecretKeyBytes,
    tofu_path: ?[]const u8,
    client: *Client,
    verbose: cli.Verbose,
    sim_rtt: u32,
    sim_loss: f32,
) ?*quic.Conn {
    var attempt: usize = 0;
    while (attempt < 10) : (attempt += 1) {
        _ = c.usleep(500 * 1000);
        const resume_session = frames.OptSession{
            .session_id = client.session_id,
            .last_consumed = client.recv_seq,
        };
        const newc = establishSession(gpa, host, port, server_name, null, null, identity, tofu_path, host, resume_session, client, verbose, sim_rtt, sim_loss) catch continue;
        return newc;
    }
    return null;
}
