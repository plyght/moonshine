const std = @import("std");
const quic = @import("transport/quic.zig");
const Pty = @import("pty/pty.zig").Pty;
const session_mod = @import("session.zig");
const ServerSession = session_mod.ServerSession;
const Session = session_mod.Session;
const bootstrap = @import("auth/bootstrap.zig");
const sshkeys = @import("auth/sshkeys.zig");
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
    \\  --require-key [path]      require ssh-pubkey auth against an authorized_keys
    \\                            file (default ~/.ssh/authorized_keys)
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
    @cInclude("sys/stat.h");
    @cInclude("stdlib.h");
});

fn monotonicNs() u64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(u64, @intCast(ts.tv_sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.tv_nsec));
}

const default_cert = "src/transport/testdata/cert.pem";
const default_key = "src/transport/testdata/key.pem";

const DaemonPaths = struct { cert: [:0]u8, key: [:0]u8 };

// Ensure a persistent self-signed daemon identity under ~/.config/moonshine.
// Generates the cert/key on first run (dir created 0700) and reuses them after.
// Returns null (fall back to the testdata cert) if HOME is unset.
fn ensureDaemonCert(gpa: std.mem.Allocator) !?DaemonPaths {
    const home = c.getenv("HOME") orelse return null;
    const home_s = std.mem.span(home);
    const dir = try std.fmt.allocPrintSentinel(gpa, "{s}/.config/moonshine", .{home_s}, 0);
    defer gpa.free(dir);
    {
        const cfg = try std.fmt.allocPrintSentinel(gpa, "{s}/.config", .{home_s}, 0);
        defer gpa.free(cfg);
        _ = c.mkdir(cfg.ptr, 0o700);
    }
    _ = c.mkdir(dir.ptr, 0o700);

    const cert = try std.fmt.allocPrintSentinel(gpa, "{s}/daemon_cert.pem", .{dir}, 0);
    errdefer gpa.free(cert);
    const key = try std.fmt.allocPrintSentinel(gpa, "{s}/daemon_key.pem", .{dir}, 0);
    errdefer gpa.free(key);

    if (c.access(cert.ptr, c.F_OK) != 0 or c.access(key.ptr, c.F_OK) != 0) {
        _ = try bootstrap.generatePersistent(cert, key);
    }
    return .{ .cert = cert, .key = key };
}

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
    var cert_explicit = false;
    var require_key = false;
    var authkeys_path: []const u8 = "";

    var args_list = std.ArrayList([]const u8).empty;
    defer args_list.deinit(gpa);
    {
        var it = init.args.iterate();
        _ = it.next();
        while (it.next()) |arg| try args_list.append(gpa, arg);
    }
    const args = args_list.items;
    var ai: usize = 0;
    while (ai < args.len) : (ai += 1) {
        const arg = args[ai];
        if (std.mem.eql(u8, arg, "--listen")) {
            ai += 1;
            if (ai >= args.len) return error.MissingArg;
            const spec = args[ai];
            if (std.mem.lastIndexOfScalar(u8, spec, ':')) |idx| {
                bind_addr = spec[0..idx];
                listen_port = try std.fmt.parseInt(u16, spec[idx + 1 ..], 10);
            } else {
                listen_port = try std.fmt.parseInt(u16, spec, 10);
            }
        } else if (std.mem.eql(u8, arg, "--bootstrap")) {
            boot_mode = true;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            ai += 1;
            if (ai >= args.len) return error.MissingArg;
            cert_path = args[ai];
            cert_explicit = true;
        } else if (std.mem.eql(u8, arg, "--key")) {
            ai += 1;
            if (ai >= args.len) return error.MissingArg;
            key_path = args[ai];
        } else if (std.mem.eql(u8, arg, "--require-key")) {
            require_key = true;
            // Optional inline path; a leading '-' means it's the next flag.
            if (ai + 1 < args.len and args[ai + 1].len > 0 and args[ai + 1][0] != '-') {
                ai += 1;
                authkeys_path = args[ai];
            }
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

    // Standalone daemon identity: unless --cert/--key were given (or bootstrap
    // mode), use a persistent self-signed cert under ~/.config/moonshine so the
    // fingerprint is stable across restarts (TOFU-pinnable by clients).
    var persist_cert: ?[:0]u8 = null;
    var persist_key: ?[:0]u8 = null;
    defer if (persist_cert) |p| gpa.free(p);
    defer if (persist_key) |p| gpa.free(p);
    if (!boot_mode and !cert_explicit) {
        if (try ensureDaemonCert(gpa)) |paths| {
            persist_cert = paths.cert;
            persist_key = paths.key;
            cert_path = paths.cert;
            key_path = paths.key;
        }
    }

    // require-key: load the authorized_keys file and the server's own cert
    // fingerprint (the channel-binding value clients must sign).
    var authorized_keys: ?std.ArrayList(sshkeys.PublicKey) = null;
    var akpath_buf: ?[:0]u8 = null;
    defer if (akpath_buf) |p| gpa.free(p);
    defer if (authorized_keys) |*k| k.deinit(gpa);
    var own_fp: ?bootstrap.Fingerprint = null;
    if (require_key) {
        var path: []const u8 = authkeys_path;
        if (path.len == 0) {
            const home = c.getenv("HOME") orelse return error.NoHome;
            akpath_buf = try std.fmt.allocPrintSentinel(gpa, "{s}/.ssh/authorized_keys", .{std.mem.span(home)}, 0);
            path = akpath_buf.?;
        }
        var keys = std.ArrayList(sshkeys.PublicKey).empty;
        try sshkeys.loadAuthorizedKeys(gpa, path, &keys);
        authorized_keys = keys;
        const cert_z = try gpa.dupeZ(u8, cert_path);
        defer gpa.free(cert_z);
        own_fp = try bootstrap.fingerprintFromPemFile(cert_z);
    }

    var env_list = std.ArrayList([]const u8).empty;
    defer env_list.deinit(gpa);
    for (init.environ.block.slice) |e| {
        if (e) |ptr| try env_list.append(gpa, std.mem.span(ptr));
    }
    try env_list.append(gpa, "TERM=xterm-256color");

    if (boot_mode) {
        try serveBootstrap(gpa, bind_addr, listen_port, cert_path, key_path, eph.?, required_token.?, env_list.items);
    } else {
        const ak: ?[]const sshkeys.PublicKey = if (authorized_keys) |k| k.items else null;
        try serveListen(gpa, bind_addr, listen_port, cert_path, key_path, ak, own_fp, env_list.items);
    }
}

// Bootstrap: mint a one-time token + ephemeral cert, serve exactly one
// (non-resumable) session, then exit. Preserves the pre-resume behavior.
fn serveBootstrap(
    gpa: std.mem.Allocator,
    bind_addr: []const u8,
    listen_port: u16,
    cert_path: []const u8,
    key_path: []const u8,
    eph: bootstrap.Ephemeral,
    required_token: bootstrap.Token,
    env: []const []const u8,
) !void {
    const conn = try quic.Server.init(gpa, bind_addr, listen_port, cert_path, key_path);
    defer conn.deinit();

    var line_buf: [256]u8 = undefined;
    const line = try bootstrap.formatLine(&line_buf, conn.localPort(), eph.fingerprint, required_token);
    _ = c.write(1, line.ptr, line.len);

    const deadline_ns: u64 = monotonicNs() + 30 * std.time.ns_per_s;
    while (!conn.handshakeCompleted()) {
        try conn.poll(50);
        if (conn.peerClosed()) return;
        if (monotonicNs() > deadline_ns) return;
    }

    var pty = try Pty.open(gpa);
    defer pty.close();
    try pty.spawnShell(&.{}, env, .{ .cols = 80, .rows = 24 });

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

        if (pfds[0].revents & (c.POLLIN | c.POLLERR | c.POLLHUP) != 0) conn.step() catch break;
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

    conn.closeGraceful();
    conn.step() catch {};
}

// After a client detaches, keep the shell alive this long waiting for a
// resuming connection before tearing everything down and exiting.
const detached_ttl_ns: u64 = 5 * 60 * std.time.ns_per_s;

// Persistent listen mode: one durable shell/session per process. The UDP socket
// (Listener) outlives connections, so a lost connection can be replaced by a
// brand-new one that reattaches to the same live shell and replays missed
// output (session resume).
fn serveListen(
    gpa: std.mem.Allocator,
    bind_addr: []const u8,
    listen_port: u16,
    cert_path: []const u8,
    key_path: []const u8,
    authorized_keys: ?[]const sshkeys.PublicKey,
    own_cert_fp: ?bootstrap.Fingerprint,
    env: []const []const u8,
) !void {
    const listener = try quic.Listener.init(gpa, bind_addr, listen_port, cert_path, key_path);
    defer listener.deinit();

    {
        var stdout_buf: [128]u8 = undefined;
        const msg = try std.fmt.bufPrint(&stdout_buf, "listening {d} (underlay-trust: relies on network trust)\n", .{listener.localPort()});
        _ = c.write(1, msg.ptr, msg.len);
    }

    // The durable session (PTY + replay ring). Created lazily on first attach so
    // the initial shell prompt is produced with a client already listening.
    var pty: Pty = undefined;
    var session: Session = undefined;
    var have_session = false;
    defer if (have_session) {
        session.deinit();
        pty.close();
    };

    // Current live connection, or null while detached/awaiting the first client.
    var conn: ?*quic.Conn = null;
    var sess: ServerSession = undefined;
    var detached_since: u64 = monotonicNs();

    defer if (conn) |cn| {
        sess.deinit();
        cn.deinit();
    };

    var buf: [16384]u8 = undefined;
    while (true) {
        var pfds = [_]c.struct_pollfd{
            .{ .fd = listener.socketFd(), .events = c.POLLIN, .revents = 0 },
            .{ .fd = if (have_session) pty.master else -1, .events = c.POLLIN, .revents = 0 },
        };
        _ = c.poll(&pfds, 2, 10);

        // Drain the PTY in every state: while attached we also relay live; while
        // detached the output is captured in the ring (bounded) for replay.
        if (have_session and pfds[1].revents & (c.POLLIN | c.POLLERR | c.POLLHUP) != 0) {
            const n = pty.read(&buf) catch return;
            if (n == 0) { // shell exited: notify any client, tear down, exit
                if (conn) |cn| {
                    sess.sendShutdown(0);
                    cn.step() catch {};
                    cn.closeGraceful();
                    cn.step() catch {};
                }
                return;
            }
            session.record(buf[0..n]);
            if (conn != null) sess.relayPtyOutput(buf[0..n]);
        }

        if (conn) |cn| {
            cn.step() catch {
                detachConn(&conn, &sess, &detached_since);
                continue;
            };
            if (sess.rejected or cn.peerClosed()) {
                detachConn(&conn, &sess, &detached_since);
                continue;
            }
        } else {
            // Detached: accept the next connection on the same socket.
            if (try listener.pollAccept()) |new_conn| {
                if (!have_session) {
                    pty = try Pty.open(gpa);
                    try pty.spawnShell(&.{}, env, .{ .cols = 80, .rows = 24 });
                    session = Session.init(gpa, &pty, session_mod.default_replay_cap);
                    have_session = true;
                }
                sess.init(gpa, new_conn, &pty);
                sess.session = &session;
                sess.authorized_keys = authorized_keys;
                sess.own_cert_fp = own_cert_fp;
                conn = new_conn;
            } else if (have_session and monotonicNs() -% detached_since > detached_ttl_ns) {
                return; // no client for too long: give up the shell
            }
        }
    }
}

fn detachConn(conn: *?*quic.Conn, sess: *ServerSession, detached_since: *u64) void {
    if (conn.*) |cn| {
        cn.closeGraceful();
        cn.step() catch {};
        sess.deinit();
        cn.deinit();
    }
    conn.* = null;
    detached_since.* = monotonicNs();
}
