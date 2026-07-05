const std = @import("std");

const c = @cImport({
    @cInclude("ngtcp2/ngtcp2.h");
    @cInclude("ngtcp2/ngtcp2_crypto.h");
    @cInclude("ngtcp2/ngtcp2_crypto_ossl.h");
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/evp.h");
    @cInclude("sys/socket.h");
    @cInclude("netinet/in.h");
    @cInclude("arpa/inet.h");
    @cInclude("fcntl.h");
    @cInclude("poll.h");
    @cInclude("unistd.h");
    @cInclude("errno.h");
    @cInclude("string.h");
    @cInclude("time.h");
    @cInclude("netdb.h");
    @cInclude("openssl/rand.h");
});

fn fillRandom(dest: []u8) void {
    _ = c.RAND_bytes(dest.ptr, @intCast(dest.len));
}

pub fn randomBytes(dest: []u8) void {
    fillRandom(dest);
}

fn sleepMs(ms: u32) void {
    _ = c.usleep(ms * 1000);
}

fn monotonicNs() u64 {
    var ts: c.struct_timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &ts);
    return @as(u64, @intCast(ts.tv_sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.tv_nsec));
}

const PKT_INFO_VERSION: c_int = 1;
const SETTINGS_VERSION: c_int = 3;
const TRANSPORT_PARAMS_VERSION: c_int = 1;
const CALLBACKS_VERSION: c_int = 2;

const alpn_wire = "\x07msh/0.1";
const alpn_proto = "msh/0.1";

pub const Error = error{
    SocketFailed,
    BindFailed,
    GetSockNameFailed,
    ConnCreateFailed,
    TlsFailed,
    ReadFailed,
    WriteFailed,
    AcceptFailed,
    OutOfMemory,
    HandshakeFailed,
    ResolveFailed,
    MigrateFailed,
};

var ossl_initialized: bool = false;

const StreamSend = struct {
    buf: std.ArrayList(u8) = .empty,
    base: u64 = 0,
    sent: u64 = 0,
    total: u64 = 0,
    acked: u64 = 0,
};

// A datagram held in the WAN simulator's delay queue until its release time.
const DelayedPkt = struct {
    data: [2048]u8,
    len: usize,
    addr: c.struct_sockaddr_in,
    alen: c.socklen_t,
    release: u64,
};

pub const Conn = struct {
    allocator: std.mem.Allocator,
    fd: c_int = -1,
    conn: ?*c.ngtcp2_conn = null,
    ssl: ?*c.SSL = null,
    ssl_ctx: ?*c.SSL_CTX = null,
    ossl: ?*c.ngtcp2_crypto_ossl_ctx = null,
    is_server: bool,
    handshake_done: bool = false,
    conn_ref: c.ngtcp2_crypto_conn_ref = .{ .get_conn = getConnCb, .user_data = null },
    local_sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in),
    local_len: c.socklen_t = @sizeOf(c.struct_sockaddr_in),
    remote_sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in),
    remote_len: c.socklen_t = @sizeOf(c.struct_sockaddr_in),
    have_remote: bool = false,
    recv_buf: std.ArrayList(u8) = .empty,
    recv_handler: ?*const fn (ctx: ?*anyopaque, stream_id: i64, bytes: []const u8) void = null,
    recv_ctx: ?*anyopaque = null,
    peer_closed: bool = false,
    _base: u64 = 0,
    sends: std.AutoHashMap(i64, StreamSend) = undefined,
    sends_init: bool = false,
    // WAN simulator (dev/testing): when sim_delay_ns > 0, outgoing and incoming
    // datagrams are held in delay queues to emulate propagation latency, and are
    // dropped with probability sim_loss_permille/1000. Zero = disabled (fast path).
    sim_delay_ns: u64 = 0,
    sim_loss_permille: u32 = 0,
    tx_q: std.ArrayList(DelayedPkt) = .empty,
    rx_q: std.ArrayList(DelayedPkt) = .empty,
    // When a Conn is minted by a Listener it shares the listener's persistent
    // UDP socket and server TLS context, so it must not free them on deinit.
    owns_fd: bool = true,
    owns_ctx: bool = true,

    fn now(self: *Conn) c.ngtcp2_tstamp {
        _ = self;
        return monotonicNs();
    }

    pub fn handshakeCompleted(self: *Conn) bool {
        return self.handshake_done;
    }

    pub fn localPort(self: *Conn) u16 {
        return std.mem.bigToNative(u16, self.local_sa.sin_port);
    }

    pub fn setRecvHandler(self: *Conn, ctx: ?*anyopaque, handler: *const fn (ctx: ?*anyopaque, stream_id: i64, bytes: []const u8) void) void {
        self.recv_ctx = ctx;
        self.recv_handler = handler;
    }

    pub fn socketFd(self: *Conn) c_int {
        return self.fd;
    }

    pub fn peerClosed(self: *Conn) bool {
        return self.peer_closed;
    }

    /// Send a QUIC CONNECTION_CLOSE so the peer learns the session ended
    /// immediately instead of waiting out the idle timeout. Best-effort.
    pub fn closeGraceful(self: *Conn) void {
        if (self.conn == null or self.peer_closed) return;
        var ccerr: c.ngtcp2_ccerr = undefined;
        c.ngtcp2_ccerr_default(&ccerr);
        var buf: [1500]u8 = undefined;
        var pi: c.ngtcp2_pkt_info = std.mem.zeroes(c.ngtcp2_pkt_info);
        var ps: c.ngtcp2_path_storage = undefined;
        c.ngtcp2_path_storage_zero(&ps);
        const n = c.ngtcp2_conn_write_connection_close_versioned(self.conn, &ps.path, PKT_INFO_VERSION, &pi, &buf, buf.len, &ccerr, self.now());
        if (n > 0) {
            // A graceful close should reach the peer even under the simulator,
            // so send it directly rather than through the delay/loss queue.
            _ = c.sendto(self.fd, &buf, @intCast(n), 0, @ptrCast(&self.remote_sa), self.remote_len);
        }
    }

    /// Fetch the peer's leaf TLS certificate and compute its SHA-256 DER
    /// fingerprint. Returns false if no peer certificate is available.
    pub fn peerFingerprint(self: *Conn, out: *[32]u8) bool {
        const ssl = self.ssl orelse return false;
        const cert = c.SSL_get1_peer_certificate(ssl) orelse return false;
        defer c.X509_free(cert);
        var len: c_uint = 0;
        if (c.X509_digest(cert, c.EVP_sha256(), out, &len) != 1) return false;
        return len == 32;
    }

    /// Enable the WAN simulator: `rtt_ms` round-trip latency (split half on each
    /// direction) and `loss_pct` per-datagram drop probability, each way.
    pub fn setSim(self: *Conn, rtt_ms: u32, loss_pct: f32) void {
        self.sim_delay_ns = @as(u64, rtt_ms) * std.time.ns_per_ms / 2;
        const permille: i64 = @intFromFloat(loss_pct * 10.0);
        self.sim_loss_permille = @intCast(std.math.clamp(permille, 0, 1000));
    }

    fn simActive(self: *Conn) bool {
        return self.sim_delay_ns != 0 or self.sim_loss_permille != 0;
    }

    fn simDrop(self: *Conn) bool {
        if (self.sim_loss_permille == 0) return false;
        var r: [2]u8 = undefined;
        fillRandom(&r);
        const v: u32 = (@as(u32, r[0]) << 8 | r[1]) % 1000;
        return v < self.sim_loss_permille;
    }

    // Send a datagram, honoring the WAN simulator when active.
    fn emit(self: *Conn, bytes: []const u8, addr: *const c.struct_sockaddr_in, alen: c.socklen_t) void {
        if (!self.simActive()) {
            _ = c.sendto(self.fd, bytes.ptr, bytes.len, 0, @ptrCast(addr), alen);
            return;
        }
        if (self.simDrop()) return;
        if (bytes.len > 2048) return;
        var pkt: DelayedPkt = .{ .data = undefined, .len = bytes.len, .addr = addr.*, .alen = alen, .release = monotonicNs() + self.sim_delay_ns };
        @memcpy(pkt.data[0..bytes.len], bytes);
        self.tx_q.append(self.allocator, pkt) catch return;
    }

    // Flush any tx datagrams whose delay has elapsed; return true if the rx queue
    // still holds undelivered packets (so the caller keeps polling promptly).
    fn serviceSim(self: *Conn) void {
        if (!self.simActive()) return;
        const t = monotonicNs();
        var i: usize = 0;
        while (i < self.tx_q.items.len) {
            const p = self.tx_q.items[i];
            if (p.release <= t) {
                _ = c.sendto(self.fd, &p.data, p.len, 0, @ptrCast(&self.tx_q.items[i].addr), p.alen);
                _ = self.tx_q.orderedRemove(i);
            } else i += 1;
        }
    }

    /// Block up to timeout_ms for a datagram, then service the connection once
    /// (read, timers, drain writes). Pass 0 to poll without blocking.
    pub fn poll(self: *Conn, timeout_ms: c_int) Error!void {
        // With the WAN simulator active, cap the wait so delayed packets are
        // released on time even when the socket is otherwise idle.
        var t = timeout_ms;
        if (self.simActive() and (t < 0 or t > 5)) t = 5;
        var pfd: c.struct_pollfd = .{ .fd = self.fd, .events = c.POLLIN, .revents = 0 };
        _ = c.poll(&pfd, 1, t);
        try self.step();
    }

    /// Client-initiated QUIC connection migration: bind a fresh UDP socket to a
    /// new ephemeral local address and ask ngtcp2 to validate and migrate the
    /// existing connection to that new path (same Connection ID, new 4-tuple).
    pub fn migrate(self: *Conn) Error!void {
        if (self.is_server) return Error.MigrateFailed;

        const new_fd = try makeUdpSocket();
        errdefer _ = c.close(new_fd);

        var new_sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
        new_sa.sin_family = c.AF_INET;
        new_sa.sin_port = 0;
        _ = c.inet_pton(c.AF_INET, "127.0.0.1", &new_sa.sin_addr);
        var new_len: c.socklen_t = @sizeOf(c.struct_sockaddr_in);
        if (c.bind(new_fd, @ptrCast(&new_sa), new_len) != 0) return Error.BindFailed;
        if (c.getsockname(new_fd, @ptrCast(&new_sa), &new_len) != 0) return Error.GetSockNameFailed;

        var path: c.ngtcp2_path = .{
            .local = .{ .addr = @ptrCast(&new_sa), .addrlen = new_len },
            .remote = .{ .addr = @ptrCast(&self.remote_sa), .addrlen = self.remote_len },
            .user_data = null,
        };
        if (c.ngtcp2_conn_initiate_migration(self.conn, &path, self.now()) != 0) {
            return Error.MigrateFailed;
        }

        if (self.fd >= 0) _ = c.close(self.fd);
        self.fd = new_fd;
        self.local_sa = new_sa;
        self.local_len = new_len;
    }

    pub fn openStream(self: *Conn) Error!i64 {
        var sid: i64 = -1;
        if (c.ngtcp2_conn_open_bidi_stream(self.conn, &sid, null) != 0) {
            return Error.WriteFailed;
        }
        return sid;
    }

    pub fn write(self: *Conn, stream_id: i64, bytes: []const u8) Error!void {
        const gop = try self.sends.getOrPut(stream_id);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        try gop.value_ptr.buf.appendSlice(self.allocator, bytes);
        gop.value_ptr.total += bytes.len;
        try self.drain();
    }

    pub fn received(self: *Conn) []const u8 {
        return self.recv_buf.items;
    }

    pub fn deinit(self: *Conn) void {
        if (self.conn) |cn| c.ngtcp2_conn_del(cn);
        if (self.ssl) |s| c.SSL_free(s);
        if (self.ossl) |o| c.ngtcp2_crypto_ossl_ctx_del(o);
        if (self.owns_ctx) {
            if (self.ssl_ctx) |x| c.SSL_CTX_free(x);
        }
        if (self.owns_fd and self.fd >= 0) _ = c.close(self.fd);
        self.recv_buf.deinit(self.allocator);
        if (self.sends_init) {
            var it = self.sends.iterator();
            while (it.next()) |entry| entry.value_ptr.buf.deinit(self.allocator);
            self.sends.deinit();
        }
        self.tx_q.deinit(self.allocator);
        self.rx_q.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    fn setupTlsClient(self: *Conn, server_name: []const u8) Error!void {
        const ctx = c.SSL_CTX_new(c.TLS_method()) orelse return Error.TlsFailed;
        self.ssl_ctx = ctx;
        _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_3_VERSION);
        _ = c.SSL_CTX_set_max_proto_version(ctx, c.TLS1_3_VERSION);

        const ssl = c.SSL_new(ctx) orelse return Error.TlsFailed;
        self.ssl = ssl;
        _ = c.SSL_set_app_data(ssl, &self.conn_ref);
        c.SSL_set_connect_state(ssl);
        if (c.SSL_set_alpn_protos(ssl, alpn_wire, alpn_wire.len) != 0) return Error.TlsFailed;

        const name_z = try self.allocator.dupeZ(u8, server_name);
        defer self.allocator.free(name_z);
        _ = c.SSL_ctrl(ssl, c.SSL_CTRL_SET_TLSEXT_HOSTNAME, c.TLSEXT_NAMETYPE_host_name, @ptrCast(name_z.ptr));

        if (c.ngtcp2_crypto_ossl_configure_client_session(ssl) != 0) return Error.TlsFailed;
        try self.wrapOssl(ssl);
    }

    fn setupTlsServer(self: *Conn, cert_path: []const u8, key_path: []const u8) Error!void {
        const ctx = c.SSL_CTX_new(c.TLS_method()) orelse return Error.TlsFailed;
        self.ssl_ctx = ctx;
        _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_3_VERSION);
        _ = c.SSL_CTX_set_max_proto_version(ctx, c.TLS1_3_VERSION);

        const cert_z = try self.allocator.dupeZ(u8, cert_path);
        defer self.allocator.free(cert_z);
        const key_z = try self.allocator.dupeZ(u8, key_path);
        defer self.allocator.free(key_z);
        if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_z.ptr) != 1) return Error.TlsFailed;
        if (c.SSL_CTX_use_PrivateKey_file(ctx, key_z.ptr, c.SSL_FILETYPE_PEM) != 1) return Error.TlsFailed;
        c.SSL_CTX_set_alpn_select_cb(ctx, alpnSelectCb, null);
    }

    fn serverSslForConn(self: *Conn) Error!void {
        const ssl = c.SSL_new(self.ssl_ctx) orelse return Error.TlsFailed;
        self.ssl = ssl;
        _ = c.SSL_set_app_data(ssl, &self.conn_ref);
        c.SSL_set_accept_state(ssl);
        if (c.ngtcp2_crypto_ossl_configure_server_session(ssl) != 0) return Error.TlsFailed;
        try self.wrapOssl(ssl);
    }

    fn wrapOssl(self: *Conn, ssl: *c.SSL) Error!void {
        var octx: ?*c.ngtcp2_crypto_ossl_ctx = null;
        if (c.ngtcp2_crypto_ossl_ctx_new(&octx, ssl) != 0) return Error.TlsFailed;
        self.ossl = octx;
        c.ngtcp2_conn_set_tls_native_handle(self.conn, octx);
    }

    pub fn step(self: *Conn) Error!void {
        self.serviceSim();
        try self.readAll();
        try self.handleTimer();
        try self.drainWrite();
        self.serviceSim();
    }

    fn readAll(self: *Conn) Error!void {
        var buf: [2048]u8 = undefined;
        while (true) {
            var src: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
            var slen: c.socklen_t = @sizeOf(c.struct_sockaddr_in);
            const n = c.recvfrom(self.fd, &buf, buf.len, 0, @ptrCast(&src), &slen);
            if (n < 0) {
                const e = errno();
                if (e == c.EWOULDBLOCK or e == c.EAGAIN) break;
                return Error.ReadFailed;
            }
            if (n == 0) break;
            const pkt = buf[0..@intCast(n)];

            if (!self.simActive()) {
                try self.processPacket(pkt, &src, slen);
            } else if (!self.simDrop() and pkt.len <= 2048) {
                var p: DelayedPkt = .{ .data = undefined, .len = pkt.len, .addr = src, .alen = slen, .release = monotonicNs() + self.sim_delay_ns };
                @memcpy(p.data[0..pkt.len], pkt);
                self.rx_q.append(self.allocator, p) catch {};
            }
        }
        try self.drainRx();
    }

    // Deliver any received datagrams whose simulated delay has elapsed.
    fn drainRx(self: *Conn) Error!void {
        if (self.rx_q.items.len == 0) return;
        const t = monotonicNs();
        var i: usize = 0;
        while (i < self.rx_q.items.len) {
            if (self.rx_q.items[i].release <= t) {
                var p = self.rx_q.orderedRemove(i);
                try self.processPacket(p.data[0..p.len], &p.addr, p.alen);
            } else i += 1;
        }
    }

    fn processPacket(self: *Conn, pkt: []const u8, src: *c.struct_sockaddr_in, slen: c.socklen_t) Error!void {
        if (self.is_server and self.conn == null) {
            self.serverAccept(pkt, src, slen) catch return Error.AcceptFailed;
        } else if (self.is_server) {
            self.remote_sa = src.*;
            self.remote_len = slen;
        }
        if (self.conn == null) return;

        var path: c.ngtcp2_path = .{
            .local = .{ .addr = @ptrCast(&self.local_sa), .addrlen = self.local_len },
            .remote = .{ .addr = @ptrCast(src), .addrlen = slen },
            .user_data = null,
        };
        var pi: c.ngtcp2_pkt_info = std.mem.zeroes(c.ngtcp2_pkt_info);
        const rv = c.ngtcp2_conn_read_pkt_versioned(self.conn, &path, PKT_INFO_VERSION, &pi, pkt.ptr, pkt.len, self.now());
        if (rv != 0) {
            if (rv == c.NGTCP2_ERR_DRAINING or rv == c.NGTCP2_ERR_CLOSING) {
                // Peer sent CONNECTION_CLOSE (or we're draining); the session
                // is over — surface it so the app loop exits promptly.
                self.peer_closed = true;
                return;
            }
            return Error.ReadFailed;
        }
    }

    fn serverAccept(self: *Conn, pkt: []const u8, src: *c.struct_sockaddr_in, slen: c.socklen_t) Error!void {
        var vc: c.ngtcp2_version_cid = std.mem.zeroes(c.ngtcp2_version_cid);
        if (c.ngtcp2_pkt_decode_version_cid(&vc, pkt.ptr, pkt.len, 8) != 0) return Error.AcceptFailed;

        self.remote_sa = src.*;
        self.remote_len = slen;
        self.have_remote = true;

        var dcid: c.ngtcp2_cid = undefined;
        c.ngtcp2_cid_init(&dcid, vc.scid, vc.scidlen);
        var scid: c.ngtcp2_cid = undefined;
        var scid_buf: [18]u8 = undefined;
        fillRandom(&scid_buf);
        c.ngtcp2_cid_init(&scid, &scid_buf, scid_buf.len);
        var odcid: c.ngtcp2_cid = undefined;
        c.ngtcp2_cid_init(&odcid, vc.dcid, vc.dcidlen);

        var settings: c.ngtcp2_settings = undefined;
        c.ngtcp2_settings_default_versioned(SETTINGS_VERSION, &settings);
        settings.initial_ts = self.now();

        var params: c.ngtcp2_transport_params = undefined;
        c.ngtcp2_transport_params_default_versioned(TRANSPORT_PARAMS_VERSION, &params);
        fillParams(&params);
        params.original_dcid = odcid;
        params.original_dcid_present = 1;

        var cbs = serverCallbacks();
        var path: c.ngtcp2_path = .{
            .local = .{ .addr = @ptrCast(&self.local_sa), .addrlen = self.local_len },
            .remote = .{ .addr = @ptrCast(src), .addrlen = slen },
            .user_data = null,
        };
        var cn: ?*c.ngtcp2_conn = null;
        if (c.ngtcp2_conn_server_new_versioned(&cn, &dcid, &scid, &path, vc.version, CALLBACKS_VERSION, &cbs, SETTINGS_VERSION, &settings, TRANSPORT_PARAMS_VERSION, &params, null, self) != 0) {
            return Error.ConnCreateFailed;
        }
        self.conn = cn;
        try self.serverSslForConn();
    }

    fn drainWrite(self: *Conn) Error!void {
        try self.drain();
    }

    fn pendingStream(self: *Conn) ?i64 {
        var it = self.sends.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.sent < entry.value_ptr.total) return entry.key_ptr.*;
        }
        return null;
    }

    fn drain(self: *Conn) Error!void {
        if (self.conn == null) return;
        var buf: [1500]u8 = undefined;
        while (true) {
            var pi: c.ngtcp2_pkt_info = std.mem.zeroes(c.ngtcp2_pkt_info);
            var ps: c.ngtcp2_path_storage = undefined;
            c.ngtcp2_path_storage_zero(&ps);
            var pdatalen: c.ngtcp2_ssize = 0;

            const pend = self.pendingStream();
            var vec: c.ngtcp2_vec = undefined;
            var sid: i64 = -1;
            var vptr: [*c]const c.ngtcp2_vec = null;
            var vcnt: usize = 0;
            if (pend) |ps_id| {
                const st = self.sends.getPtr(ps_id).?;
                const off: usize = @intCast(st.sent - st.base);
                vec = .{ .base = st.buf.items.ptr + off, .len = st.buf.items.len - off };
                sid = ps_id;
                vptr = &vec;
                vcnt = 1;
            }

            const n = c.ngtcp2_conn_writev_stream_versioned(self.conn, &ps.path, PKT_INFO_VERSION, &pi, &buf, buf.len, &pdatalen, 0, sid, vptr, vcnt, self.now());
            if (n == c.NGTCP2_ERR_WRITE_MORE) {
                if (pdatalen > 0 and pend != null) {
                    self.sends.getPtr(pend.?).?.sent += @intCast(pdatalen);
                }
                continue;
            }
            if (n < 0) return Error.WriteFailed;
            if (pdatalen > 0 and pend != null) {
                self.sends.getPtr(pend.?).?.sent += @intCast(pdatalen);
            }
            if (n > 0) {
                self.emit(buf[0..@intCast(n)], &self.remote_sa, self.remote_len);
            }
            if (n == 0) break;
        }
    }

    fn handleTimer(self: *Conn) Error!void {
        if (self.conn == null) return;
        const expiry = c.ngtcp2_conn_get_expiry(self.conn);
        if (expiry == std.math.maxInt(u64)) return;
        const t = self.now();
        if (t >= expiry) {
            if (c.ngtcp2_conn_handle_expiry(self.conn, t) != 0) return Error.ReadFailed;
        }
    }
};

/// Ask the kernel which local IPv4 address it would use to reach `remote_sa`.
/// A connected UDP socket sends no packets; connect() just primes route
/// selection so getsockname() reveals the chosen source address.
pub fn preferredLocalAddr(remote_sa: c.struct_sockaddr_in) ?c.struct_sockaddr_in {
    const fd = c.socket(c.AF_INET, c.SOCK_DGRAM, 0);
    if (fd < 0) return null;
    defer _ = c.close(fd);
    var r = remote_sa;
    if (c.connect(fd, @ptrCast(&r), @sizeOf(c.struct_sockaddr_in)) != 0) return null;
    var local: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    var llen: c.socklen_t = @sizeOf(c.struct_sockaddr_in);
    if (c.getsockname(fd, @ptrCast(&local), &llen) != 0) return null;
    return local;
}

/// Watches the OS's preferred source address for the connection's peer and
/// triggers a QUIC migration when it changes (e.g. wifi -> cellular). Timing
/// runs off the monotonic clock so tick() is cheap to call every loop.
pub const Roamer = struct {
    next_check_ns: u64 = 0,
    interval_ns: u64 = std.time.ns_per_s,

    /// Pure decision: migrate only when the kernel's preferred source IP is
    /// valid (non-zero) and differs from the IP the connection is bound to.
    pub fn decide(bound_ip: u32, preferred_ip: u32) bool {
        if (preferred_ip == 0) return false;
        return preferred_ip != bound_ip;
    }

    /// Rate-limited check; migrates the connection if the path changed. Returns
    /// true when a migration was performed.
    pub fn tick(self: *Roamer, conn: *Conn) Error!bool {
        const t = monotonicNs();
        if (t < self.next_check_ns) return false;
        self.next_check_ns = t + self.interval_ns;
        const pref = preferredLocalAddr(conn.remote_sa) orelse return false;
        if (!decide(conn.local_sa.sin_addr.s_addr, pref.sin_addr.s_addr)) return false;
        try conn.migrate();
        return true;
    }
};

fn fillParams(params: *c.ngtcp2_transport_params) void {
    params.initial_max_streams_bidi = 128;
    params.initial_max_streams_uni = 128;
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.initial_max_data = 1024 * 1024;
    params.max_idle_timeout = 30 * std.time.ns_per_s;
}

fn errno() c_int {
    return c.__error().*;
}

fn getConnCb(ref: [*c]c.ngtcp2_crypto_conn_ref) callconv(.c) ?*c.ngtcp2_conn {
    const self: *Conn = @ptrCast(@alignCast(ref.*.user_data));
    return self.conn;
}

fn randCb(dest: [*c]u8, destlen: usize, rand_ctx: [*c]const c.ngtcp2_rand_ctx) callconv(.c) void {
    _ = rand_ctx;
    fillRandom(dest[0..destlen]);
}

fn getNewCidCb(conn: ?*c.ngtcp2_conn, cid: [*c]c.ngtcp2_cid, token: [*c]u8, cidlen: usize, user_data: ?*anyopaque) callconv(.c) c_int {
    _ = conn;
    _ = user_data;
    fillRandom(cid.*.data[0..cidlen]);
    cid.*.datalen = cidlen;
    fillRandom(token[0..c.NGTCP2_STATELESS_RESET_TOKENLEN]);
    return 0;
}

fn recvStreamDataCb(conn: ?*c.ngtcp2_conn, flags: u32, stream_id: i64, offset: u64, data: [*c]const u8, datalen: usize, user_data: ?*anyopaque, stream_user_data: ?*anyopaque) callconv(.c) c_int {
    _ = conn;
    _ = offset;
    _ = stream_user_data;
    const self: *Conn = @ptrCast(@alignCast(user_data));
    if (flags & c.NGTCP2_STREAM_DATA_FLAG_FIN != 0) self.peer_closed = true;
    if (datalen > 0) {
        if (self.recv_handler) |h| {
            h(self.recv_ctx, stream_id, data[0..datalen]);
        } else {
            self.recv_buf.appendSlice(self.allocator, data[0..datalen]) catch return c.NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }
    return 0;
}

fn ackedStreamDataOffsetCb(conn: ?*c.ngtcp2_conn, stream_id: i64, offset: u64, datalen: u64, user_data: ?*anyopaque, stream_user_data: ?*anyopaque) callconv(.c) c_int {
    _ = conn;
    _ = stream_user_data;
    const self: *Conn = @ptrCast(@alignCast(user_data));
    if (self.sends.getPtr(stream_id)) |st| {
        const new_acked = offset + datalen;
        if (new_acked > st.acked) st.acked = new_acked;
        if (st.acked > st.base) {
            const drop: usize = @intCast(st.acked - st.base);
            const keep = st.buf.items.len - drop;
            std.mem.copyForwards(u8, st.buf.items[0..keep], st.buf.items[drop..]);
            st.buf.shrinkRetainingCapacity(keep);
            st.base = st.acked;
        }
    }
    return 0;
}

fn handshakeCompletedCb(conn: ?*c.ngtcp2_conn, user_data: ?*anyopaque) callconv(.c) c_int {
    _ = conn;
    const self: *Conn = @ptrCast(@alignCast(user_data));
    self.handshake_done = true;
    return 0;
}

fn alpnSelectCb(ssl: ?*c.SSL, out: [*c][*c]const u8, outlen: [*c]u8, in: [*c]const u8, inlen: c_uint, arg: ?*anyopaque) callconv(.c) c_int {
    _ = ssl;
    _ = in;
    _ = inlen;
    _ = arg;
    out.* = @ptrCast(alpn_proto.ptr);
    outlen.* = alpn_proto.len;
    return c.SSL_TLSEXT_ERR_OK;
}

fn baseCallbacks() c.ngtcp2_callbacks {
    var cbs: c.ngtcp2_callbacks = std.mem.zeroes(c.ngtcp2_callbacks);
    cbs.recv_crypto_data = c.ngtcp2_crypto_recv_crypto_data_cb;
    cbs.encrypt = c.ngtcp2_crypto_encrypt_cb;
    cbs.decrypt = c.ngtcp2_crypto_decrypt_cb;
    cbs.hp_mask = c.ngtcp2_crypto_hp_mask_cb;
    cbs.update_key = c.ngtcp2_crypto_update_key_cb;
    cbs.delete_crypto_aead_ctx = c.ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cbs.delete_crypto_cipher_ctx = c.ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cbs.get_path_challenge_data = c.ngtcp2_crypto_get_path_challenge_data_cb;
    cbs.version_negotiation = c.ngtcp2_crypto_version_negotiation_cb;
    cbs.rand = randCb;
    cbs.get_new_connection_id = getNewCidCb;
    cbs.recv_stream_data = recvStreamDataCb;
    cbs.acked_stream_data_offset = ackedStreamDataOffsetCb;
    cbs.handshake_completed = handshakeCompletedCb;
    return cbs;
}

fn clientCallbacks() c.ngtcp2_callbacks {
    var cbs = baseCallbacks();
    cbs.client_initial = c.ngtcp2_crypto_client_initial_cb;
    cbs.recv_retry = c.ngtcp2_crypto_recv_retry_cb;
    return cbs;
}

fn serverCallbacks() c.ngtcp2_callbacks {
    var cbs = baseCallbacks();
    cbs.recv_client_initial = c.ngtcp2_crypto_recv_client_initial_cb;
    return cbs;
}

fn ensureOsslInit() Error!void {
    if (!ossl_initialized) {
        if (c.ngtcp2_crypto_ossl_init() != 0) return Error.TlsFailed;
        ossl_initialized = true;
    }
}

fn makeUdpSocket() Error!c_int {
    const fd = c.socket(c.AF_INET, c.SOCK_DGRAM, 0);
    if (fd < 0) return Error.SocketFailed;
    const flags = c.fcntl(fd, c.F_GETFL, @as(c_int, 0));
    _ = c.fcntl(fd, c.F_SETFL, flags | c.O_NONBLOCK);
    return fd;
}

fn loopbackAddr(port: u16) c.struct_sockaddr_in {
    var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    sa.sin_family = c.AF_INET;
    sa.sin_port = std.mem.nativeToBig(u16, port);
    _ = c.inet_pton(c.AF_INET, "127.0.0.1", &sa.sin_addr);
    return sa;
}

// Resolve `host` (dotted IPv4 literal or a hostname/MagicDNS name) to an IPv4
// sockaddr on `port`. IPv4-only for v1 (AF_INET); IPv6 is deferred.
fn resolveV4(allocator: std.mem.Allocator, host: []const u8, port: u16) Error!c.struct_sockaddr_in {
    var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    sa.sin_family = c.AF_INET;
    sa.sin_port = std.mem.nativeToBig(u16, port);

    const host_z = try allocator.dupeZ(u8, host);
    defer allocator.free(host_z);

    if (c.inet_pton(c.AF_INET, host_z.ptr, &sa.sin_addr) == 1) return sa;

    var hints: c.struct_addrinfo = std.mem.zeroes(c.struct_addrinfo);
    hints.ai_family = c.AF_INET;
    hints.ai_socktype = c.SOCK_DGRAM;
    var res: ?*c.struct_addrinfo = null;
    if (c.getaddrinfo(host_z.ptr, null, &hints, &res) != 0 or res == null) return Error.ResolveFailed;
    defer c.freeaddrinfo(res);
    const ai_addr = res.?.ai_addr orelse return Error.ResolveFailed;
    const in4: *c.struct_sockaddr_in = @ptrCast(@alignCast(ai_addr));
    sa.sin_addr = in4.sin_addr;
    return sa;
}

fn bindAddrV4(allocator: std.mem.Allocator, bind_addr: []const u8, port: u16) Error!c.struct_sockaddr_in {
    var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    sa.sin_family = c.AF_INET;
    sa.sin_port = std.mem.nativeToBig(u16, port);
    const addr_z = try allocator.dupeZ(u8, bind_addr);
    defer allocator.free(addr_z);
    if (c.inet_pton(c.AF_INET, addr_z.ptr, &sa.sin_addr) != 1) return Error.ResolveFailed;
    return sa;
}

pub const Client = struct {
    pub fn connect(allocator: std.mem.Allocator, host: []const u8, server_port: u16, server_name: []const u8) Error!*Conn {
        try ensureOsslInit();
        const self = try allocator.create(Conn);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .is_server = false,
        };
        self.sends = std.AutoHashMap(i64, StreamSend).init(allocator);
        self.sends_init = true;
        self.conn_ref.user_data = self;

        self.fd = try makeUdpSocket();
        errdefer _ = c.close(self.fd);

        self.local_sa = try bindAddrV4(allocator, "0.0.0.0", 0);
        if (c.bind(self.fd, @ptrCast(&self.local_sa), self.local_len) != 0) return Error.BindFailed;
        if (c.getsockname(self.fd, @ptrCast(&self.local_sa), &self.local_len) != 0) return Error.GetSockNameFailed;

        self.remote_sa = try resolveV4(allocator, host, server_port);
        self.remote_len = @sizeOf(c.struct_sockaddr_in);
        self.have_remote = true;

        var dcid: c.ngtcp2_cid = undefined;
        var dcid_buf: [18]u8 = undefined;
        fillRandom(&dcid_buf);
        c.ngtcp2_cid_init(&dcid, &dcid_buf, dcid_buf.len);
        var scid: c.ngtcp2_cid = undefined;
        var scid_buf: [18]u8 = undefined;
        fillRandom(&scid_buf);
        c.ngtcp2_cid_init(&scid, &scid_buf, scid_buf.len);

        var settings: c.ngtcp2_settings = undefined;
        c.ngtcp2_settings_default_versioned(SETTINGS_VERSION, &settings);
        settings.initial_ts = self.now();

        var params: c.ngtcp2_transport_params = undefined;
        c.ngtcp2_transport_params_default_versioned(TRANSPORT_PARAMS_VERSION, &params);
        fillParams(&params);

        var cbs = clientCallbacks();
        var path: c.ngtcp2_path = .{
            .local = .{ .addr = @ptrCast(&self.local_sa), .addrlen = self.local_len },
            .remote = .{ .addr = @ptrCast(&self.remote_sa), .addrlen = self.remote_len },
            .user_data = null,
        };
        var cn: ?*c.ngtcp2_conn = null;
        if (c.ngtcp2_conn_client_new_versioned(&cn, &dcid, &scid, &path, c.NGTCP2_PROTO_VER_V1, CALLBACKS_VERSION, &cbs, SETTINGS_VERSION, &settings, TRANSPORT_PARAMS_VERSION, &params, null, self) != 0) {
            return Error.ConnCreateFailed;
        }
        self.conn = cn;
        try self.setupTlsClient(server_name);
        return self;
    }
};

pub const Server = struct {
    pub fn init(allocator: std.mem.Allocator, bind_addr: []const u8, port: u16, cert_path: []const u8, key_path: []const u8) Error!*Conn {
        try ensureOsslInit();
        const self = try allocator.create(Conn);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .is_server = true,
        };
        self.sends = std.AutoHashMap(i64, StreamSend).init(allocator);
        self.sends_init = true;
        self.conn_ref.user_data = self;

        self.fd = try makeUdpSocket();
        errdefer _ = c.close(self.fd);

        self.local_sa = try bindAddrV4(allocator, bind_addr, port);
        if (c.bind(self.fd, @ptrCast(&self.local_sa), self.local_len) != 0) return Error.BindFailed;
        if (c.getsockname(self.fd, @ptrCast(&self.local_sa), &self.local_len) != 0) return Error.GetSockNameFailed;

        try self.setupTlsServer(cert_path, key_path);
        return self;
    }
};

fn buildServerCtx(allocator: std.mem.Allocator, cert_path: []const u8, key_path: []const u8) Error!*c.SSL_CTX {
    const ctx = c.SSL_CTX_new(c.TLS_method()) orelse return Error.TlsFailed;
    errdefer c.SSL_CTX_free(ctx);
    _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_3_VERSION);
    _ = c.SSL_CTX_set_max_proto_version(ctx, c.TLS1_3_VERSION);

    const cert_z = try allocator.dupeZ(u8, cert_path);
    defer allocator.free(cert_z);
    const key_z = try allocator.dupeZ(u8, key_path);
    defer allocator.free(key_z);
    if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_z.ptr) != 1) return Error.TlsFailed;
    if (c.SSL_CTX_use_PrivateKey_file(ctx, key_z.ptr, c.SSL_FILETYPE_PEM) != 1) return Error.TlsFailed;
    c.SSL_CTX_set_alpn_select_cb(ctx, alpnSelectCb, null);
    return ctx;
}

/// A persistent listening endpoint: it owns the UDP socket and the server TLS
/// context, both of which outlive any individual connection. `accept` hands
/// back a fully-handshaked server `Conn` bound to the shared socket; when that
/// connection dies the same `Listener` accepts the next one (used for session
/// resume, where a brand-new QUIC connection reattaches to a surviving shell).
pub const Listener = struct {
    allocator: std.mem.Allocator,
    fd: c_int = -1,
    ssl_ctx: *c.SSL_CTX,
    local_sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in),
    local_len: c.socklen_t = @sizeOf(c.struct_sockaddr_in),
    pending: ?*Conn = null,

    pub fn init(allocator: std.mem.Allocator, bind_addr: []const u8, port: u16, cert_path: []const u8, key_path: []const u8) Error!*Listener {
        try ensureOsslInit();
        const self = try allocator.create(Listener);
        errdefer allocator.destroy(self);

        const ctx = try buildServerCtx(allocator, cert_path, key_path);
        errdefer c.SSL_CTX_free(ctx);

        self.* = .{ .allocator = allocator, .ssl_ctx = ctx };

        self.fd = try makeUdpSocket();
        errdefer _ = c.close(self.fd);

        self.local_sa = try bindAddrV4(allocator, bind_addr, port);
        if (c.bind(self.fd, @ptrCast(&self.local_sa), self.local_len) != 0) return Error.BindFailed;
        if (c.getsockname(self.fd, @ptrCast(&self.local_sa), &self.local_len) != 0) return Error.GetSockNameFailed;
        return self;
    }

    pub fn localPort(self: *Listener) u16 {
        return std.mem.bigToNative(u16, self.local_sa.sin_port);
    }

    pub fn socketFd(self: *Listener) c_int {
        return self.fd;
    }

    fn newPendingConn(self: *Listener) Error!*Conn {
        const conn = try self.allocator.create(Conn);
        errdefer self.allocator.destroy(conn);
        conn.* = .{
            .allocator = self.allocator,
            .is_server = true,
            .fd = self.fd,
            .owns_fd = false,
            .owns_ctx = false,
            .ssl_ctx = self.ssl_ctx,
            .local_sa = self.local_sa,
            .local_len = self.local_len,
        };
        conn.sends = std.AutoHashMap(i64, StreamSend).init(self.allocator);
        conn.sends_init = true;
        conn.conn_ref.user_data = conn;
        return conn;
    }

    /// Non-blocking: drive an in-progress accept one step. Returns a `Conn` only
    /// once its handshake completes; otherwise null. Call whenever the socket is
    /// readable (and periodically to service handshake timers).
    pub fn pollAccept(self: *Listener) Error!?*Conn {
        if (self.pending == null) self.pending = try self.newPendingConn();
        const p = self.pending.?;
        p.step() catch {
            p.deinit();
            self.pending = null;
            return null;
        };
        if (p.handshakeCompleted()) {
            self.pending = null;
            return p;
        }
        if (p.peerClosed()) {
            p.deinit();
            self.pending = null;
        }
        return null;
    }

    /// Blocking: read datagrams until a client fully handshakes, then return it.
    pub fn accept(self: *Listener) Error!*Conn {
        while (true) {
            var pfd: c.struct_pollfd = .{ .fd = self.fd, .events = c.POLLIN, .revents = 0 };
            _ = c.poll(&pfd, 1, 50);
            if (try self.pollAccept()) |conn| return conn;
        }
    }

    pub fn deinit(self: *Listener) void {
        if (self.pending) |p| p.deinit();
        c.SSL_CTX_free(self.ssl_ctx);
        if (self.fd >= 0) _ = c.close(self.fd);
        self.allocator.destroy(self);
    }
};

test "preferredLocalAddr returns loopback source for a loopback remote" {
    const remote = loopbackAddr(9); // discard port; no packets are sent
    const local = preferredLocalAddr(remote) orelse return error.NoPreferredAddr;
    var expect_lo: c.struct_in_addr = undefined;
    _ = c.inet_pton(c.AF_INET, "127.0.0.1", &expect_lo);
    try std.testing.expectEqual(expect_lo.s_addr, local.sin_addr.s_addr);
}

test "quic handshake and stream round-trip over loopback" {
    const allocator = std.testing.allocator;

    var server = try Server.init(allocator, "127.0.0.1", 0, "src/transport/testdata/cert.pem", "src/transport/testdata/key.pem");
    defer server.deinit();
    const port = server.localPort();

    var client = try Client.connect(allocator, "127.0.0.1", port, "localhost");
    defer client.deinit();

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        try client.step();
        try server.step();
        if (client.handshakeCompleted() and server.handshakeCompleted()) break;
        sleepMs(1);
    }
    try std.testing.expect(client.handshakeCompleted());
    try std.testing.expect(server.handshakeCompleted());

    const sid = try client.openStream();
    const msg = "hello moonshine";
    try client.write(sid, msg);

    i = 0;
    while (i < 1000) : (i += 1) {
        try client.step();
        try server.step();
        if (server.received().len >= msg.len) break;
        sleepMs(1);
    }
    try std.testing.expectEqualStrings(msg, server.received());

    const reply = "echo back";
    try server.write(sid, reply);
    i = 0;
    while (i < 1000) : (i += 1) {
        try server.step();
        try client.step();
        if (client.received().len >= reply.len) break;
        sleepMs(1);
    }
    try std.testing.expectEqualStrings(reply, client.received());
}

test "quic retains outbound stream data after write returns (clobber-after-write)" {
    const allocator = std.testing.allocator;

    var server = try Server.init(allocator, "127.0.0.1", 0, "src/transport/testdata/cert.pem", "src/transport/testdata/key.pem");
    defer server.deinit();
    const port = server.localPort();

    var client = try Client.connect(allocator, "127.0.0.1", port, "localhost");
    defer client.deinit();

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        try client.step();
        try server.step();
        if (client.handshakeCompleted() and server.handshakeCompleted()) break;
        sleepMs(1);
    }
    try std.testing.expect(client.handshakeCompleted());
    try std.testing.expect(server.handshakeCompleted());

    const total: usize = 256 * 1024;
    const msg = try allocator.alloc(u8, total);
    defer allocator.free(msg);
    var k: usize = 0;
    while (k < total) : (k += 1) msg[k] = @intCast((k * 31 + 7) & 0xff);

    const expected = try allocator.dupe(u8, msg);
    defer allocator.free(expected);

    const sid = try client.openStream();
    try client.write(sid, msg);

    @memset(msg, 0xff);

    i = 0;
    while (i < 20000) : (i += 1) {
        try client.step();
        try server.step();
        if (server.received().len >= total) break;
        sleepMs(1);
    }
    try std.testing.expectEqual(total, server.received().len);
    try std.testing.expectEqualSlices(u8, expected, server.received());
}
