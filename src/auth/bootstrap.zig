const std = @import("std");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/rand.h");
    @cInclude("openssl/obj_mac.h");
    @cInclude("unistd.h");
});

const hex_chars = "0123456789abcdef";

pub const token_len = 32;
pub const Token = [token_len]u8;
pub const Fingerprint = [32]u8;

pub const Error = error{
    KeygenFailed,
    CertFailed,
    WriteFailed,
    LoadCertFailed,
    DigestFailed,
    OutOfMemory,
    BadBootstrapLine,
};

const b64 = std.base64.standard;

pub fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

pub fn randomToken() Token {
    var tok: Token = undefined;
    _ = c.RAND_bytes(&tok, tok.len);
    return tok;
}

pub const Ephemeral = struct {
    allocator: std.mem.Allocator,
    cert_path: [:0]u8,
    key_path: [:0]u8,
    fingerprint: Fingerprint,

    pub fn deinit(self: *Ephemeral) void {
        _ = c.unlink(self.cert_path.ptr);
        _ = c.unlink(self.key_path.ptr);
        self.allocator.free(self.cert_path);
        self.allocator.free(self.key_path);
    }
};

fn tempPath(allocator: std.mem.Allocator, suffix: []const u8) ![:0]u8 {
    var rnd: [8]u8 = undefined;
    _ = c.RAND_bytes(&rnd, rnd.len);
    var hex: [16]u8 = undefined;
    for (rnd, 0..) |b, i| {
        hex[i * 2] = hex_chars[b >> 4];
        hex[i * 2 + 1] = hex_chars[b & 0x0f];
    }
    return std.fmt.allocPrintSentinel(allocator, "/tmp/mshd-boot-{s}-{s}", .{ hex, suffix }, 0);
}

/// Generate a fresh self-signed ed25519 certificate and private key, write them
/// to temp files, and compute the SHA-256 fingerprint of the cert DER.
pub fn generateEphemeral(allocator: std.mem.Allocator) Error!Ephemeral {
    const pctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_ED25519, null) orelse return Error.KeygenFailed;
    defer c.EVP_PKEY_CTX_free(pctx);
    if (c.EVP_PKEY_keygen_init(pctx) != 1) return Error.KeygenFailed;
    var pkey: ?*c.EVP_PKEY = null;
    if (c.EVP_PKEY_keygen(pctx, &pkey) != 1) return Error.KeygenFailed;
    defer c.EVP_PKEY_free(pkey);

    const x = c.X509_new() orelse return Error.CertFailed;
    defer c.X509_free(x);
    _ = c.X509_set_version(x, 2);
    _ = c.ASN1_INTEGER_set(c.X509_get_serialNumber(x), 1);
    _ = c.X509_gmtime_adj(c.X509_getm_notBefore(x), 0);
    _ = c.X509_gmtime_adj(c.X509_getm_notAfter(x), 60 * 60 * 24);
    if (c.X509_set_pubkey(x, pkey) != 1) return Error.CertFailed;

    const name = c.X509_get_subject_name(x);
    _ = c.X509_NAME_add_entry_by_txt(name, "CN", c.MBSTRING_ASC, "moonshine", -1, -1, 0);
    if (c.X509_set_issuer_name(x, name) != 1) return Error.CertFailed;
    if (c.X509_sign(x, pkey, null) == 0) return Error.CertFailed;

    var fp: Fingerprint = undefined;
    var fplen: c_uint = 0;
    if (c.X509_digest(x, c.EVP_sha256(), &fp, &fplen) != 1 or fplen != 32) return Error.DigestFailed;

    const cert_path = tempPath(allocator, "cert.pem") catch return Error.OutOfMemory;
    errdefer allocator.free(cert_path);
    const key_path = tempPath(allocator, "key.pem") catch return Error.OutOfMemory;
    errdefer allocator.free(key_path);

    {
        const bio = c.BIO_new_file(cert_path.ptr, "w") orelse return Error.WriteFailed;
        defer _ = c.BIO_free(bio);
        if (c.PEM_write_bio_X509(bio, x) != 1) return Error.WriteFailed;
    }
    {
        const bio = c.BIO_new_file(key_path.ptr, "w") orelse return Error.WriteFailed;
        defer _ = c.BIO_free(bio);
        if (c.PEM_write_bio_PrivateKey(bio, pkey, null, null, 0, null, null) != 1) return Error.WriteFailed;
    }

    return .{
        .allocator = allocator,
        .cert_path = cert_path,
        .key_path = key_path,
        .fingerprint = fp,
    };
}

/// Load a PEM certificate from `path` and compute its SHA-256 DER fingerprint.
pub fn fingerprintFromPemFile(path: [:0]const u8) Error!Fingerprint {
    const bio = c.BIO_new_file(path.ptr, "r") orelse return Error.LoadCertFailed;
    defer _ = c.BIO_free(bio);
    const x = c.PEM_read_bio_X509(bio, null, null, null) orelse return Error.LoadCertFailed;
    defer c.X509_free(x);
    var fp: Fingerprint = undefined;
    var fplen: c_uint = 0;
    if (c.X509_digest(x, c.EVP_sha256(), &fp, &fplen) != 1 or fplen != 32) return Error.DigestFailed;
    return fp;
}

pub const BootstrapLine = struct {
    version: u16,
    port: u16,
    fingerprint: Fingerprint,
    token: Token,
};

/// Format the single bootstrap line printed by `mshd --bootstrap`.
pub fn formatLine(buf: []u8, port: u16, fp: Fingerprint, token: Token) ![]u8 {
    var fp_b64: [b64.Encoder.calcSize(32)]u8 = undefined;
    var tok_b64: [b64.Encoder.calcSize(token_len)]u8 = undefined;
    const fp_enc = b64.Encoder.encode(&fp_b64, &fp);
    const tok_enc = b64.Encoder.encode(&tok_b64, &token);
    return std.fmt.bufPrint(buf, "MSH-BOOTSTRAP v=1 port={d} fp={s} token={s}\n", .{ port, fp_enc, tok_enc });
}

fn field(line: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    while (it.next()) |tok| {
        if (std.mem.startsWith(u8, tok, key) and tok.len > key.len and tok[key.len] == '=') {
            return tok[key.len + 1 ..];
        }
    }
    return null;
}

pub fn parseLine(line_in: []const u8) Error!BootstrapLine {
    const line = std.mem.trim(u8, line_in, " \r\n");
    if (!std.mem.startsWith(u8, line, "MSH-BOOTSTRAP")) return Error.BadBootstrapLine;

    const v_s = field(line, "v") orelse return Error.BadBootstrapLine;
    const port_s = field(line, "port") orelse return Error.BadBootstrapLine;
    const fp_s = field(line, "fp") orelse return Error.BadBootstrapLine;
    const tok_s = field(line, "token") orelse return Error.BadBootstrapLine;

    const version = std.fmt.parseInt(u16, v_s, 10) catch return Error.BadBootstrapLine;
    const port = std.fmt.parseInt(u16, port_s, 10) catch return Error.BadBootstrapLine;

    var fp: Fingerprint = undefined;
    var tok: Token = undefined;
    if ((b64.Decoder.calcSizeForSlice(fp_s) catch return Error.BadBootstrapLine) != fp.len) return Error.BadBootstrapLine;
    if ((b64.Decoder.calcSizeForSlice(tok_s) catch return Error.BadBootstrapLine) != tok.len) return Error.BadBootstrapLine;
    b64.Decoder.decode(&fp, fp_s) catch return Error.BadBootstrapLine;
    b64.Decoder.decode(&tok, tok_s) catch return Error.BadBootstrapLine;

    return .{ .version = version, .port = port, .fingerprint = fp, .token = tok };
}

const testing = std.testing;

test "constant-time compare equal, unequal, different length" {
    const a = [_]u8{ 1, 2, 3, 4 };
    const b = [_]u8{ 1, 2, 3, 4 };
    const d = [_]u8{ 1, 2, 3, 5 };
    const short = [_]u8{ 1, 2, 3 };
    try testing.expect(constantTimeEql(&a, &b));
    try testing.expect(!constantTimeEql(&a, &d));
    try testing.expect(!constantTimeEql(&a, &short));
}

test "bootstrap line format/parse round-trip" {
    var fp: Fingerprint = undefined;
    var tok: Token = undefined;
    for (&fp, 0..) |*p, i| p.* = @intCast(i);
    for (&tok, 0..) |*p, i| p.* = @intCast(255 - i);
    var buf: [256]u8 = undefined;
    const line = try formatLine(&buf, 54321, fp, tok);
    const parsed = try parseLine(line);
    try testing.expectEqual(@as(u16, 1), parsed.version);
    try testing.expectEqual(@as(u16, 54321), parsed.port);
    try testing.expectEqualSlices(u8, &fp, &parsed.fingerprint);
    try testing.expectEqualSlices(u8, &tok, &parsed.token);
}

test "bad bootstrap line rejected" {
    try testing.expectError(Error.BadBootstrapLine, parseLine("not a bootstrap line"));
    try testing.expectError(Error.BadBootstrapLine, parseLine("MSH-BOOTSTRAP v=1 port=10"));
}

test "ephemeral cert fingerprint match vs mismatch" {
    const allocator = testing.allocator;
    var eph = try generateEphemeral(allocator);
    defer eph.deinit();
    const loaded = try fingerprintFromPemFile(eph.cert_path);
    try testing.expect(constantTimeEql(&eph.fingerprint, &loaded));
    var wrong = eph.fingerprint;
    wrong[0] ^= 0xFF;
    try testing.expect(!constantTimeEql(&eph.fingerprint, &wrong));
}
