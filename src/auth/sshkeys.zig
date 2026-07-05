const std = @import("std");

const c = @cImport({
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
});

const Ed25519 = std.crypto.sign.Ed25519;

/// Read an entire file into a freshly allocated buffer using POSIX I/O (this
/// build's std.fs is stripped down, so the codebase uses libc directly).
pub fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8, max: usize) ![]u8 {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    const fd = c.open(path_z.ptr, c.O_RDONLY);
    if (fd < 0) return error.OpenFailed;
    defer _ = c.close(fd);
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = c.read(fd, &buf, buf.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        if (list.items.len + @as(usize, @intCast(n)) > max) return error.FileTooLarge;
        try list.appendSlice(allocator, buf[0..@intCast(n)]);
    }
    return list.toOwnedSlice(allocator);
}

pub const PublicKey = [32]u8;
pub const SecretKeyBytes = [64]u8;
pub const Signature = [64]u8;

pub const domain = "moonshine-auth-v1:";

pub const Error = error{
    BadKeyFormat,
    NoEd25519Key,
    EncryptedKey,
    OutOfMemory,
    ReadFailed,
};

const b64 = std.base64.standard;

const SshReader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn take(r: *SshReader, n: usize) Error![]const u8 {
        if (r.buf.len - r.pos < n) return Error.BadKeyFormat;
        const s = r.buf[r.pos .. r.pos + n];
        r.pos += n;
        return s;
    }

    fn u32be(r: *SshReader) Error!u32 {
        const s = try r.take(4);
        return std.mem.readInt(u32, s[0..4], .big);
    }

    fn string(r: *SshReader) Error![]const u8 {
        const len = try r.u32be();
        return r.take(len);
    }
};

/// Decode a single base64 ed25519 public-key blob (the middle field of an
/// `authorized_keys` line) into its 32-byte key. Returns NoEd25519Key for any
/// non-ed25519 blob.
fn decodePubBlob(blob_b64: []const u8, out: *PublicKey) Error!void {
    var raw: [512]u8 = undefined;
    const dlen = b64.Decoder.calcSizeForSlice(blob_b64) catch return Error.BadKeyFormat;
    if (dlen > raw.len) return Error.BadKeyFormat;
    b64.Decoder.decode(raw[0..dlen], blob_b64) catch return Error.BadKeyFormat;

    var r = SshReader{ .buf = raw[0..dlen] };
    const kind = try r.string();
    if (!std.mem.eql(u8, kind, "ssh-ed25519")) return Error.NoEd25519Key;
    const pk = try r.string();
    if (pk.len != 32) return Error.BadKeyFormat;
    @memcpy(out, pk);
}

/// Parse the contents of an OpenSSH `authorized_keys` file, appending every
/// ed25519 public key found to `out`. Non-ed25519 lines, comments and blank
/// lines are ignored.
pub fn parseAuthorizedKeys(allocator: std.mem.Allocator, contents: []const u8, out: *std.ArrayList(PublicKey)) Error!void {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        const kind = fields.next() orelse continue;
        if (!std.mem.eql(u8, kind, "ssh-ed25519")) continue;
        const blob = fields.next() orelse continue;
        var pk: PublicKey = undefined;
        decodePubBlob(blob, &pk) catch continue;
        out.append(allocator, pk) catch return Error.OutOfMemory;
    }
}

/// Load and parse an `authorized_keys` file from disk.
pub fn loadAuthorizedKeys(allocator: std.mem.Allocator, path: []const u8, out: *std.ArrayList(PublicKey)) Error!void {
    const data = readFileAlloc(allocator, path, 1 << 20) catch return Error.ReadFailed;
    defer allocator.free(data);
    try parseAuthorizedKeys(allocator, data, out);
}

const pem_begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
const pem_end = "-----END OPENSSH PRIVATE KEY-----";

/// Parse an UNENCRYPTED OpenSSH private key (the `-----BEGIN OPENSSH PRIVATE
/// KEY-----` PEM form). Returns the 64-byte secret field, which is exactly
/// seed(32)||pub(32) — the layout std.crypto.sign.Ed25519.SecretKey expects.
/// Encrypted keys (ciphername != "none") yield error.EncryptedKey.
pub fn parsePrivateKey(allocator: std.mem.Allocator, pem: []const u8) Error!SecretKeyBytes {
    const bstart = std.mem.indexOf(u8, pem, pem_begin) orelse return Error.BadKeyFormat;
    const body_start = bstart + pem_begin.len;
    const bend = std.mem.indexOfPos(u8, pem, body_start, pem_end) orelse return Error.BadKeyFormat;

    var b64buf: std.ArrayList(u8) = .empty;
    defer b64buf.deinit(allocator);
    var lines = std.mem.splitScalar(u8, pem[body_start..bend], '\n');
    while (lines.next()) |line| {
        const t = std.mem.trim(u8, line, " \t\r");
        if (t.len == 0) continue;
        b64buf.appendSlice(allocator, t) catch return Error.OutOfMemory;
    }

    const dlen = b64.Decoder.calcSizeForSlice(b64buf.items) catch return Error.BadKeyFormat;
    const raw = allocator.alloc(u8, dlen) catch return Error.OutOfMemory;
    defer allocator.free(raw);
    b64.Decoder.decode(raw, b64buf.items) catch return Error.BadKeyFormat;

    var r = SshReader{ .buf = raw };
    const magic = try r.take(15);
    if (!std.mem.eql(u8, magic, "openssh-key-v1\x00")) return Error.BadKeyFormat;
    const ciphername = try r.string();
    if (!std.mem.eql(u8, ciphername, "none")) return Error.EncryptedKey;
    _ = try r.string(); // kdfname
    _ = try r.string(); // kdfoptions
    const numkeys = try r.u32be();
    if (numkeys != 1) return Error.BadKeyFormat;
    _ = try r.string(); // public key block
    const priv = try r.string(); // private section

    var pr = SshReader{ .buf = priv };
    const c1 = try pr.u32be();
    const c2 = try pr.u32be();
    if (c1 != c2) return Error.BadKeyFormat;
    const kind = try pr.string();
    if (!std.mem.eql(u8, kind, "ssh-ed25519")) return Error.NoEd25519Key;
    const pk = try pr.string();
    if (pk.len != 32) return Error.BadKeyFormat;
    const sk = try pr.string();
    if (sk.len != 64) return Error.BadKeyFormat;

    var out: SecretKeyBytes = undefined;
    @memcpy(&out, sk);
    return out;
}

/// Load and parse an unencrypted OpenSSH private key file from disk.
pub fn loadPrivateKey(allocator: std.mem.Allocator, path: []const u8) Error!SecretKeyBytes {
    const data = readFileAlloc(allocator, path, 1 << 20) catch return Error.ReadFailed;
    defer allocator.free(data);
    return parsePrivateKey(allocator, data);
}

/// Derive the public key from a 64-byte secret (its trailing 32 bytes).
pub fn publicFromSecret(secret: SecretKeyBytes) PublicKey {
    var pk: PublicKey = undefined;
    @memcpy(&pk, secret[32..64]);
    return pk;
}

fn challengeMessage(server_fp: [32]u8, out: *[domain.len + 32]u8) void {
    @memcpy(out[0..domain.len], domain);
    @memcpy(out[domain.len..], &server_fp);
}

/// Sign the channel-binding challenge for `server_fp` with a raw ed25519 secret.
/// The message is domain-separated and bound to the TLS session's server cert
/// fingerprint, so the signature is replay-proof across sessions.
pub fn signChallenge(secret: SecretKeyBytes, server_fp: [32]u8) Error!Signature {
    const sk = Ed25519.SecretKey.fromBytes(secret) catch return Error.BadKeyFormat;
    const kp = Ed25519.KeyPair.fromSecretKey(sk) catch return Error.BadKeyFormat;
    var msg: [domain.len + 32]u8 = undefined;
    challengeMessage(server_fp, &msg);
    const sig = kp.sign(&msg, null) catch return Error.BadKeyFormat;
    return sig.toBytes();
}

/// Verify a channel-binding signature against a claimed public key.
pub fn verifyChallenge(pubkey: PublicKey, server_fp: [32]u8, sig: Signature) bool {
    const pk = Ed25519.PublicKey.fromBytes(pubkey) catch return false;
    var msg: [domain.len + 32]u8 = undefined;
    challengeMessage(server_fp, &msg);
    const s = Ed25519.Signature.fromBytes(sig);
    s.verify(&msg, pk) catch return false;
    return true;
}

const testing = std.testing;

fn readFixture(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return readFileAlloc(allocator, path, 1 << 20);
}

test "parse authorized_keys fixture yields ed25519 pubkey" {
    const a = testing.allocator;
    const data = try readFixture(a, "src/auth/testdata/authorized_keys");
    defer a.free(data);
    var keys: std.ArrayList(PublicKey) = .empty;
    defer keys.deinit(a);
    try parseAuthorizedKeys(a, data, &keys);
    try testing.expectEqual(@as(usize, 1), keys.items.len);
}

test "parse private key fixture, sign and verify" {
    const a = testing.allocator;
    const pem = try readFixture(a, "src/auth/testdata/id_ed25519");
    defer a.free(pem);
    const secret = try parsePrivateKey(a, pem);
    const pk = publicFromSecret(secret);

    // The parsed public key must equal the authorized_keys entry.
    const auth = try readFixture(a, "src/auth/testdata/authorized_keys");
    defer a.free(auth);
    var keys: std.ArrayList(PublicKey) = .empty;
    defer keys.deinit(a);
    try parseAuthorizedKeys(a, auth, &keys);
    try testing.expectEqualSlices(u8, &keys.items[0], &pk);

    const sk = try Ed25519.SecretKey.fromBytes(secret);
    const kp = try Ed25519.KeyPair.fromSecretKey(sk);
    const sig = try kp.sign("hello moonshine", null);
    const pub_ed = try Ed25519.PublicKey.fromBytes(pk);
    try sig.verify("hello moonshine", pub_ed);
    try testing.expectError(error.SignatureVerificationFailed, sig.verify("tampered", pub_ed));
}

test "signChallenge/verifyChallenge round-trip and negatives" {
    const a = testing.allocator;
    const pem = try readFixture(a, "src/auth/testdata/id_ed25519");
    defer a.free(pem);
    const secret = try parsePrivateKey(a, pem);
    const pk = publicFromSecret(secret);

    var fp: [32]u8 = undefined;
    for (&fp, 0..) |*p, i| p.* = @intCast(i);

    const sig = try signChallenge(secret, fp);
    try testing.expect(verifyChallenge(pk, fp, sig));

    var wrong_fp = fp;
    wrong_fp[0] ^= 0xFF;
    try testing.expect(!verifyChallenge(pk, wrong_fp, sig));

    var wrong_pk = pk;
    wrong_pk[0] ^= 0xFF;
    try testing.expect(!verifyChallenge(wrong_pk, fp, sig));
}

test "encrypted key rejected" {
    const a = testing.allocator;
    // A minimal blob claiming an aes256 cipher must be refused.
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(a);
    try raw.appendSlice(a, "openssh-key-v1\x00");
    const cipher = "aes256-ctr";
    var len4: [4]u8 = undefined;
    std.mem.writeInt(u32, &len4, @intCast(cipher.len), .big);
    try raw.appendSlice(a, &len4);
    try raw.appendSlice(a, cipher);
    var enc: std.ArrayList(u8) = .empty;
    defer enc.deinit(a);
    try enc.appendSlice(a, pem_begin);
    try enc.append(a, '\n');
    var b64buf: [512]u8 = undefined;
    const encoded = b64.Encoder.encode(&b64buf, raw.items);
    try enc.appendSlice(a, encoded);
    try enc.append(a, '\n');
    try enc.appendSlice(a, pem_end);
    try testing.expectError(Error.EncryptedKey, parsePrivateKey(a, enc.items));
}
