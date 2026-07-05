const std = @import("std");

pub const Version = packed struct(u16) {
    minor: u8,
    major: u8,

    pub fn init(major: u8, minor: u8) Version {
        return .{ .major = major, .minor = minor };
    }

    pub fn fromInt(v: u16) Version {
        return @bitCast(v);
    }

    pub fn toInt(self: Version) u16 {
        return @bitCast(self);
    }

    pub fn order(a: Version, b: Version) std.math.Order {
        return std.math.order(a.toInt(), b.toInt());
    }
};

pub const current: Version = Version.fromInt(0x0001);

pub const Range = struct {
    min: Version,
    max: Version,

    pub fn contains(self: Range, v: Version) bool {
        return v.toInt() >= self.min.toInt() and v.toInt() <= self.max.toInt();
    }
};

pub const supported: Range = .{ .min = current, .max = current };

pub fn negotiate(local: Range, remote: Range) ?Version {
    const hi = @min(local.max.toInt(), remote.max.toInt());
    const lo = @max(local.min.toInt(), remote.min.toInt());
    if (hi < lo) return null;
    return Version.fromInt(hi);
}

pub const Capabilities = struct {
    bits: u64 = 0,

    pub const PREDICT: u64 = 1 << 0;
    pub const RESUME: u64 = 1 << 1;
    pub const MIGRATE: u64 = 1 << 2;
    pub const COMPRESS: u64 = 1 << 3;
    pub const PORTFWD: u64 = 1 << 4;

    pub fn init(bits: u64) Capabilities {
        return .{ .bits = bits };
    }

    pub fn has(self: Capabilities, bit: u64) bool {
        return (self.bits & bit) == bit;
    }

    pub fn effective(a: Capabilities, b: Capabilities) Capabilities {
        return .{ .bits = a.bits & b.bits };
    }
};

test "version pack/unpack" {
    try std.testing.expectEqual(@as(u16, 0x0001), current.toInt());
    try std.testing.expectEqual(@as(u8, 0), current.major);
    try std.testing.expectEqual(@as(u8, 1), current.minor);
    const v = Version.init(1, 2);
    try std.testing.expectEqual(@as(u16, 0x0102), v.toInt());
    try std.testing.expectEqual(v.toInt(), Version.fromInt(v.toInt()).toInt());
}

test "negotiate overlap" {
    const local: Range = .{ .min = Version.fromInt(0x0001), .max = Version.fromInt(0x0103) };
    const remote: Range = .{ .min = Version.fromInt(0x0002), .max = Version.fromInt(0x0102) };
    const got = negotiate(local, remote).?;
    try std.testing.expectEqual(@as(u16, 0x0102), got.toInt());
}

test "negotiate exact" {
    const r: Range = .{ .min = current, .max = current };
    const got = negotiate(r, r).?;
    try std.testing.expectEqual(@as(u16, 0x0001), got.toInt());
}

test "negotiate no overlap" {
    const local: Range = .{ .min = Version.fromInt(0x0001), .max = Version.fromInt(0x0001) };
    const remote: Range = .{ .min = Version.fromInt(0x0002), .max = Version.fromInt(0x0003) };
    try std.testing.expect(negotiate(local, remote) == null);
}

test "capability AND" {
    const a = Capabilities.init(Capabilities.PREDICT | Capabilities.RESUME | Capabilities.MIGRATE);
    const b = Capabilities.init(Capabilities.RESUME | Capabilities.MIGRATE | Capabilities.PORTFWD);
    const eff = Capabilities.effective(a, b);
    try std.testing.expectEqual(Capabilities.RESUME | Capabilities.MIGRATE, eff.bits);
    try std.testing.expect(eff.has(Capabilities.RESUME));
    try std.testing.expect(!eff.has(Capabilities.PREDICT));
    try std.testing.expect(!eff.has(Capabilities.PORTFWD));
}
