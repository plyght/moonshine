const std = @import("std");
const VtTrack = @import("vt_track.zig").VtTrack;

const max_predictions = 64;
const cooldown_after_repair = 8;

const Entry = struct {
    char: u8,
    row: usize,
    col: usize,
};

pub const Predictor = struct {
    allocator: std.mem.Allocator,
    auth: VtTrack,
    pred: VtTrack,
    out: std.ArrayList(u8) = .empty,

    ring: [max_predictions]Entry = undefined,
    head: usize = 0,
    count: usize = 0,

    epoch_open: bool = true,
    cooldown: usize = 0,

    pub fn init(allocator: std.mem.Allocator) Predictor {
        return .{
            .allocator = allocator,
            .auth = VtTrack.init(),
            .pred = VtTrack.init(),
        };
    }

    pub fn deinit(self: *Predictor) void {
        self.out.deinit(self.allocator);
    }

    pub fn setSize(self: *Predictor, cols: usize, rows: usize) void {
        self.auth.setSize(cols, rows);
        self.pred.setSize(cols, rows);
    }

    pub fn onInput(self: *Predictor, keystrokes: []const u8) []const u8 {
        self.out.clearRetainingCapacity();
        if (self.cooldown > 0) self.cooldown -= 1;

        var i: usize = 0;
        while (i < keystrokes.len) : (i += 1) {
            const b = keystrokes[i];
            switch (b) {
                '\r', '\n', 0x1b, '\t' => self.epoch_open = false,
                0x08, 0x7f => {
                    if (self.epoch_open and self.auth.predictionSafe() and self.count > 0) {
                        self.count -= 1;
                        self.pred.feed(&[_]u8{0x08});
                        self.push("\x08 \x08");
                    }
                },
                else => {
                    if (b >= 0x20 and b <= 0x7e) {
                        if (self.canPredict()) {
                            self.pushEntry(.{ .char = b, .row = self.pred.row, .col = self.pred.col });
                            self.pushByte(b);
                            self.pred.feed(keystrokes[i .. i + 1]);
                        }
                    } else if (b < 0x20) {
                        self.epoch_open = false;
                    }
                },
            }
        }
        return self.out.items;
    }

    pub fn onAuthoritative(self: *Predictor, server_bytes: []const u8) []const u8 {
        self.out.clearRetainingCapacity();

        var i: usize = 0;
        while (i < server_bytes.len) {
            const b = server_bytes[i];
            if (self.count == 0) {
                self.auth.feed(server_bytes[i .. i + 1]);
                self.pushByte(b);
                i += 1;
                continue;
            }

            const h = self.ring[self.head];
            if (b == h.char and self.auth.col == h.col and self.auth.row == h.row) {
                self.auth.feed(server_bytes[i .. i + 1]);
                self.popHead();
                i += 1;
                continue;
            }

            self.repair(h);
            while (i < server_bytes.len) : (i += 1) {
                self.auth.feed(server_bytes[i .. i + 1]);
                self.pushByte(server_bytes[i]);
            }
            break;
        }

        if (self.count == 0) self.epoch_open = true;
        return self.out.items;
    }

    fn canPredict(self: *const Predictor) bool {
        return self.epoch_open and
            self.cooldown == 0 and
            self.count < max_predictions and
            self.auth.predictionSafe();
    }

    fn repair(self: *Predictor, first: Entry) void {
        var buf: [32]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "\x1b[{d};{d}H\x1b[K", .{ first.row + 1, first.col + 1 }) catch return;
        self.push(s);
        self.head = 0;
        self.count = 0;
        self.pred = self.auth;
        self.cooldown = cooldown_after_repair;
    }

    fn pushEntry(self: *Predictor, e: Entry) void {
        const idx = (self.head + self.count) % max_predictions;
        self.ring[idx] = e;
        self.count += 1;
    }

    fn popHead(self: *Predictor) void {
        self.head = (self.head + 1) % max_predictions;
        self.count -= 1;
    }

    fn push(self: *Predictor, s: []const u8) void {
        self.out.appendSlice(self.allocator, s) catch {};
    }

    fn pushByte(self: *Predictor, b: u8) void {
        self.out.append(self.allocator, b) catch {};
    }
};

const testing = std.testing;

test "type abc then authoritative echo suppresses all" {
    var p = Predictor.init(testing.allocator);
    defer p.deinit();

    try testing.expectEqualStrings("a", p.onInput("a"));
    try testing.expectEqualStrings("b", p.onInput("b"));
    try testing.expectEqualStrings("c", p.onInput("c"));
    try testing.expectEqual(@as(usize, 3), p.count);

    try testing.expectEqualStrings("", p.onAuthoritative("abc"));
    try testing.expectEqual(@as(usize, 0), p.count);
}

test "misprediction emits repair then passthrough" {
    var p = Predictor.init(testing.allocator);
    defer p.deinit();

    try testing.expectEqualStrings("a", p.onInput("a"));
    const out = p.onAuthoritative("X");
    try testing.expect(std.mem.indexOf(u8, out, "\x1b[K") != null);
    try testing.expect(std.mem.endsWith(u8, out, "X"));
    try testing.expectEqual(@as(usize, 0), p.count);
}

test "backspace erases pending prediction without underflow" {
    var p = Predictor.init(testing.allocator);
    defer p.deinit();

    try testing.expectEqualStrings("a", p.onInput("a"));
    try testing.expectEqualStrings("\x08 \x08", p.onInput(&[_]u8{0x7f}));
    try testing.expectEqual(@as(usize, 0), p.count);
    _ = p.onAuthoritative("a");
    try testing.expectEqual(@as(usize, 0), p.count);
}

test "enter closes epoch until queue drains" {
    var p = Predictor.init(testing.allocator);
    defer p.deinit();

    try testing.expectEqualStrings("a", p.onInput("a"));
    try testing.expectEqualStrings("", p.onInput("\r"));
    try testing.expectEqualStrings("", p.onInput("b"));

    _ = p.onAuthoritative("a");
    try testing.expect(p.epoch_open);
    try testing.expectEqualStrings("c", p.onInput("c"));
}

test "alt screen disables prediction and passes through" {
    var p = Predictor.init(testing.allocator);
    defer p.deinit();

    try testing.expectEqualStrings("\x1b[?1049h", p.onAuthoritative("\x1b[?1049h"));
    try testing.expect(!p.auth.predictionSafe());
    try testing.expectEqualStrings("", p.onInput("a"));
    try testing.expectEqualStrings("ls\r\n", p.onAuthoritative("ls\r\n"));
}

test "confirming echo split across chunks" {
    var p = Predictor.init(testing.allocator);
    defer p.deinit();

    try testing.expectEqualStrings("a", p.onInput("a"));
    try testing.expectEqualStrings("b", p.onInput("b"));
    try testing.expectEqualStrings("", p.onAuthoritative("a"));
    try testing.expectEqual(@as(usize, 1), p.count);
    try testing.expectEqualStrings("", p.onAuthoritative("b"));
    try testing.expectEqual(@as(usize, 0), p.count);
}

test "prediction cap halts further prediction" {
    var p = Predictor.init(testing.allocator);
    defer p.deinit();
    p.setSize(4096, 24);

    var n: usize = 0;
    while (n < max_predictions) : (n += 1) {
        try testing.expectEqualStrings("x", p.onInput("x"));
    }
    try testing.expectEqual(@as(usize, max_predictions), p.count);
    try testing.expectEqualStrings("", p.onInput("x"));
    try testing.expectEqual(@as(usize, max_predictions), p.count);
}
