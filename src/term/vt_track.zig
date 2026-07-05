const std = @import("std");

const max_params = 16;

const State = enum {
    ground,
    escape,
    csi,
    osc,
    osc_esc,
};

pub const VtTrack = struct {
    row: usize = 0,
    col: usize = 0,
    cols: usize = 80,
    rows: usize = 24,

    alt_screen: bool = false,
    app_cursor_keys: bool = false,
    bracketed_paste: bool = false,
    mouse_tracking: bool = false,

    state: State = .ground,
    private: bool = false,
    params: [max_params]usize = undefined,
    param_count: usize = 0,
    param_seen: bool = false,
    cur_param: usize = 0,

    pub fn init() VtTrack {
        return .{};
    }

    pub fn setSize(self: *VtTrack, cols: usize, rows: usize) void {
        self.cols = if (cols == 0) 1 else cols;
        self.rows = if (rows == 0) 1 else rows;
    }

    pub fn predictionSafe(self: *const VtTrack) bool {
        return !(self.alt_screen or self.bracketed_paste or self.mouse_tracking);
    }

    pub fn feed(self: *VtTrack, bytes: []const u8) void {
        for (bytes) |b| self.feedByte(b);
    }

    fn feedByte(self: *VtTrack, b: u8) void {
        switch (self.state) {
            .ground => self.ground(b),
            .escape => self.escape(b),
            .csi => self.csi(b),
            .osc => {
                if (b == 0x07) {
                    self.state = .ground;
                } else if (b == 0x1b) {
                    self.state = .osc_esc;
                }
            },
            .osc_esc => {
                self.state = if (b == '\\') .ground else .osc;
            },
        }
    }

    fn ground(self: *VtTrack, b: u8) void {
        switch (b) {
            0x1b => self.state = .escape,
            '\r' => self.col = 0,
            '\n' => self.lineFeed(),
            0x08 => {
                if (self.col > 0) self.col -= 1;
            },
            0x07, 0x00 => {},
            else => {
                if (b < 0x20) return;
                if (b >= 0x80 and b < 0xC0) return;
                self.advance();
            },
        }
    }

    fn advance(self: *VtTrack) void {
        self.col += 1;
        if (self.col >= self.cols) {
            self.col = 0;
            self.lineFeed();
        }
    }

    fn lineFeed(self: *VtTrack) void {
        if (self.row + 1 < self.rows) self.row += 1;
    }

    fn escape(self: *VtTrack, b: u8) void {
        switch (b) {
            '[' => {
                self.state = .csi;
                self.private = false;
                self.param_count = 0;
                self.param_seen = false;
                self.cur_param = 0;
            },
            ']' => self.state = .osc,
            else => self.state = .ground,
        }
    }

    fn pushParam(self: *VtTrack) void {
        if (self.param_count < max_params) {
            self.params[self.param_count] = self.cur_param;
            self.param_count += 1;
        }
        self.cur_param = 0;
    }

    fn param(self: *const VtTrack, idx: usize, default: usize) usize {
        if (idx >= self.param_count) return default;
        const v = self.params[idx];
        return if (v == 0) default else v;
    }

    fn csi(self: *VtTrack, b: u8) void {
        switch (b) {
            '0'...'9' => {
                self.param_seen = true;
                self.cur_param = self.cur_param * 10 + (b - '0');
            },
            ';' => {
                self.pushParam();
                self.param_seen = true;
            },
            '?', '>', '<', '=' => self.private = true,
            0x20...0x2f => {},
            0x40...0x7e => {
                if (self.param_seen or self.cur_param != 0) self.pushParam();
                self.dispatch(b);
                self.state = .ground;
            },
            else => self.state = .ground,
        }
    }

    fn dispatch(self: *VtTrack, final: u8) void {
        if (self.private) {
            switch (final) {
                'h', 'l' => {
                    const set = final == 'h';
                    var i: usize = 0;
                    while (i < self.param_count) : (i += 1) {
                        self.setMode(self.params[i], set);
                    }
                },
                else => {},
            }
            return;
        }
        switch (final) {
            'H', 'f' => {
                const r = self.param(0, 1);
                const c = self.param(1, 1);
                self.row = clampDown(r);
                self.col = clampDown(c);
                self.clampCursor();
            },
            'A' => {
                const n = self.param(0, 1);
                self.row = if (self.row >= n) self.row - n else 0;
            },
            'B' => {
                const n = self.param(0, 1);
                self.row += n;
                self.clampCursor();
            },
            'C' => {
                const n = self.param(0, 1);
                self.col += n;
                self.clampCursor();
            },
            'D' => {
                const n = self.param(0, 1);
                self.col = if (self.col >= n) self.col - n else 0;
            },
            'G' => {
                self.col = clampDown(self.param(0, 1));
                self.clampCursor();
            },
            'd' => {
                self.row = clampDown(self.param(0, 1));
                self.clampCursor();
            },
            else => {},
        }
    }

    fn clampDown(v: usize) usize {
        return if (v > 0) v - 1 else 0;
    }

    fn clampCursor(self: *VtTrack) void {
        if (self.cols > 0 and self.col >= self.cols) self.col = self.cols - 1;
        if (self.rows > 0 and self.row >= self.rows) self.row = self.rows - 1;
    }

    fn setMode(self: *VtTrack, mode: usize, set: bool) void {
        switch (mode) {
            47, 1047, 1049 => self.alt_screen = set,
            1 => self.app_cursor_keys = set,
            2004 => self.bracketed_paste = set,
            1000, 1002, 1003, 1006 => self.mouse_tracking = set,
            else => {},
        }
    }
};

test "plain text advances col; CR/LF" {
    var t = VtTrack.init();
    t.feed("abc");
    try std.testing.expectEqual(@as(usize, 3), t.col);
    try std.testing.expectEqual(@as(usize, 0), t.row);
    t.feed("\r");
    try std.testing.expectEqual(@as(usize, 0), t.col);
    t.feed("\n");
    try std.testing.expectEqual(@as(usize, 1), t.row);
}

test "backspace" {
    var t = VtTrack.init();
    t.feed("ab");
    t.feed(&[_]u8{0x08});
    try std.testing.expectEqual(@as(usize, 1), t.col);
}

test "CUP sets row and col" {
    var t = VtTrack.init();
    t.feed("\x1b[5;10H");
    try std.testing.expectEqual(@as(usize, 4), t.row);
    try std.testing.expectEqual(@as(usize, 9), t.col);
}

test "cursor moves with and without params" {
    var t = VtTrack.init();
    t.feed("\x1b[10;10H");
    t.feed("\x1b[A");
    try std.testing.expectEqual(@as(usize, 8), t.row);
    t.feed("\x1b[3B");
    try std.testing.expectEqual(@as(usize, 11), t.row);
    t.feed("\x1b[2C");
    try std.testing.expectEqual(@as(usize, 11), t.col);
    t.feed("\x1b[D");
    try std.testing.expectEqual(@as(usize, 10), t.col);
}

test "CHA and VPA" {
    var t = VtTrack.init();
    t.feed("\x1b[15G");
    try std.testing.expectEqual(@as(usize, 14), t.col);
    t.feed("\x1b[7d");
    try std.testing.expectEqual(@as(usize, 6), t.row);
}

test "alt screen toggles predictionSafe" {
    var t = VtTrack.init();
    try std.testing.expect(t.predictionSafe());
    t.feed("\x1b[?1049h");
    try std.testing.expect(t.alt_screen);
    try std.testing.expect(!t.predictionSafe());
    t.feed("\x1b[?1049l");
    try std.testing.expect(!t.alt_screen);
    try std.testing.expect(t.predictionSafe());
}

test "bracketed paste and mouse toggle predictionSafe" {
    var t = VtTrack.init();
    t.feed("\x1b[?2004h");
    try std.testing.expect(!t.predictionSafe());
    t.feed("\x1b[?2004l");
    try std.testing.expect(t.predictionSafe());
    t.feed("\x1b[?1000h");
    try std.testing.expect(t.mouse_tracking);
    try std.testing.expect(!t.predictionSafe());
    t.feed("\x1b[?1000l");
    t.feed("\x1b[?1006h");
    try std.testing.expect(!t.predictionSafe());
}

test "DECCKM app cursor keys" {
    var t = VtTrack.init();
    t.feed("\x1b[?1h");
    try std.testing.expect(t.app_cursor_keys);
    try std.testing.expect(t.predictionSafe());
}

test "sequence split across feeds" {
    var t = VtTrack.init();
    t.feed("\x1b[");
    t.feed("5;10H");
    try std.testing.expectEqual(@as(usize, 4), t.row);
    try std.testing.expectEqual(@as(usize, 9), t.col);
}

test "OSC title is skipped" {
    var t = VtTrack.init();
    t.feed("ab");
    t.feed("\x1b]0;hello\x07");
    try std.testing.expectEqual(@as(usize, 2), t.col);
    try std.testing.expectEqual(@as(usize, 0), t.row);
}

test "OSC terminated by ST" {
    var t = VtTrack.init();
    t.feed("\x1b]2;title\x1b\\");
    t.feed("x");
    try std.testing.expectEqual(@as(usize, 1), t.col);
}

test "tmux-like alt screen lifecycle" {
    var t = VtTrack.init();
    try std.testing.expect(t.predictionSafe());
    t.feed("\x1b[?1049h");
    t.feed("\x1b[2;2Hdrawing");
    try std.testing.expect(!t.predictionSafe());
    t.feed("\x1b[?1049l");
    try std.testing.expect(t.predictionSafe());
}

test "wrap advances row" {
    var t = VtTrack.init();
    t.setSize(5, 24);
    t.feed("abcde");
    try std.testing.expectEqual(@as(usize, 0), t.col);
    try std.testing.expectEqual(@as(usize, 1), t.row);
}

test "utf8 lead advances once per codepoint" {
    var t = VtTrack.init();
    t.feed("\xC3\xA9");
    try std.testing.expectEqual(@as(usize, 1), t.col);
}
