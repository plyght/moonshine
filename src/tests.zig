const std = @import("std");

test {
    _ = @import("proto/version.zig");
    _ = @import("proto/frames.zig");
    _ = @import("term/vt_track.zig");
    _ = @import("term/predict.zig");
    _ = @import("pty/pty.zig");
    _ = @import("transport/quic.zig");
    _ = @import("transport/e2e_test.zig");
    _ = @import("transport/roaming_test.zig");
    _ = @import("transport/resume_test.zig");
    _ = @import("auth/bootstrap.zig");
    _ = @import("auth/sshkeys.zig");
    _ = @import("auth/tofu.zig");
    _ = @import("transport/keyauth_test.zig");
}
