const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exes = [_]struct { name: []const u8, src: []const u8 }{
        .{ .name = "msh", .src = "src/main_msh.zig" },
        .{ .name = "mshd", .src = "src/main_mshd.zig" },
    };

    for (exes) |e| {
        const mod = b.createModule(.{
            .root_source_file = b.path(e.src),
            .target = target,
            .optimize = optimize,
        });
        mod.link_libc = true;
        mod.linkSystemLibrary("libngtcp2", .{});
        mod.linkSystemLibrary("libngtcp2_crypto_ossl", .{});
        mod.linkSystemLibrary("openssl", .{});

        const exe = b.addExecutable(.{ .name = e.name, .root_module = mod });
        b.installArtifact(exe);
    }

    const test_step = b.step("test", "Run unit tests");
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.link_libc = true;
    test_mod.linkSystemLibrary("libngtcp2", .{});
    test_mod.linkSystemLibrary("libngtcp2_crypto_ossl", .{});
    test_mod.linkSystemLibrary("openssl", .{});
    const unit_tests = b.addTest(.{ .root_module = test_mod });
    const run_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_tests.step);
}
