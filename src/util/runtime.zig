const std = @import("std");

/// Process-wide runtime: a threaded `Io` implementation plus buffered stdout/stderr.
/// Zig 0.16 routes all IO (files, sockets, terminal) through the `std.Io` interface,
/// so every subsystem takes an `Io` from here rather than reaching for globals.
pub const Runtime = struct {
    gpa: std.mem.Allocator,
    threaded: std.Io.Threaded,
    stdout_writer: std.Io.File.Writer,
    stderr_writer: std.Io.File.Writer,

    pub fn init(rt: *Runtime, gpa: std.mem.Allocator, out_buf: []u8, err_buf: []u8) void {
        rt.* = .{
            .gpa = gpa,
            .threaded = std.Io.Threaded.init(gpa, .{}),
            .stdout_writer = undefined,
            .stderr_writer = undefined,
        };
        const rt_io = rt.threaded.io();
        rt.stdout_writer = std.Io.File.stdout().writer(rt_io, out_buf);
        rt.stderr_writer = std.Io.File.stderr().writer(rt_io, err_buf);
    }

    pub fn deinit(rt: *Runtime) void {
        rt.threaded.deinit();
    }

    pub fn io(rt: *Runtime) std.Io {
        return rt.threaded.io();
    }

    pub fn stdout(rt: *Runtime) *std.Io.Writer {
        return &rt.stdout_writer.interface;
    }

    pub fn stderr(rt: *Runtime) *std.Io.Writer {
        return &rt.stderr_writer.interface;
    }
};
