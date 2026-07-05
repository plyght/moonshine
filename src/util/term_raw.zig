const std = @import("std");

const c = @cImport({
    @cInclude("termios.h");
    @cInclude("unistd.h");
    @cInclude("errno.h");
});

pub const Saved = c.struct_termios;

pub const Error = error{
    TcGetAttrFailed,
    TcSetAttrFailed,
};

fn errno() c_int {
    return c.__error().*;
}

pub fn enableRaw(fd: c_int) Error!?Saved {
    var saved: Saved = undefined;
    if (c.tcgetattr(fd, &saved) != 0) {
        if (errno() == c.ENOTTY) return null;
        return Error.TcGetAttrFailed;
    }
    var raw = saved;
    raw.c_iflag &= ~@as(c.tcflag_t, c.BRKINT | c.ICRNL | c.INPCK | c.ISTRIP | c.IXON | c.IGNBRK | c.PARMRK);
    raw.c_oflag &= ~@as(c.tcflag_t, c.OPOST);
    raw.c_lflag &= ~@as(c.tcflag_t, c.ECHO | c.ICANON | c.IEXTEN | c.ISIG);
    raw.c_cflag &= ~@as(c.tcflag_t, c.CSIZE | c.PARENB);
    raw.c_cflag |= @as(c.tcflag_t, c.CS8);
    raw.c_cc[c.VMIN] = 1;
    raw.c_cc[c.VTIME] = 0;
    if (c.tcsetattr(fd, c.TCSAFLUSH, &raw) != 0) return Error.TcSetAttrFailed;
    return saved;
}

pub fn restore(fd: c_int, saved: Saved) void {
    var s = saved;
    _ = c.tcsetattr(fd, c.TCSAFLUSH, &s);
}
