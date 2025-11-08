// Cheat code representation

const std = @import("std");

/// Represents a cheat code pair (address and value)
pub const Code = struct {
    addr: u32,
    val: u32,

    pub const ParseError = error{
        InvalidFormat,
        InvalidCharacter,
        Overflow,
    };

    /// Parse a code from hex string format "AAAAAAAA VVVVVVVV"
    pub fn parse(s: []const u8) ParseError!Code {
        var it = std.mem.splitScalar(u8, s, ' ');
        const addr_str = it.next() orelse return error.InvalidFormat;
        const val_str = it.next() orelse return error.InvalidFormat;

        const addr = std.fmt.parseInt(u32, addr_str, 16) catch |err| switch (err) {
            error.InvalidCharacter => return error.InvalidCharacter,
            error.Overflow => return error.Overflow,
        };
        const val = std.fmt.parseInt(u32, val_str, 16) catch |err| switch (err) {
            error.InvalidCharacter => return error.InvalidCharacter,
            error.Overflow => return error.Overflow,
        };

        return Code{ .addr = addr, .val = val };
    }

    /// Format a code as hex string "AAAAAAAA VVVVVVVV"
    pub fn format(
        self: Code,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(writer, "{X:0>8} {X:0>8}", .{ self.addr, self.val });
    }
};
