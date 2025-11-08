// Cheat code representation

const std = @import("std");

/// Represents a cheat code pair (address and value)
pub const Code = struct {
    addr: u32,
    val: u32,

    /// Parse a code from hex string format "AAAAAAAA VVVVVVVV"
    pub fn fromHex(s: []const u8) !Code {
        var it = std.mem.splitScalar(u8, s, ' ');
        const addr_str = it.next() orelse return error.InvalidFormat;
        const val_str = it.next() orelse return error.InvalidFormat;
        return Code{
            .addr = try std.fmt.parseInt(u32, addr_str, 16),
            .val = try std.fmt.parseInt(u32, val_str, 16),
        };
    }
};
