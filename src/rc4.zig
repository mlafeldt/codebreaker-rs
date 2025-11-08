const std = @import("std");

pub const Rc4 = struct {
    i: u8,
    j: u8,
    state: [256]u8,

    pub fn init(key: []const u8) Rc4 {
        std.debug.assert(key.len > 0 and key.len <= 256);

        var state: [256]u8 = undefined;
        for (state[0..], 0..) |*slot, idx| {
            slot.* = @intCast(idx);
        }

        var j: u8 = 0;
        for (0..256) |idx_usize| {
            const idx = idx_usize;
            j +%= state[idx];
            j +%= key[idx % key.len];
            const j_idx = @as(usize, @intCast(j));
            std.mem.swap(u8, &state[idx], &state[j_idx]);
        }

        return .{ .i = 0, .j = 0, .state = state };
    }

    pub fn crypt(self: *Rc4, buf: []u8) void {
        for (buf) |*byte| {
            self.i +%= 1;
            const i_idx = @as(usize, @intCast(self.i));
            self.j +%= self.state[i_idx];
            const j_idx = @as(usize, @intCast(self.j));
            std.mem.swap(u8, &self.state[i_idx], &self.state[j_idx]);
            const idx = self.state[i_idx] +% self.state[j_idx];
            byte.* ^= self.state[@as(usize, @intCast(idx))];
        }
    }
};

test "rc4 wikipedia vectors" {
    const vectors = [_]struct {
        key: []const u8,
        input: []const u8,
        output: []const u8,
    }{
        .{ .key = "Key", .input = "Plaintext", .output = &[_]u8{ 0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3 } },
        .{ .key = "Wiki", .input = "pedia", .output = &[_]u8{ 0x10, 0x21, 0xbf, 0x04, 0x20 } },
        .{
            .key = "Secret",
            .input = "Attack at dawn",
            .output = &[_]u8{ 0x45, 0xa0, 0x1f, 0x64, 0x5f, 0xc3, 0x5b, 0x38, 0x35, 0x52, 0x54, 0x4b, 0x9b, 0xf5 },
        },
    };

    for (vectors) |vec| {
        var cipher = Rc4.init(vec.key);
        var buf: [16]u8 = undefined;
        const len = vec.input.len;
        @memcpy(buf[0..len], vec.input);
        cipher.crypt(buf[0..len]);
        try std.testing.expectEqualSlices(u8, vec.output, buf[0..len]);
    }
}
