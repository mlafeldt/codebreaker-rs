// Implementation of the stream cipher RC4

const std = @import("std");
const testing = std.testing;

pub const Rc4 = struct {
    i: u8,
    j: u8,
    state: [256]u8,

    pub fn init(key: []const u8) Rc4 {
        std.debug.assert(key.len > 0 and key.len <= 256);

        var state: [256]u8 = undefined;
        for (&state, 0..) |*s, idx| {
            s.* = @intCast(idx);
        }

        var j: u8 = 0;
        for (0..256) |i| {
            j = j +% state[i] +% key[i % key.len];
            std.mem.swap(u8, &state[i], &state[j]);
        }

        return Rc4{
            .i = 0,
            .j = 0,
            .state = state,
        };
    }

    pub fn crypt(self: *Rc4, buf: []u8) void {
        for (buf) |*b| {
            self.i +%= 1;
            self.j +%= self.state[self.i];
            std.mem.swap(u8, &self.state[self.i], &self.state[self.j]);
            const k = self.state[self.i] +% self.state[self.j];
            b.* ^= self.state[k];
        }
    }
};

test "RC4 - Wikipedia test vectors" {
    const TestCase = struct {
        key: []const u8,
        input: []const u8,
        output: []const u8,
    };

    const test_cases = [_]TestCase{
        .{
            .key = "Key",
            .input = "Plaintext",
            .output = &[_]u8{ 0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3 },
        },
        .{
            .key = "Wiki",
            .input = "pedia",
            .output = &[_]u8{ 0x10, 0x21, 0xbf, 0x04, 0x20 },
        },
        .{
            .key = "Secret",
            .input = "Attack at dawn",
            .output = &[_]u8{ 0x45, 0xa0, 0x1f, 0x64, 0x5f, 0xc3, 0x5b, 0x38, 0x35, 0x52, 0x54, 0x4b, 0x9b, 0xf5 },
        },
    };

    for (test_cases) |tc| {
        var rc4 = Rc4.init(tc.key);
        const buf = try testing.allocator.alloc(u8, tc.input.len);
        defer testing.allocator.free(buf);

        @memcpy(buf, tc.input);
        rc4.crypt(buf);

        try testing.expectEqualSlices(u8, tc.output, buf);
    }
}
