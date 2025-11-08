// Encrypt and decrypt cheat codes for all versions of CodeBreaker PS2.

const std = @import("std");
const testing = std.testing;

pub const cb1 = @import("cb1.zig");
pub const cb7 = @import("cb7.zig");
pub const rc4 = @import("rc4.zig");

const Cb7 = cb7.Cb7;
const isBeefcode = cb7.isBeefcode;

const Scheme = enum {
    raw,
    v1,
    v7,
};

/// A processor for CB v1 and v7 codes.
pub const Codebreaker = struct {
    scheme: Scheme,
    cb7_ctx: Cb7,
    code_lines: usize,
    allocator: std.mem.Allocator,

    /// Returns a new processor for encrypting and decrypting a list of CB v1
    /// and v7 codes.
    pub fn init(allocator: std.mem.Allocator) Codebreaker {
        return Codebreaker{
            .scheme = .raw,
            .cb7_ctx = Cb7.init(allocator),
            .code_lines = 0,
            .allocator = allocator,
        };
    }

    /// Returns a new processor for all CB v7 codes published on CMGSCCC.com.
    /// Lets you omit `B4336FA9 4DFEFB79` as the first code in the list.
    pub fn initV7(allocator: std.mem.Allocator) !Codebreaker {
        return Codebreaker{
            .scheme = .v7,
            .cb7_ctx = try Cb7.initDefault(allocator),
            .code_lines = 0,
            .allocator = allocator,
        };
    }

    /// Encrypts a code and returns the result.
    pub fn encryptCode(self: *Codebreaker, addr: u32, val: u32) !struct { u32, u32 } {
        var new_addr = addr;
        var new_val = val;
        try self.encryptCodeMut(&new_addr, &new_val);
        return .{ new_addr, new_val };
    }

    /// Encrypts a code directly.
    pub fn encryptCodeMut(self: *Codebreaker, addr: *u32, val: *u32) !void {
        const oldaddr = addr.*;
        const oldval = val.*;

        if (self.scheme == .v7) {
            try self.cb7_ctx.encryptCodeMut(addr, val);
        } else {
            cb1.encryptCodeMut(addr, val);
        }

        if (isBeefcode(oldaddr)) {
            try self.cb7_ctx.beefcode(oldaddr, oldval);
            self.scheme = .v7;
        }
    }

    /// Decrypts a code and returns the result.
    pub fn decryptCode(self: *Codebreaker, addr: u32, val: u32) !struct { u32, u32 } {
        var new_addr = addr;
        var new_val = val;
        try self.decryptCodeMut(&new_addr, &new_val);
        return .{ new_addr, new_val };
    }

    /// Decrypts a code directly.
    pub fn decryptCodeMut(self: *Codebreaker, addr: *u32, val: *u32) !void {
        if (self.scheme == .v7) {
            try self.cb7_ctx.decryptCodeMut(addr, val);
        } else {
            cb1.decryptCodeMut(addr, val);
        }

        if (isBeefcode(addr.*)) {
            try self.cb7_ctx.beefcode(addr.*, val.*);
            self.scheme = .v7;
        }
    }

    /// Smart version of `decryptCode` that detects if and how a code needs to be decrypted.
    pub fn autoDecryptCode(self: *Codebreaker, addr: u32, val: u32) !struct { u32, u32 } {
        var new_addr = addr;
        var new_val = val;
        try self.autoDecryptCodeMut(&new_addr, &new_val);
        return .{ new_addr, new_val };
    }

    /// Smart version of `decryptCodeMut` that detects if and how a code needs to be decrypted.
    pub fn autoDecryptCodeMut(self: *Codebreaker, addr: *u32, val: *u32) !void {
        if (self.scheme != .v7) {
            if (self.code_lines == 0) {
                self.code_lines = numCodeLines(addr.*);
                if ((addr.* >> 24) & 0x0e != 0) {
                    if (isBeefcode(addr.*)) {
                        // ignore raw beefcode
                        self.code_lines -= 1;
                        return;
                    }
                    self.scheme = .v1;
                    self.code_lines -= 1;
                    cb1.decryptCodeMut(addr, val);
                } else {
                    self.scheme = .raw;
                    self.code_lines -= 1;
                }
            } else {
                self.code_lines -= 1;
                if (self.scheme == .raw) {
                    return;
                }
                cb1.decryptCodeMut(addr, val);
            }
        } else {
            try self.cb7_ctx.decryptCodeMut(addr, val);
            if (self.code_lines == 0) {
                self.code_lines = numCodeLines(addr.*);
                if (self.code_lines == 1 and addr.* == 0xffff_ffff) {
                    // XXX: changing encryption via "FFFFFFFF 000xnnnn" is not supported
                    self.code_lines = 0;
                    return;
                }
            }
            self.code_lines -= 1;
        }

        if (isBeefcode(addr.*)) {
            try self.cb7_ctx.beefcode(addr.*, val.*);
            self.scheme = .v7;
            self.code_lines = 1;
        }
    }
};

fn numCodeLines(addr: u32) usize {
    const cmd = addr >> 28;

    if (cmd < 3 or cmd > 6) {
        return 1;
    } else if (cmd == 3) {
        return if (addr & 0x0040_0000 != 0) 2 else 1;
    } else {
        return 2;
    }
}

// Tests
const Code = struct {
    addr: u32,
    val: u32,

    fn fromHex(s: []const u8) !Code {
        var it = std.mem.splitScalar(u8, s, ' ');
        const addr_str = it.next() orelse return error.InvalidFormat;
        const val_str = it.next() orelse return error.InvalidFormat;
        return Code{
            .addr = try std.fmt.parseInt(u32, addr_str, 16),
            .val = try std.fmt.parseInt(u32, val_str, 16),
        };
    }

    fn eql(self: Code, other: Code) bool {
        return self.addr == other.addr and self.val == other.val;
    }
};

test "Codebreaker - encrypt code" {
    const decrypted = [_]Code{
        try Code.fromHex("2043AFCC 2411FFFF"),
        try Code.fromHex("BEEFC0DE 00000000"),
        try Code.fromHex("2096F5B8 000000BE"),
    };
    const encrypted = [_]Code{
        try Code.fromHex("2AFF014C 2411FFFF"),
        try Code.fromHex("B4336FA9 4DFEFB79"),
        try Code.fromHex("973E0B2A A7D4AF10"),
    };

    var cb = Codebreaker.init(testing.allocator);
    for (decrypted, encrypted) |dec, enc| {
        const result = try cb.encryptCode(dec.addr, dec.val);
        const result_code = Code{ .addr = result[0], .val = result[1] };
        try testing.expect(result_code.eql(enc));
    }
}

test "Codebreaker - encrypt code mut" {
    const decrypted = [_]Code{
        try Code.fromHex("2043AFCC 2411FFFF"),
        try Code.fromHex("BEEFC0DE 00000000"),
        try Code.fromHex("2096F5B8 000000BE"),
    };
    const encrypted = [_]Code{
        try Code.fromHex("2AFF014C 2411FFFF"),
        try Code.fromHex("B4336FA9 4DFEFB79"),
        try Code.fromHex("973E0B2A A7D4AF10"),
    };

    var cb = Codebreaker.init(testing.allocator);
    for (decrypted, encrypted) |dec, enc| {
        var addr = dec.addr;
        var val = dec.val;
        try cb.encryptCodeMut(&addr, &val);
        try testing.expectEqual(enc.addr, addr);
        try testing.expectEqual(enc.val, val);
    }
}

test "Codebreaker - decrypt code" {
    const decrypted = [_]Code{
        try Code.fromHex("2043AFCC 2411FFFF"),
        try Code.fromHex("BEEFC0DE 00000000"),
        try Code.fromHex("2096F5B8 000000BE"),
    };
    const encrypted = [_]Code{
        try Code.fromHex("2AFF014C 2411FFFF"),
        try Code.fromHex("B4336FA9 4DFEFB79"),
        try Code.fromHex("973E0B2A A7D4AF10"),
    };

    var cb = Codebreaker.init(testing.allocator);
    for (encrypted, decrypted) |enc, dec| {
        const result = try cb.decryptCode(enc.addr, enc.val);
        const result_code = Code{ .addr = result[0], .val = result[1] };
        try testing.expect(result_code.eql(dec));
    }
}

test "Codebreaker - decrypt code mut" {
    const decrypted = [_]Code{
        try Code.fromHex("2043AFCC 2411FFFF"),
        try Code.fromHex("BEEFC0DE 00000000"),
        try Code.fromHex("2096F5B8 000000BE"),
    };
    const encrypted = [_]Code{
        try Code.fromHex("2AFF014C 2411FFFF"),
        try Code.fromHex("B4336FA9 4DFEFB79"),
        try Code.fromHex("973E0B2A A7D4AF10"),
    };

    var cb = Codebreaker.init(testing.allocator);
    for (encrypted, decrypted) |enc, dec| {
        var addr = enc.addr;
        var val = enc.val;
        try cb.decryptCodeMut(&addr, &val);
        try testing.expectEqual(dec.addr, addr);
        try testing.expectEqual(dec.val, val);
    }
}

test "Codebreaker - auto decrypt code - raw" {
    const input = [_]Code{
        try Code.fromHex("9029BEAC 0C0A9225"),
        try Code.fromHex("201F6024 00000000"),
        try Code.fromHex("2096F5B8 000000BE"),
    };
    const output = [_]Code{
        try Code.fromHex("9029BEAC 0C0A9225"),
        try Code.fromHex("201F6024 00000000"),
        try Code.fromHex("2096F5B8 000000BE"),
    };

    var cb = Codebreaker.init(testing.allocator);
    for (input, output) |inp, out| {
        const result = try cb.autoDecryptCode(inp.addr, inp.val);
        const result_code = Code{ .addr = result[0], .val = result[1] };
        try testing.expect(result_code.eql(out));
    }
}

test "Codebreaker - auto decrypt code - v1 encrypted" {
    const input = [_]Code{
        try Code.fromHex("9A545CC6 188CBCFB"),
        try Code.fromHex("2A973DBD 00000000"),
        try Code.fromHex("2A03B60A 000000BE"),
    };
    const output = [_]Code{
        try Code.fromHex("9029BEAC 0C0A9225"),
        try Code.fromHex("201F6024 00000000"),
        try Code.fromHex("2096F5B8 000000BE"),
    };

    var cb = Codebreaker.init(testing.allocator);
    for (input, output) |inp, out| {
        const result = try cb.autoDecryptCode(inp.addr, inp.val);
        const result_code = Code{ .addr = result[0], .val = result[1] };
        try testing.expect(result_code.eql(out));
    }
}

test "Codebreaker - auto decrypt code - v7 encrypted" {
    const input = [_]Code{
        try Code.fromHex("B4336FA9 4DFEFB79"),
        try Code.fromHex("D08F3A49 00078A53"),
        try Code.fromHex("3818DDE5 E72B2B16"),
        try Code.fromHex("973E0B2A A7D4AF10"),
    };
    const output = [_]Code{
        try Code.fromHex("BEEFC0DE 00000000"),
        try Code.fromHex("9029BEAC 0C0A9225"),
        try Code.fromHex("201F6024 00000000"),
        try Code.fromHex("2096F5B8 000000BE"),
    };

    var cb = Codebreaker.init(testing.allocator);
    for (input, output) |inp, out| {
        const result = try cb.autoDecryptCode(inp.addr, inp.val);
        const result_code = Code{ .addr = result[0], .val = result[1] };
        try testing.expect(result_code.eql(out));
    }
}

test "Codebreaker - auto decrypt code - v1 and v7 encrypted" {
    const input = [_]Code{
        try Code.fromHex("9A545CC6 188CBCFB"),
        try Code.fromHex("2A973DBD 00000000"),
        try Code.fromHex("B4336FA9 4DFEFB79"),
        try Code.fromHex("973E0B2A A7D4AF10"),
    };
    const output = [_]Code{
        try Code.fromHex("9029BEAC 0C0A9225"),
        try Code.fromHex("201F6024 00000000"),
        try Code.fromHex("BEEFC0DE 00000000"),
        try Code.fromHex("2096F5B8 000000BE"),
    };

    var cb = Codebreaker.init(testing.allocator);
    for (input, output) |inp, out| {
        const result = try cb.autoDecryptCode(inp.addr, inp.val);
        const result_code = Code{ .addr = result[0], .val = result[1] };
        try testing.expect(result_code.eql(out));
    }
}

test "Codebreaker - auto decrypt code - raw, v1, and v7 encrypted" {
    const input = [_]Code{
        try Code.fromHex("9029BEAC 0C0A9225"),
        try Code.fromHex("2A973DBD 00000000"),
        try Code.fromHex("B4336FA9 4DFEFB79"),
        try Code.fromHex("973E0B2A A7D4AF10"),
    };
    const output = [_]Code{
        try Code.fromHex("9029BEAC 0C0A9225"),
        try Code.fromHex("201F6024 00000000"),
        try Code.fromHex("BEEFC0DE 00000000"),
        try Code.fromHex("2096F5B8 000000BE"),
    };

    var cb = Codebreaker.init(testing.allocator);
    for (input, output) |inp, out| {
        const result = try cb.autoDecryptCode(inp.addr, inp.val);
        const result_code = Code{ .addr = result[0], .val = result[1] };
        try testing.expect(result_code.eql(out));
    }
}

test "Codebreaker v7 - encrypt code" {
    const decrypted = [_]Code{
        try Code.fromHex("9029BEAC 0C0A9225"),
        try Code.fromHex("201F6024 00000000"),
        try Code.fromHex("2096F5B8 000000BE"),
    };
    const encrypted = [_]Code{
        try Code.fromHex("D08F3A49 00078A53"),
        try Code.fromHex("3818DDE5 E72B2B16"),
        try Code.fromHex("973E0B2A A7D4AF10"),
    };

    var cb = try Codebreaker.initV7(testing.allocator);
    for (decrypted, encrypted) |dec, enc| {
        const result = try cb.encryptCode(dec.addr, dec.val);
        const result_code = Code{ .addr = result[0], .val = result[1] };
        try testing.expect(result_code.eql(enc));
    }
}

test "Codebreaker v7 - decrypt code" {
    const decrypted = [_]Code{
        try Code.fromHex("9029BEAC 0C0A9225"),
        try Code.fromHex("201F6024 00000000"),
        try Code.fromHex("2096F5B8 000000BE"),
    };
    const encrypted = [_]Code{
        try Code.fromHex("D08F3A49 00078A53"),
        try Code.fromHex("3818DDE5 E72B2B16"),
        try Code.fromHex("973E0B2A A7D4AF10"),
    };

    var cb = try Codebreaker.initV7(testing.allocator);
    for (encrypted, decrypted) |enc, dec| {
        const result = try cb.decryptCode(enc.addr, enc.val);
        const result_code = Code{ .addr = result[0], .val = result[1] };
        try testing.expect(result_code.eql(dec));
    }
}
