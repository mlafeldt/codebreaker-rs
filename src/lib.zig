const std = @import("std");

pub const cb1 = @import("cb1.zig");
pub const cb7 = @import("cb7.zig");
pub const rc4 = @import("rc4.zig");

const Scheme = enum { raw, v1, v7 };

pub const Codebreaker = struct {
    scheme: Scheme,
    cb7_state: cb7.Cb7,
    code_lines: usize,

    pub fn init() Codebreaker {
        return .{
            .scheme = .raw,
            .cb7_state = cb7.Cb7.init(),
            .code_lines = 0,
        };
    }

    pub fn initV7() Codebreaker {
        return .{
            .scheme = .v7,
            .cb7_state = cb7.Cb7.initDefault(),
            .code_lines = 0,
        };
    }

    pub fn encryptCode(self: *Codebreaker, addr: u32, val: u32) [2]u32 {
        var code = [2]u32{ addr, val };
        self.encryptCodeMut(&code[0], &code[1]);
        return code;
    }

    pub fn encryptCodeMut(self: *Codebreaker, addr: *u32, val: *u32) void {
        const oldaddr = addr.*;
        const oldval = val.*;

        if (self.scheme == .v7) {
            self.cb7_state.encryptCodeMut(addr, val);
        } else {
            cb1.encryptCodeMut(addr, val);
        }

        if (cb7.isBeefcode(oldaddr)) {
            self.cb7_state.beefcode(oldaddr, oldval);
            self.scheme = .v7;
        }
    }

    pub fn decryptCode(self: *Codebreaker, addr: u32, val: u32) [2]u32 {
        var code = [2]u32{ addr, val };
        self.decryptCodeMut(&code[0], &code[1]);
        return code;
    }

    pub fn decryptCodeMut(self: *Codebreaker, addr: *u32, val: *u32) void {
        if (self.scheme == .v7) {
            self.cb7_state.decryptCodeMut(addr, val);
        } else {
            cb1.decryptCodeMut(addr, val);
        }

        if (cb7.isBeefcode(addr.*)) {
            self.cb7_state.beefcode(addr.*, val.*);
            self.scheme = .v7;
        }
    }

    pub fn autoDecryptCode(self: *Codebreaker, addr: u32, val: u32) [2]u32 {
        var code = [2]u32{ addr, val };
        self.autoDecryptCodeMut(&code[0], &code[1]);
        return code;
    }

    pub fn autoDecryptCodeMut(self: *Codebreaker, addr: *u32, val: *u32) void {
        if (self.scheme != .v7) {
            if (self.code_lines == 0) {
                self.code_lines = numCodeLines(addr.*);
                if ((addr.* >> 24) & 0x0e != 0) {
                    if (cb7.isBeefcode(addr.*)) {
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
            self.cb7_state.decryptCodeMut(addr, val);
            if (self.code_lines == 0) {
                self.code_lines = numCodeLines(addr.*);
                if (self.code_lines == 1 and addr.* == 0xffff_ffff) {
                    self.code_lines = 0;
                    return;
                }
            }
            self.code_lines -= 1;
        }

        if (cb7.isBeefcode(addr.*)) {
            self.cb7_state.beefcode(addr.*, val.*);
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

const TestBuilder = enum { new, new_v7, default };

fn makeTestCb(builder: TestBuilder) Codebreaker {
    return switch (builder) {
        .new => Codebreaker.init(),
        .new_v7 => Codebreaker.initV7(),
        .default => Codebreaker.init(),
    };
}

test "codebreaker encrypt/decrypt" {
    const tests = [_]struct {
        builder: TestBuilder,
        decrypted: []const [2]u32,
        encrypted: []const [2]u32,
    }{
        .{
            .builder = .new,
            .decrypted = &[_][2]u32{
                .{ 0x2043_afcc, 0x2411_ffff },
                .{ 0xbeef_c0de, 0x0000_0000 },
                .{ 0x2096_f5b8, 0x0000_00be },
            },
            .encrypted = &[_][2]u32{
                .{ 0x2aff_014c, 0x2411_ffff },
                .{ 0xb433_6fa9, 0x4dfe_fb79 },
                .{ 0x973e_0b2a, 0xa7d4_af10 },
            },
        },
        .{
            .builder = .new_v7,
            .decrypted = &[_][2]u32{
                .{ 0x9029_beac, 0x0c0a_9225 },
                .{ 0x201f_6024, 0x0000_0000 },
                .{ 0x2096_f5b8, 0x0000_00be },
            },
            .encrypted = &[_][2]u32{
                .{ 0xd08f_3a49, 0x0007_8a53 },
                .{ 0x3818_dde5, 0xe72b_2b16 },
                .{ 0x973e_0b2a, 0xa7d4_af10 },
            },
        },
        .{
            .builder = .default,
            .decrypted = &[_][2]u32{
                .{ 0x9029_beac, 0x0c0a_9225 },
                .{ 0x201f_6024, 0x0000_0000 },
                .{ 0x2096_f5b8, 0x0000_00be },
            },
            .encrypted = &[_][2]u32{
                .{ 0x9a54_5cc6, 0x188c_bcfb },
                .{ 0x2a97_3dbd, 0x0000_0000 },
                .{ 0x2a03_b60a, 0x0000_00be },
            },
        },
    };

    inline for (tests) |case| {
        var cb = makeTestCb(case.builder);
        for (case.decrypted, 0..) |code, idx| {
            const enc = cb.encryptCode(code[0], code[1]);
            try std.testing.expectEqual(case.encrypted[idx], enc);
        }

        cb = makeTestCb(case.builder);
        for (case.decrypted, 0..) |code, idx| {
            var mut = code;
            cb.encryptCodeMut(&mut[0], &mut[1]);
            try std.testing.expectEqual(case.encrypted[idx], mut);
        }

        cb = makeTestCb(case.builder);
        for (case.encrypted, 0..) |code, idx| {
            const dec = cb.decryptCode(code[0], code[1]);
            try std.testing.expectEqual(case.decrypted[idx], dec);
        }

        cb = makeTestCb(case.builder);
        for (case.encrypted, 0..) |code, idx| {
            var mut = code;
            cb.decryptCodeMut(&mut[0], &mut[1]);
            try std.testing.expectEqual(case.decrypted[idx], mut);
        }
    }
}

test "codebreaker auto decrypt" {
    const auto_tests = [_]struct {
        input: []const [2]u32,
        output: []const [2]u32,
    }{
        .{
            .input = &[_][2]u32{
                .{ 0x9029_beac, 0x0c0a_9225 },
                .{ 0x201f_6024, 0x0000_0000 },
                .{ 0x2096_f5b8, 0x0000_00be },
            },
            .output = &[_][2]u32{
                .{ 0x9029_beac, 0x0c0a_9225 },
                .{ 0x201f_6024, 0x0000_0000 },
                .{ 0x2096_f5b8, 0x0000_00be },
            },
        },
        .{
            .input = &[_][2]u32{
                .{ 0x9a54_5cc6, 0x188c_bcfb },
                .{ 0x2a97_3dbd, 0x0000_0000 },
                .{ 0x2a03_b60a, 0x0000_00be },
            },
            .output = &[_][2]u32{
                .{ 0x9029_beac, 0x0c0a_9225 },
                .{ 0x201f_6024, 0x0000_0000 },
                .{ 0x2096_f5b8, 0x0000_00be },
            },
        },
        .{
            .input = &[_][2]u32{
                .{ 0xb433_6fa9, 0x4dfe_fb79 },
                .{ 0xd08f_3a49, 0x0007_8a53 },
                .{ 0x3818_dde5, 0xe72b_2b16 },
                .{ 0x973e_0b2a, 0xa7d4_af10 },
            },
            .output = &[_][2]u32{
                .{ 0xbeef_c0de, 0x0000_0000 },
                .{ 0x9029_beac, 0x0c0a_9225 },
                .{ 0x201f_6024, 0x0000_0000 },
                .{ 0x2096_f5b8, 0x0000_00be },
            },
        },
        .{
            .input = &[_][2]u32{
                .{ 0x9a54_5cc6, 0x188c_bcfb },
                .{ 0x2a97_3dbd, 0x0000_0000 },
                .{ 0xb433_6fa9, 0x4dfe_fb79 },
                .{ 0x973e_0b2a, 0xa7d4_af10 },
            },
            .output = &[_][2]u32{
                .{ 0x9029_beac, 0x0c0a_9225 },
                .{ 0x201f_6024, 0x0000_0000 },
                .{ 0xbeef_c0de, 0x0000_0000 },
                .{ 0x2096_f5b8, 0x0000_00be },
            },
        },
        .{
            .input = &[_][2]u32{
                .{ 0x9029_beac, 0x0c0a_9225 },
                .{ 0x2a97_3dbd, 0x0000_0000 },
                .{ 0xb433_6fa9, 0x4dfe_fb79 },
                .{ 0x973e_0b2a, 0xa7d4_af10 },
            },
            .output = &[_][2]u32{
                .{ 0x9029_beac, 0x0c0a_9225 },
                .{ 0x201f_6024, 0x0000_0000 },
                .{ 0xbeef_c0de, 0x0000_0000 },
                .{ 0x2096_f5b8, 0x0000_00be },
            },
        },
    };

    for (auto_tests) |case| {
        var cb = Codebreaker.init();
        for (case.input, 0..) |code, idx| {
            const result = cb.autoDecryptCode(code[0], code[1]);
            try std.testing.expectEqual(case.output[idx], result);
        }

        cb = Codebreaker.init();
        var buf: [8][2]u32 = undefined;
        var len: usize = 0;
        for (case.input) |code| {
            buf[len] = code;
            len += 1;
        }

        for (buf[0..len], 0..) |*code, idx| {
            cb.autoDecryptCodeMut(&code.*[0], &code.*[1]);
            try std.testing.expectEqual(case.output[idx], code.*);
        }
    }
}
