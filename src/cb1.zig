// Encrypt and decrypt cheat codes for CodeBreaker PS2 v1 - v6

const std = @import("std");
const testing = std.testing;

pub const Code = @import("code.zig").Code;

const SEEDS = [3][16]u32{
    [16]u32{
        0x0a0b_8d9b, 0x0a01_33f8, 0x0af7_33ec, 0x0a15_c574,
        0x0a50_ac20, 0x0a92_0fb9, 0x0a59_9f0b, 0x0a4a_a0e3,
        0x0a21_c012, 0x0a90_6254, 0x0a31_fd54, 0x0a09_1c0e,
        0x0a37_2b38, 0x0a6f_266c, 0x0a61_dd4a, 0x0a0d_bf92,
    },
    [16]u32{
        0x0028_8596, 0x0037_dd28, 0x003b_eef1, 0x000b_c822,
        0x00bc_935d, 0x00a1_39f2, 0x00e9_bbf8, 0x00f5_7f7b,
        0x0090_d704, 0x0018_14d4, 0x00c5_848e, 0x005b_83e7,
        0x0010_8cf7, 0x0046_ce5a, 0x003a_5bf4, 0x006f_affc,
    },
    [16]u32{
        0x1dd9_a10a, 0xb95a_b9b0, 0x5cf5_d328, 0x95fe_7f10,
        0x8e2d_6303, 0x16bb_6286, 0xe389_324c, 0x07ac_6ea8,
        0xaa48_11d8, 0x76ce_4e18, 0xfe44_7516, 0xf9cd_94d0,
        0x4c24_dedb, 0x6827_5c4e, 0x7249_4382, 0xc8aa_88e8,
    },
};

/// Encrypts a code and returns the result.
pub fn encryptCode(addr: u32, val: u32) Code {
    const cmd: usize = @intCast(addr >> 28);
    const tmp = addr & 0xff00_0000;
    var new_addr = ((addr & 0xff) << 16) | ((addr >> 8) & 0xffff);
    new_addr = (tmp | ((new_addr +% SEEDS[1][cmd]) & 0x00ff_ffff)) ^ SEEDS[0][cmd];

    var new_val = val;
    if (cmd > 2) {
        new_val = new_addr ^ (val +% SEEDS[2][cmd]);
    }

    return .{ .addr = new_addr, .val = new_val };
}

/// Encrypts a code directly.
pub fn encryptCodeMut(addr: *u32, val: *u32) void {
    const result = encryptCode(addr.*, val.*);
    addr.* = result.addr;
    val.* = result.val;
}

/// Decrypts a code and returns the result.
pub fn decryptCode(addr: u32, val: u32) Code {
    const cmd: usize = @intCast(addr >> 28);

    var new_val = val;
    if (cmd > 2) {
        new_val = (addr ^ val) -% SEEDS[2][cmd];
    }

    const tmp = addr ^ SEEDS[0][cmd];
    var new_addr = tmp -% SEEDS[1][cmd];
    new_addr = (tmp & 0xff00_0000) | ((new_addr & 0xffff) << 8) | ((new_addr >> 16) & 0xff);

    return .{ .addr = new_addr, .val = new_val };
}

/// Decrypts a code directly.
pub fn decryptCodeMut(addr: *u32, val: *u32) void {
    const result = decryptCode(addr.*, val.*);
    addr.* = result.addr;
    val.* = result.val;
}

// Tests

test "CB1 - encrypt code" {
    const TestCase = struct {
        decrypted: Code,
        encrypted: Code,
    };

    const test_cases = [_]TestCase{
        .{
            .decrypted = try Code.fromHex("0031789A 00000063"),
            .encrypted = try Code.fromHex("0AC93A95 00000063"),
        },
        .{
            .decrypted = try Code.fromHex("1031A028 0000FFFF"),
            .encrypted = try Code.fromHex("1A613D30 0000FFFF"),
        },
        .{
            .decrypted = try Code.fromHex("201F6024 00000000"),
            .encrypted = try Code.fromHex("2A973DBD 00000000"),
        },
        .{
            .decrypted = try Code.fromHex("902DB32C 0C0BAFF1"),
            .encrypted = try Code.fromHex("9AD420D3 180DDEDA"),
        },
        .{
            .decrypted = try Code.fromHex("A008060C 08028007"),
            .encrypted = try Code.fromHex("AAE071C0 ACA684DD"),
        },
        .{
            .decrypted = try Code.fromHex("BEEFC0DE 00000000"),
            .encrypted = try Code.fromHex("B4336FA9 4DFEFB79"),
        },
    };

    for (test_cases) |tc| {
        const result = encryptCode(tc.decrypted.addr, tc.decrypted.val);
        try testing.expectEqual(tc.encrypted, result);
    }
}

test "CB1 - encrypt code mut" {
    const TestCase = struct {
        decrypted: Code,
        encrypted: Code,
    };

    const test_cases = [_]TestCase{
        .{
            .decrypted = try Code.fromHex("0031789A 00000063"),
            .encrypted = try Code.fromHex("0AC93A95 00000063"),
        },
        .{
            .decrypted = try Code.fromHex("201F6024 00000000"),
            .encrypted = try Code.fromHex("2A973DBD 00000000"),
        },
    };

    for (test_cases) |tc| {
        var addr = tc.decrypted.addr;
        var val = tc.decrypted.val;
        encryptCodeMut(&addr, &val);
        try testing.expectEqual(tc.encrypted.addr, addr);
        try testing.expectEqual(tc.encrypted.val, val);
    }
}

test "CB1 - decrypt code" {
    const TestCase = struct {
        decrypted: Code,
        encrypted: Code,
    };

    const test_cases = [_]TestCase{
        .{
            .decrypted = try Code.fromHex("0031789A 00000063"),
            .encrypted = try Code.fromHex("0AC93A95 00000063"),
        },
        .{
            .decrypted = try Code.fromHex("1031A028 0000FFFF"),
            .encrypted = try Code.fromHex("1A613D30 0000FFFF"),
        },
        .{
            .decrypted = try Code.fromHex("201F6024 00000000"),
            .encrypted = try Code.fromHex("2A973DBD 00000000"),
        },
        .{
            .decrypted = try Code.fromHex("902DB32C 0C0BAFF1"),
            .encrypted = try Code.fromHex("9AD420D3 180DDEDA"),
        },
        .{
            .decrypted = try Code.fromHex("A008060C 08028007"),
            .encrypted = try Code.fromHex("AAE071C0 ACA684DD"),
        },
        .{
            .decrypted = try Code.fromHex("BEEFC0DE 00000000"),
            .encrypted = try Code.fromHex("B4336FA9 4DFEFB79"),
        },
    };

    for (test_cases) |tc| {
        const result = decryptCode(tc.encrypted.addr, tc.encrypted.val);
        try testing.expectEqual(tc.decrypted, result);
    }
}

test "CB1 - decrypt code mut" {
    const TestCase = struct {
        decrypted: Code,
        encrypted: Code,
    };

    const test_cases = [_]TestCase{
        .{
            .decrypted = try Code.fromHex("0031789A 00000063"),
            .encrypted = try Code.fromHex("0AC93A95 00000063"),
        },
        .{
            .decrypted = try Code.fromHex("201F6024 00000000"),
            .encrypted = try Code.fromHex("2A973DBD 00000000"),
        },
    };

    for (test_cases) |tc| {
        var addr = tc.encrypted.addr;
        var val = tc.encrypted.val;
        decryptCodeMut(&addr, &val);
        try testing.expectEqual(tc.decrypted.addr, addr);
        try testing.expectEqual(tc.decrypted.val, val);
    }
}
