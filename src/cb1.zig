const std = @import("std");

pub fn encryptCode(addr: u32, val: u32) [2]u32 {
    var a = addr;
    var v = val;
    encryptCodeMut(&a, &v);
    return .{ a, v };
}

pub fn encryptCodeMut(addr: *u32, val: *u32) void {
    const cmd = @as(usize, @intCast(addr.* >> 28));
    const tmp = addr.* & 0xff00_0000;
    addr.* = ((addr.* & 0xff) << 16) | ((addr.* >> 8) & 0xffff);
    addr.* = (tmp | ((addr.* +% SEEDS[1][cmd]) & 0x00ff_ffff)) ^ SEEDS[0][cmd];
    if (cmd > 2) {
        val.* = addr.* ^ (val.* +% SEEDS[2][cmd]);
    }
}

pub fn decryptCode(addr: u32, val: u32) [2]u32 {
    var a = addr;
    var v = val;
    decryptCodeMut(&a, &v);
    return .{ a, v };
}

pub fn decryptCodeMut(addr: *u32, val: *u32) void {
    const cmd = @as(usize, @intCast(addr.* >> 28));
    if (cmd > 2) {
        val.* = (addr.* ^ val.*) -% SEEDS[2][cmd];
    }
    const tmp = addr.* ^ SEEDS[0][cmd];
    addr.* = tmp -% SEEDS[1][cmd];
    addr.* = (tmp & 0xff00_0000) | ((addr.* & 0xffff) << 8) | ((addr.* >> 16) & 0xff);
}

const SEEDS = [_][16]u32{
    [_]u32{
        0x0a0b_8d9b, 0x0a01_33f8, 0x0af7_33ec, 0x0a15_c574,
        0x0a50_ac20, 0x0a92_0fb9, 0x0a59_9f0b, 0x0a4a_a0e3,
        0x0a21_c012, 0x0a90_6254, 0x0a31_fd54, 0x0a09_1c0e,
        0x0a37_2b38, 0x0a6f_266c, 0x0a61_dd4a, 0x0a0d_bf92,
    },
    [_]u32{
        0x0028_8596, 0x0037_dd28, 0x003b_eef1, 0x000b_c822,
        0x00bc_935d, 0x00a1_39f2, 0x00e9_bbf8, 0x00f5_7f7b,
        0x0090_d704, 0x0018_14d4, 0x00c5_848e, 0x005b_83e7,
        0x0010_8cf7, 0x0046_ce5a, 0x003a_5bf4, 0x006f_affc,
    },
    [_]u32{
        0x1dd9_a10a, 0xb95a_b9b0, 0x5cf5_d328, 0x95fe_7f10,
        0x8e2d_6303, 0x16bb_6286, 0xe389_324c, 0x07ac_6ea8,
        0xaa48_11d8, 0x76ce_4e18, 0xfe44_7516, 0xf9cd_94d0,
        0x4c24_dedb, 0x6827_5c4e, 0x7249_4382, 0xc8aa_88e8,
    },
};

test "cb1 encrypt/decrypt vectors" {
    const Test = struct {
        decrypted: [2]u32,
        encrypted: [2]u32,
    };

    const tests = [_]Test{
        .{ .decrypted = .{ 0x0031_789a, 0x0000_0063 }, .encrypted = .{ 0x0ac9_3a95, 0x0000_0063 } },
        .{ .decrypted = .{ 0x1031_a028, 0x0000_ffff }, .encrypted = .{ 0x1a61_3d30, 0x0000_ffff } },
        .{ .decrypted = .{ 0x201f_6024, 0x0000_0000 }, .encrypted = .{ 0x2a97_3dbd, 0x0000_0000 } },
        .{ .decrypted = .{ 0x902d_b32c, 0x0c0b_aff1 }, .encrypted = .{ 0x9ad4_20d3, 0x180d_deda } },
        .{ .decrypted = .{ 0xa008_060c, 0x0802_8007 }, .encrypted = .{ 0xaae0_71c0, 0xaca6_84dd } },
        .{ .decrypted = .{ 0xbeef_c0de, 0x0000_0000 }, .encrypted = .{ 0xb433_6fa9, 0x4dfe_fb79 } },
    };

    for (tests) |case| {
        var tmp = encryptCode(case.decrypted[0], case.decrypted[1]);
        try std.testing.expectEqualSlices(u32, case.encrypted[0..], tmp[0..]);

        var a = case.decrypted[0];
        var v = case.decrypted[1];
        encryptCodeMut(&a, &v);
        try std.testing.expectEqualSlices(u32, case.encrypted[0..], &.{ a, v });

        tmp = decryptCode(case.encrypted[0], case.encrypted[1]);
        try std.testing.expectEqualSlices(u32, case.decrypted[0..], tmp[0..]);

        a = case.encrypted[0];
        v = case.encrypted[1];
        decryptCodeMut(&a, &v);
        try std.testing.expectEqualSlices(u32, case.decrypted[0..], &.{ a, v });
    }
}
