#!/usr/bin/env python3
# Unpack the CodeBreaker v10 retail BOOT.ELF body (REVERSING.md §10).
#
# The body is zlib-compressed then RC4-encrypted. Recovery is RC4-decrypt then
# inflate -- once the RC4 key is known.
#
# The loader derives the key in FUN_01000248 (§10.5):
#   seed(0x20 @ 0x1010980) = 4x FUN_010009c0(constA, constB)  # EE float mixer
#   A = SHA1(seed, 0x20)                 -> 0x1012a88
#   B = SHA1(0x1010980, 0x14)            # after FUN_01000150
#   C = SHA1(A || B)
#   real_key = (stored key @ 0x1010940) XOR C
#
# FUN_010009c0 is the anti-tamper core: a 10-round EE single-precision float
# bit-mixer (madd.s/msub.s, EE COP1 extensions) that keeps the low 3 bits of
# each result -- exactly where the EE FPU diverges from IEEE. The EE FPU is
# ported below from PCSX2's FPU.cpp (fpuDouble + the arithmetic bodies). Even
# so, the reconstructed key does NOT inflate (every SHA-1 chaining tried), so
# the key also depends on FUN_01000150's SIF-RPC read from the IOP and/or on
# EE-FPU low-bit behaviour beyond PCSX2's accuracy. Pull the real key from a
# dynamic run (§10.7) and pass it to --key to finish offline.
#
# Modes:
#   (default)      print the stored (pre-XOR) key and reconstructed candidates
#   --key <hex>    RC4-decrypt + inflate the body with a real 20-byte key
import argparse, struct, zlib, hashlib

BASE, FOFF = 0x1000000, 0x1000
def o(va): return FOFF + (va - BASE)
M32, M64 = 0xffffffff, (1 << 64) - 1

# --- EE single-precision FPU, ported from PCSX2 pcsx2/FPU.cpp ---------------
def fpu_double(u):                       # fpuDouble(): flush denorm, clamp inf/nan
    e = u & 0x7f800000
    if e == 0:            u &= 0x80000000
    elif e == 0x7f800000: u = (u & 0x80000000) | 0x7f7fffff
    return struct.unpack("<f", struct.pack("<I", u & M32))[0]
def f2b(x):                              # round double -> float32 bits (RNE)
    return struct.unpack("<I", struct.pack("<f", x))[0]
def chk(u):                              # checkOverflow then checkUnderflow
    if (u & 0x7fffffff) == 0x7f800000: return (u & 0x80000000) | 0x7f7fffff
    if (u & 0x7f800000) == 0 and (u & 0x7fffff) != 0: return u & 0x80000000
    return u
def fmul(a, b): return chk(f2b(fpu_double(a) * fpu_double(b)))
def fsub(a, b): return chk(f2b(fpu_double(a) - fpu_double(b)))
def madd(acc, fs, ft):                   # fd = ACC + float32(fs*ft)
    return chk(f2b(fpu_double(acc) + fpu_double(f2b(fpu_double(fs) * fpu_double(ft)))))
def msub(acc, fs, ft):                   # fd = ACC - float32(fs*ft)
    return chk(f2b(fpu_double(acc) - fpu_double(f2b(fpu_double(fs) * fpu_double(ft)))))
def cvt_s_w(u):                          # (float)(s32)u
    return f2b(float(u - (1 << 32) if u & 0x80000000 else u))

def fun9c0(a, b, acc=0):                 # FUN_010009c0: returns 64-bit v0
    f12, f13, v0 = a & M32, b & M32, 0
    for _ in range(10):                  # v1 = 0x3c, -6 per round, bgtzl
        f0 = madd(acc, f12, f13)
        v0 = ((v0 | (f0 & 7)) << 3) & M64
        f12 = fsub(cvt_s_w(v0 & 0xffff), f0) & 0xcfffffff
        f0 = msub(acc, f13, f12)
        v0 = (v0 | (f0 & 7)) & M64
        f13 = fsub(cvt_s_w(v0 & 0xffff), f0) & 0xcfffffff
    return v0

PAIRS = [(0x420887fb, 0x4260db20), (0x425b220c, 0x41b1e90c),
         (0x4236ee0e, 0x42c0af7b), (0x427597cb, 0x429caf82)]

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff; S[i], S[j] = S[j], S[i]
    out = bytearray(data); i = j = 0
    for k in range(len(out)):
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff; S[i], S[j] = S[j], S[i]
        out[k] ^= S[(S[i] + S[j]) & 0xff]
    return bytes(out)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("boot_elf")
    ap.add_argument("--key", help="real 20-byte RC4 key (40 hex) from a dynamic run")
    ap.add_argument("-o", "--out", default="CBv10.unpacked.bin")
    a = ap.parse_args()
    d = open(a.boot_elf, "rb").read()
    stored = d[o(0x1010940):o(0x1010940) + 0x14]
    rc4_len = struct.unpack_from("<I", d, o(0x1383580))[0]
    blob = d[o(0x1012ab0):o(0x1012ab0) + rc4_len]

    if not a.key:
        sha = lambda x: hashlib.sha1(x).digest()
        seed = b"".join(struct.pack("<Q", fun9c0(x, y)) for x, y in PAIRS)
        A_seed, B_seed = sha(seed), sha(seed[:0x14])
        A_const = struct.pack("<5I", 0x938ca6bf, 0xe620cc81, 0x137a84c2, 0x78ae9796, 0x889dca10)
        B_const = sha(struct.pack("<5I", 1, 0x39956993, 0x55, 0, 0x05bc0000))
        print("stored (pre-XOR) key :", stored.hex())
        print("FUN_010009c0 seed    :", seed.hex())
        print("reconstructed candidates (none inflate -- see header, §10.5):")
        for an, A in (("A_seed", A_seed), ("A_const", A_const)):
            for bn, B in (("B_seed", B_seed), ("B_const", B_const)):
                key = bytes(x ^ y for x, y in zip(stored, sha(A + B)))
                print("  %-15s %s" % (an + "|" + bn, key.hex()))
        print("supply the real key with --key once pulled from PCSX2 (§10.7).")
        return

    dec = rc4(bytes.fromhex(a.key), blob)
    comp = dec[8:8 + struct.unpack_from("<I", dec, 4)[0]]
    if comp[:1] != b"\x78":
        print("RC4 output is not zlib (first byte %#x); wrong key." % comp[0]); return
    out = zlib.decompress(comp)
    open(a.out, "wb").write(out)
    print("inflated %d bytes -> %s" % (len(out), a.out))

if __name__ == "__main__":
    main()
