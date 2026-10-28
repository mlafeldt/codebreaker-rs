#!/usr/bin/env python3
# Unpack the CodeBreaker v10 retail BOOT.ELF body (REVERSING.md §10).
#
# The body is zlib-compressed then RC4-encrypted. Recovery is RC4-decrypt then
# inflate -- but only once the RC4 key is known. The loader derives the key at
# boot in FUN_01000248:
#
#   seed(0x20 @ 0x1010980) = 4x FUN_010009c0(constA, constB)   # R5900 COP1 math
#   A = SHA1(seed, 0x20)                 -> 0x1012a88
#   B = SHA1(0x1010980, 0x14)            # after FUN_01000150
#   C = SHA1(A || B)
#   real_key = (stored key @ 0x1010940) XOR C
#
# FUN_010009c0 uses R5900 COP1 extensions (madd.s 0x460d601c, msub.s
# 0x460c681d) and MMI (0x70000c28) that Ghidra/rizin/llvm do not decode, so the
# seed -- and thus the key -- cannot be reconstructed statically. The static
# candidates below (A/B from the FUN_010060f8 constants) were tried and none
# yields a zlib header, confirming the FUN_010009c0 seed matters. A faithful
# key needs an R5900-accurate emulator (PCSX2) or hardware: run the loader and
# read the 20 bytes at 0x1010940 after FUN_01000248 returns, or just dump EE
# RAM at 0x100000 after inflate. Pass that key to --key to finish offline.
import argparse, struct, zlib, hashlib

BASE, FOFF = 0x1000000, 0x1000
def o(va): return FOFF + (va - BASE)

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
    ap.add_argument("--key", help="40 hex chars: real RC4 key from a dynamic run")
    ap.add_argument("-o", "--out", default="CBv10.unpacked.bin")
    a = ap.parse_args()
    d = open(a.boot_elf, "rb").read()
    stored = d[o(0x1010940):o(0x1010940) + 0x14]
    rc4_len = struct.unpack_from("<I", d, o(0x1383580))[0]
    blob = d[o(0x1012ab0):o(0x1012ab0) + rc4_len]
    if not a.key:
        print("stored (pre-XOR) key:", stored.hex())
        print("no --key given; see header -- the real key needs a dynamic run.")
        return
    key = bytes.fromhex(a.key)
    dec = rc4(key, blob)
    comp_len = struct.unpack_from("<I", dec, 4)[0]
    comp = dec[8:8 + comp_len]
    if comp[:1] != b"\x78":
        print("RC4 output is not zlib (first byte %#x); wrong key." % comp[0]); return
    out = zlib.decompress(comp)
    open(a.out, "wb").write(out)
    print("inflated %d bytes -> %s" % (len(out), a.out))

if __name__ == "__main__":
    main()
