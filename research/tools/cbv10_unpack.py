#!/usr/bin/env python3
# Unpack the CodeBreaker v10 retail BOOT.ELF body (REVERSING.md §10).
#
# The body is zlib-compressed then RC4-encrypted. This recovers the RC4 key
# statically and writes the decompressed image.
#
# Key derivation (FUN_01000248), reverse-engineered. Most of that function is
# anti-analysis decoy (§10.8):
#   - FUN_010009c0 (an EE single-precision float bit-mixer using madd.s/msub.s)
#     builds a seed that is hashed and then OVERWRITTEN by fixed constants.
#   - the SIF-RPC to the IOP (FUN_01000150) loads no module and feeds nothing
#     into the key.
#   - the stored bytes at 0x1010940 are XORed with the derived value, not used
#     directly.
# The one real trick is that the firmware's SHA-1 writes its 5 state words in
# EE-native little-endian, not the standard big-endian digest. With that:
#     const20 = {1, 0x39956993, 0x55, 0, 0x05bc0000}           @ 0x1010980
#     A       = {938ca6bf,e620cc81,137a84c2,78ae9796,889dca10} @ 0x1012a88
#     B       = le_sha1(const20)
#     C       = le_sha1(A || B)
#     key     = (stored @ 0x1010940) XOR C
#             = 29f32f090c66b07dc5b12c51695e432eb1d8ea10  (this image)
import argparse, struct, zlib, hashlib

BASE, FOFF = 0x1000000, 0x1000
def o(va): return FOFF + (va - BASE)

def le_sha1(x):                          # firmware SHA-1: state words stored LE
    dg = hashlib.sha1(x).digest()
    return b"".join(struct.pack("<I", struct.unpack_from(">I", dg, i)[0]) for i in range(0, 20, 4))

def derive_key(d):
    const20 = struct.pack("<5I", 1, 0x39956993, 0x55, 0, 0x05bc0000)
    A = struct.pack("<5I", 0x938ca6bf, 0xe620cc81, 0x137a84c2, 0x78ae9796, 0x889dca10)
    C = le_sha1(A + le_sha1(const20))
    stored = d[o(0x1010940):o(0x1010940) + 0x14]
    return bytes(a ^ b for a, b in zip(stored, C))

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
    ap.add_argument("--key", help="override the derived 20-byte RC4 key (40 hex)")
    ap.add_argument("-o", "--out", default="CBv10.unpacked.bin")
    a = ap.parse_args()
    d = open(a.boot_elf, "rb").read()
    key = bytes.fromhex(a.key) if a.key else derive_key(d)
    print("RC4 key:", key.hex())
    rc4_len = struct.unpack_from("<I", d, o(0x1383580))[0]
    blob = d[o(0x1012ab0):o(0x1012ab0) + rc4_len]
    dec = rc4(key, blob)
    comp = dec[8:8 + struct.unpack_from("<I", dec, 4)[0]]
    if comp[:1] != b"\x78":
        print("RC4 output is not zlib (first byte %#x); wrong key." % comp[0]); return
    out = zlib.decompress(comp)
    open(a.out, "wb").write(out)
    print("inflated %d bytes -> %s" % (len(out), a.out))

if __name__ == "__main__":
    main()
