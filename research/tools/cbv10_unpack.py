#!/usr/bin/env python3
# Unpack the CodeBreaker v10 BOOT.ELF body (V10.md §1).
#
# The body is zlib-compressed then RC4-encrypted. This recovers the RC4 key
# statically and writes the decompressed image. Its offsets and hardcoded
# inputs are specific to the supplied modified loader (V10.md §§1.6,1.8), whose
# BOOT.ELF SHA-256 is aafabd9b9ef8b74349ee6aa4272e4efa3fc1fd9838ceed78a23afff2521f3f04.
#
# Key derivation (FUN_01000248) combines two inputs:
# an EE single-precision float bit-mixer (FUN_010009c0, madd.s/msub.s) feeds the
# SHA-1 digest A, and a SIF-RPC (FUN_01000150) obtains const20: a status word
# followed by 16 read-key bytes. The constants below match the software-derived reply
# for serial SLUS-20202 (REVIEW.md F1); they are not an inaccessible physical secret.
# Reproducing the unmodified EE mixer in software remains unverified here.
# This image is modified: a stub at 0x10060f8 hardcodes BOTH A and const20 as
# literal immediates (the 0x1010980/0x1012a88 buffers are zero in the file), so
# the key is static. The schedule's non-obvious step is that the firmware's
# SHA-1 writes its 5 state words EE-native little-endian, not as the standard
# big-endian digest. With the stub's constants:
#     const20 = {1, 0x39956993, 0x55, 0, 0x05bc0000}           @ 0x1010980
#     A       = {938ca6bf,e620cc81,137a84c2,78ae9796,889dca10} @ 0x1012a88
#     B       = le_sha1(const20)
#     C       = le_sha1(A || B)
#     key     = (stored @ 0x1010940) XOR C
#             = 29f32f090c66b07dc5b12c51695e432eb1d8ea10  (this image)
import argparse, struct, zlib, hashlib
from pathlib import Path

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
    if len(stored) != 20:
        raise ValueError("loader is truncated before the stored RC4 key")
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
    try:
        d = Path(a.boot_elf).read_bytes()
        key = bytes.fromhex(a.key) if a.key is not None else derive_key(d)
        if len(key) != 20:
            raise ValueError("RC4 key must contain exactly 20 bytes (40 hex digits)")
        print("RC4 key:", key.hex())
        if len(d) < o(0x1383580) + 4:
            raise ValueError("loader is truncated before the encrypted-body length")
        rc4_len = struct.unpack_from("<I", d, o(0x1383580))[0]
        if rc4_len < 8 or o(0x1012ab0) + rc4_len > len(d):
            raise ValueError("encrypted-body length is outside the loader or lacks its header")
        blob = d[o(0x1012ab0):o(0x1012ab0) + rc4_len]
        dec = rc4(key, blob)
        want, comp_len = struct.unpack_from("<II", dec)
        if comp_len == 0 or comp_len > len(dec) - 8:
            raise ValueError("invalid compressed-body length; wrong key or damaged image")
        comp = dec[8:8 + comp_len]
        inflater = zlib.decompressobj()
        # Stop if the stream exceeds its declared size rather than accepting a
        # mismatch and writing the result. A complete stream needs no flush.
        out = inflater.decompress(comp, want + 1)
        if len(out) != want:
            raise ValueError("inflated %d bytes, header says %d" % (len(out), want))
        if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
            raise ValueError("incomplete zlib stream or trailing compressed data")
        Path(a.out).write_bytes(out)
    except (OSError, ValueError, zlib.error) as error:
        ap.error(str(error))
    print("inflated %d bytes -> %s" % (len(out), a.out))

if __name__ == "__main__":
    main()
