# Finds code that addresses given globals via lui + offset (which Ghidra
# often doesn't resolve). For every load, store or addiu whose base register
# was last set by a lui within the previous 64 instructions (and not written
# in between), computes the target and reports hits in the given ranges.
#
# usage: python3 -I luirefs.py <unpacked.elf> <start-end>...  (hex, end excl.)
import struct, sys

BASE = 0x100000 - 0x1000
data = open(sys.argv[1], 'rb').read()
ranges = [tuple(int(x, 16) for x in a.split('-')) if '-' in a else (int(a, 16), int(a, 16) + 1)
          for a in sys.argv[2:]]
TEXT = (0x100000, 0x289000)

LOADS = {0x20: 'lb', 0x21: 'lh', 0x23: 'lw', 0x24: 'lbu', 0x25: 'lhu', 0x27: 'lwu', 0x37: 'ld', 0x1e: 'lq'}
STORES = {0x28: 'sb', 0x29: 'sh', 0x2b: 'sw', 0x3f: 'sd', 0x1f: 'sq'}


def dest(w):
    op = w >> 26
    if op == 0:
        return (w >> 11) & 31
    if op in (0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x18, 0x19) or op in LOADS:
        return (w >> 16) & 31
    if op == 3:
        return 31
    return None


words = struct.unpack_from('<%dI' % ((TEXT[1] - TEXT[0]) // 4), data, TEXT[0] - BASE)
for i, w in enumerate(words):
    op = w >> 26
    if op not in LOADS and op not in STORES and op not in (0x09, 0x19):
        continue
    base, off = (w >> 21) & 31, struct.unpack('<h', struct.pack('<H', w & 0xffff))[0]
    if base == 0:
        continue
    for j in range(i - 1, max(-1, i - 64), -1):
        u = words[j]
        if u >> 26 == 0x0f and (u >> 16) & 31 == base:
            target = ((u & 0xffff) << 16) + off & 0xffffffff
            for lo, hi in ranges:
                if lo <= target < hi:
                    kind = LOADS.get(op) or STORES.get(op) or 'addr'
                    print(f'{TEXT[0] + 4 * i:08x} {kind:4} {target:08x}')
            break
        if dest(u) == base:
            break
