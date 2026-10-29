# Wraps the raw v10 image (CBv10.unpacked.bin, loaded at 0x100000) in a minimal
# one-segment ELF so Ghidra can load it at the right base, like unn2e.py does
# for v9.2. <extra> is extra zero-filled bytes past the file (bss); 0 is fine
# for the code-crypto call tree.
#
# usage: python3 -I wrap.py <CBv10.unpacked.bin> <CBv10.elf> <extra>
import struct, sys
src, dst, extra = sys.argv[1], sys.argv[2], int(sys.argv[3], 0)
d = open(src, 'rb').read()
base, entry = 0x100000, 0x100008
ehdr = struct.pack('<4sBBBB8sHHIIIIIHHHHHH', b'\x7fELF', 1, 1, 1, 0, b'\0'*8, 2, 8, 1, entry, 52, 0, 0, 52, 32, 1, 0, 0, 0)
phdr = struct.pack('<IIIIIIII', 1, 0x1000, base, base, len(d), len(d) + extra, 7, 0x10)
out = ehdr + phdr
open(dst, 'wb').write(out + b'\0' * (0x1000 - len(out)) + d)
