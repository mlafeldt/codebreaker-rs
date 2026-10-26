# Compare the CB constant tables in the unpacked CB v9.2 ELF against this
# crate's constants in src/cb1.rs and src/cb7.rs.
#
# usage: python3 -I cmptables.py <unpacked.elf> <crate src dir>
import os, re, struct, sys

elf_path, src_dir = sys.argv[1], sys.argv[2]
elf = open(elf_path, 'rb').read()
cb1 = open(os.path.join(src_dir, 'cb1.rs')).read()
cb7 = open(os.path.join(src_dir, 'cb7.rs')).read()

BASE = 0x100000 - 0x1000  # vaddr of file offset 0 in the unpacked ELF


def mem(addr, n):
    return elf[addr - BASE:addr - BASE + n]


def rust_const(src, name):
    m = re.search(r'^const ' + name + r':[^=]*=\s*(.*?);', src, re.S | re.M)
    return [int(x.replace('_', ''), 0) for x in re.findall(r'0x[0-9a-fA-F_]+|\b\d[\d_]*\b', m.group(1))]


def words(addr, n, fmt):
    size = struct.calcsize(fmt)
    data = mem(addr, n * size)
    return [struct.unpack_from(fmt, data, i * size)[0] for i in range(n)]


checks = [
    ('cb1 SEEDS', 0x289ad8, rust_const(cb1, 'SEEDS'), '<I'),
    ('cb7 SEEDS', 0x289b98, rust_const(cb7, 'SEEDS'), 'B'),
    ('cb7 RC4_KEY', 0x28a098, rust_const(cb7, 'RC4_KEY'), '<I'),
]
ok = True
for label, addr, want, fmt in checks:
    got = words(addr, len(want), fmt)
    ok &= got == want
    print(f"{label:12} @ {addr:#x}: {'MATCH' if got == want else 'DIFF'} ({len(want)} values)")

# The V7 decrypt builds the 64-bit modulus from an immediate 0xffffffff (high
# word) and this data word (low word), then passes exponent 11 (0xb).
modulus = (0xffffffff << 32) | struct.unpack('<I', mem(0x369000, 4))[0]
want = rust_const(cb7, 'RSA_MODULUS')[0]
ok &= modulus == want
print(f"RSA_MODULUS  @ 0x369000: {'MATCH' if modulus == want else 'DIFF'} ({modulus:#x})")
sys.exit(0 if ok else 1)
