# Basic-block coverage of the code-crypto functions from Emu.java coverage
# files.
#
# usage: python3 -I coverage.py <calltree.txt> <cov>...
#   calltree.txt is the output of tools/ghidra/CallTree.java (blocks per
#   function). A block counts as reached if its first instruction ran.
import re, sys

funcs = {}
cur = None
for l in open(sys.argv[1]):
    m = re.match(r'##### FUNC (\w+)', l)
    if m:
        cur = int(m.group(1), 16)
        funcs[cur] = []
    m = re.match(r'BLOCK (\w+) (\w+)', l)
    if m:
        funcs[cur].append((int(m.group(1), 16), int(m.group(2), 16)))

hit = {}
for path in sys.argv[2:]:
    for l in open(path):
        a, where = l.split(None, 1)
        hit.setdefault(int(a, 16), where.strip())

for f, blocks in sorted(funcs.items()):
    reached = [b for b in blocks if b[0] in hit]
    missed = [b for b in blocks if b[0] not in hit]
    print(f'{f:08x}: {len(reached)}/{len(blocks)} blocks')
    for lo, hi in missed:
        print(f'    unreached {lo:08x}-{hi:08x}')
