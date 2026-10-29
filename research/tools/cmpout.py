# Compares two EmuP.java outputs (e.g. v9.2 vs v10) list by list: the decrypted
# outputs, all state fields, and primitive (!inv/!mul/!rsa) lines. Reports, per
# corpus, how many lists differ in output, in state only, and in primitives.
#
# usage: python3 -I cmpout.py <a.out> <b.out> [max-first-lines]
import sys
def parse(p):
    lists, name = {}, None
    for l in open(p):
        l = l.rstrip('\n')
        if l.startswith('==='): name = l[3:].strip(); lists[name] = []
        elif l.strip(): lists[name].append(l)
    return lists
a, b = parse(sys.argv[1]), parse(sys.argv[2])
assert list(a) == list(b)
nout = nstate = nlines = nprim = 0; first = []
for k in a:
    fo = fs = None
    for i, (x, y) in enumerate(zip(a[k], b[k])):
        nlines += 1
        if x.startswith('!'):
            if x != y: nprim += 1; first.append(f'PRIM {k}: {x} | {y}')
            continue
        if x.split()[:5] != y.split()[:5]:
            fo = i if fo is None else fo
        elif x != y and fs is None and fo is None: fs = i
    if fo is not None:
        nout += 1
        if len(first) < int(sys.argv[3]) if len(sys.argv) > 3 else 8: first.append(f'OUT   {k}:{fo}: {a[k][fo][:40]} | {b[k][fo][19:40]}')
    elif fs is not None:
        nstate += 1
        if len(first) < 40: first.append(f'STATE {k}:{fs}: {a[k][fs][40:]} | {b[k][fs][40:]}')
print(f'{len(a)} lists, {nlines} lines: {nout} lists output differ, {nstate} state-only, {nprim} primitive differ')
for f in first: print('  ' + f)
