# Auto-decrypts cb2util-style code lists with the v9.2 and v10 firmware models
# and reports the games whose decrypted output differs between the two, plus
# how often real codes use the beefcode features that diverge. This is the
# empirical basis for REVERSING.md §11.4's "the cb2util game fixtures are
# unaffected": real published codes stay on the single default BEEFC0DE path.
#
# usage: run from research/.  python3 -I tools/fixdiff.py <code-list file>...
#   Each file is a cb2util text listing: a '"Game name"' line starts a list,
#   then "AAAAAAAA VVVVVVVV" code lines.
import sys, os, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fwmodel as m, fwmodel10 as m10
R = 'elf/'
t9 = m.Tables(m.Image(R + 'CBv92.unpacked.elf'))
t10 = m10.Tables10(m10.Image10(R + 'CBv10.unpacked.bin'))
games = lines = diffgames = difflines = 0
stats = dict(beef_nonzero=0, beefcodf=0, beef_in_v7=0, opt=0)
for path in sys.argv[1:]:
    cur = None
    def flush():
        global games, lines, diffgames, difflines
        if cur and cur[2]:
            games += 1; lines += cur[2]
            if cur[3]:
                diffgames += 1; difflines += cur[3]
                print(f'{path.split("/test/")[-1]}: {cur[0][:40]} lines={cur[2]} differ={cur[3]} first={cur[4]}')
    for l in open(path, errors='replace'):
        if l.startswith('"'):
            flush()
            a, b = m.Fw(t9), m10.Fw10(t10); a.reset(); b.reset()
            cur = [l.strip(), (a, b), 0, 0, None]
            continue
        p = l.split()
        if cur is None or len(p) != 2 or any(len(s) != 8 for s in p):
            continue
        try: x, y = int(p[0], 16), int(p[1], 16)
        except ValueError: continue
        a, b = cur[1]
        v7 = a.mode & 0x10000
        o9 = a.decrypt_line(x, y); o10 = b.decrypt_line(x, y)
        if o9[0] & ~1 & 0xffffffff == 0xbeefc0de:
            stats['beef_in_v7'] += bool(v7); stats['beefcodf'] += o9[0] & 1; stats['beef_nonzero'] += o9[1] != 0
        if o9[0] == 0xffffffff and v7: stats['opt'] += 1
        cur[2] += 1
        if o9 != o10:
            cur[3] += 1
            if cur[4] is None: cur[4] = f'{x:08X} {y:08X}: v9.2 {o9[0]:08X} {o9[1]:08X} v10 {o10[0]:08X} {o10[1]:08X}'
    flush()
print(f'{games} games, {lines} lines; {diffgames} games / {difflines} lines differ v9.2 vs v10; {stats}')
