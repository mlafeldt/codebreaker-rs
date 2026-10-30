# Attributes the v9.2 -> v10 output divergences to individual code changes.
#
# Builds a hybrid model (H) with each v10 change behind its own flag, checks
# that all flags off reproduces the v9.2 emulation and all flags on reproduces
# the v10 emulation, then counts the lists each single change alters (vs v9.2)
# and whether each change is still needed once the others are on. This is the
# evidence behind REVERSING.md §11.3/§11.4. The five flags cover behavior changes
# in four functions; initval combines reset zeroing and the init-copy decision:
#   initval  reset zeroes default seeds; rekey(1) copies them and ignores val
#   rekey0   rekey(0) uses the (val + j) index, ignoring the val == 0 case
#   always1  a beefcode already in V7 does rekey(1), not rekey(0)
#   noforce  no opt == 2 forced-V7 line
#   bfslot   v7_decrypt's key-from-line 5th word goes to beefcodf, not key[4]
#
# usage: run from research/.  python3 -I tools/attrib.py <corpus name>...
#   reads elf/emu/<name>.txt (cases), elf/emu/<name>.out (v9.2 emulation) and
#   elf/emu10/<name>.out (v10 emulation).
import sys, os, zlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fwmodel as m, fwmodel10 as m10
from fwmodel import M32, BEEF, Rc4, le_words, from_le
R = 'elf/'
t = m.Tables(m.Image(R + 'CBv92.unpacked.elf'))
FLAGS = ['initval', 'rekey0', 'always1', 'noforce', 'bfslot']


class H(m10.Fw10):
    def __init__(self, t, f):
        super().__init__(t); self.f = f
    def reset(self):
        self.mode = self.lines = 0
        self.defseeds = bytearray(0x500) if self.f['initval'] else bytearray(self.t.seeds)
    def rekey(self, init, val):
        if init:
            self.opt = self.bf = 0
            self.key = list(self.t.rc4key)
            if self.f['initval']:
                self.seeds = bytearray(self.defseeds)
            elif val == 0:
                self.seeds = bytearray(0x500)
            else:
                self.seeds = bytearray(self.t.seeds); m.Fw.derive(self, val)
        elif self.f['rekey0']:
            for i in range(4):
                self.key[i] = sum(self.seeds[0x100 * ((i + j) % 4) + ((val + j) & 0xff)] << (8 * j) for j in range(4))
        else:
            if val == 0: self.seeds = bytearray(0x500)
            m.Fw.derive(self, val)
        for i in range(5):
            rc4 = Rc4(le_words(self.key)); tab = self.seeds[0x100 * i:0x100 * (i + 1)]; rc4.crypt(tab)
            self.seeds[0x100 * i:0x100 * (i + 1)] = tab; k = le_words(self.key); rc4.crypt(k); self.key = from_le(k)
        self.kc = list(self.key)
    def v7_decrypt(self, a, v):
        if self.f['bfslot']: return m10.Fw10.v7_decrypt(self, a, v)
        return m.Fw.v7_decrypt(self, a, v)
    def decrypt_line(self, a, v):
        return self._v92(a, v)
    def _v92(self, addr, val):
        is_v7 = bool(self.mode & 0x10000) or (self.opt == 2 and not self.f['noforce'])
        if not is_v7:
            if self.lines == 0:
                self.lines = m.num_code_lines(addr)
                if (addr >> 24) & 0xe == 0: self.lines -= 1; self.v1 = 0; return addr, val
                if addr & ~1 & M32 == BEEF: self.lines += 1; self.v1 = 0; return addr, val
                self.v1 = 1
            elif self.v1 == 0: self.lines -= 1; return addr, val
            addr, val = m.v1_decrypt(self.t, addr, val); self.lines -= 1
        else:
            addr, val = self.v7_decrypt(addr, val)
            if self.lines == 0:
                self.lines = m.num_code_lines(addr)
                if self.lines == 1 and addr == M32:
                    self.mode = ((self.mode >> 16) << 24 | val & 0xffffff) & M32; self.lines = 0
                    self.opt = (val & 0x20000) >> 16; return addr, val
            self.lines -= 1
            if self.opt == 2 and not self.f['noforce']: self.opt = 0; return addr, val
        if self.mode & 0xffff:
            self.mode = (self.mode - 1) & M32
            if self.mode & 0xffff == 0: self.mode = (self.mode >> 24) << 16
        if addr & ~1 & M32 == BEEF:
            if not self.mode & 0x10000 or self.f['always1']:
                self.mode |= 0x10000; self.rekey(1, val)
            else: self.rekey(0, val)
            self.bf = addr & 1; self.lines = 1
        return addr, val


def lists(path):
    out, cur = [], None
    for l in open(path):
        l = l.strip()
        if not l or l.startswith('#') or l.startswith('!'): continue
        if l.startswith('==='): cur = []; out.append((l[3:].strip(), cur)); continue
        cur.append(tuple(int(x, 16) for x in l.split()))
    return out
def run(ls, f):
    res = []
    for name, rows in ls:
        fw = H(t, f); fw.reset(); r = []
        for a, v in rows: r.append((fw.decrypt_line(a, v), tuple(sorted(fw.state().items(), key=str)).__repr__()))
        res.append(r)
    return res
def emu(path):
    return [[(o, None) for _, o, _ in rows] for _, rows in m.parse_emu(path)]
E = R + 'emu/'; S = R + 'emu10/'
for c in sys.argv[1:]:
    ls = lists(E + c + '.txt')
    off = run(ls, dict.fromkeys(FLAGS, False)); on = run(ls, dict.fromkeys(FLAGS, True))
    e9 = [[o for o, _ in r] for r in emu(E + c + '.out')]; e10 = [[o for o, _ in r] for r in emu(S + c + '.out')]
    ok9 = [[o for o, _ in r] for r in off] == e9; ok10 = [[o for o, _ in r] for r in on] == e10
    counts = {}
    for fl in FLAGS:
        one = run(ls, {k: k == fl for k in FLAGS})
        counts[fl] = sum(1 for x, y in zip(off, one) if [o for o, _ in x] != [o for o, _ in y])
    rest = {}
    for fl in FLAGS:   # all-on minus one: does removing it change v10's output?
        allbut = run(ls, {k: k != fl for k in FLAGS})
        rest[fl] = sum(1 for x, y in zip(on, allbut) if [o for o, _ in x] != [o for o, _ in y])
    print(f'{c}: lists={len(ls)} off==v92emu {ok9} on==v10emu {ok10}  single-change(output lists vs v9.2) {counts}  needed-in-v10 {rest}')
