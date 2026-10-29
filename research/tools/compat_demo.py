# Reproduce REVERSING.md §11.5 with the committed tools, using gen.py's correct
# encryptor (Prog): a plain BEEFC0DE 0 list decrypts identically on both
# images; a BEEFC0DE <nonzero> list and a second beefcode do not.
#
# usage: run from research/.  python3 -I tools/compat_demo.py
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fwmodel as m, fwmodel10 as m10
from gen import Prog
t9  = m.Tables(m.Image('elf/CBv92.unpacked.elf'))
t10 = m10.Tables10(m10.Image10('elf/CBv10.unpacked.bin'))
CODES = [(0x01234567,0x89ABCDEF),(0x10203040,0x50607080),(0xDEADBEEF,0x0BADF00D)]

def build(beefval, second=None):        # cipher list, encrypted by the v9.2 fw
    p = Prog(t9, 'demo'); p.add(m.BEEF, beefval, 'v1')
    for a,v in CODES: p.add(a, v)
    if second is not None:
        p.add(m.BEEF, second, 'v1')
        for a,v in CODES: p.add(a, v)
    return p.lines

def dec(tab, Cls, cipher):
    fw = Cls(tab); fw.reset(); return [fw.decrypt_line(a,v) for a,v in cipher]

for label, cipher in [("plain   BEEFC0DE 00000000",            build(0)),
                      ("value   BEEFC0DE 0000002A",            build(0x2A)),
                      ("second  BEEFC0DE 0 .. BEEFC0DE 0",      build(0, second=0))]:
    d9, d10 = dec(t9,m.Fw,cipher), dec(t10,m10.Fw10,cipher)
    print(f"{label}: v9.2==v10 ? {d9==d10}")
    if d9!=d10:
        for i,(x,y) in enumerate(zip(d9,d10)):
            if x!=y: print(f"    line {i}: v9.2 {x[0]:08X} {x[1]:08X}  v10 {y[0]:08X} {y[1]:08X}")
