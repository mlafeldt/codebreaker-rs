#!/usr/bin/env python3
# Relocation-aware normalized diff of the CB code-crypto call tree, v9.2 vs v10
# (REVERSING.md section 11).
#
# This is a static comparison aid for the identified images, not a proof of
# behavioral equivalence. Only explicitly mapped code/data coordinates are
# normalized. Unknown references retain their address and block IDENTICAL.
# A LUI high half is normalized only when its uses establish mapped addresses;
# numeric uses and unproven control-flow chains keep the original bits.
# Every changed word in an equal normalized pair is independently checked for
# its instruction field and mapped coordinate. Unvalidated differences remain
# UNRESOLVED. Registers, shifts and other constants retain their raw bits.
# Function ranges are explicit, include return/tail-jump delay slots, and omit
# alignment padding; no first-return boundary heuristic is used.
#
#   python3 -I tools/cbcrypt_diff.py [v92.elf v10.bin] [--allow-differences]
# Exit status: 0 identical, 1 changed/unresolved, 2 invalid input. The flag
# permits CHANGED functions for version surveys, but never permits UNRESOLVED.
#
# v9.2 maps vaddr V -> file V-0x100000+0x1000 (PT_LOAD p_offset 0x1000); the v10
# image is raw at base 0x100000.
import argparse
import difflib
from pathlib import Path
import struct
import sys

REG = ["zero","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4","t5",
       "t6","t7","s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1",
       "gp","sp","s8","ra"]

def dec(w, pc=0):
    op=w>>26; rs=(w>>21)&31; rt=(w>>16)&31; rd=(w>>11)&31; sa=(w>>6)&31; fn=w&63
    imm=w&0xffff; s=imm-0x10000 if imm&0x8000 else imm; R=REG
    t=lambda: f"0x{(((pc+4)&0xf0000000)|((w&0x3ffffff)<<2)):x}"
    b=lambda: f"0x{pc+4+s*4:x}"
    if w==0: return "nop"
    if op==0:
        m={0x20:"add",0x21:"addu",0x22:"sub",0x23:"subu",0x24:"and",0x25:"or",
           0x26:"xor",0x27:"nor",0x2a:"slt",0x2b:"sltu",0x2d:"daddu",0x2f:"dsubu"}
        if fn in m: return f"{m[fn]} {R[rd]},{R[rs]},{R[rt]}"
        if fn==0: return f"sll {R[rd]},{R[rt]},{sa}"
        if fn==2: return f"srl {R[rd]},{R[rt]},{sa}"
        if fn==3: return f"sra {R[rd]},{R[rt]},{sa}"
        if fn==8: return f"jr {R[rs]}"
        if fn==9: return f"jalr {R[rd]},{R[rs]}"
        if fn==0x12: return f"mflo {R[rd]}"
        if fn==0x18: return f"mult {R[rs]},{R[rt]}"
        if fn==0x1b: return f"divu {R[rs]},{R[rt]}"
        return f".word 0x{w:08x} (R fn=0x{fn:02x})"
    if op==1: return f"{'bgez' if rt&1 else 'bltz'}{'l' if rt&2 else ''} {R[rs]},{b()}"
    if op==2: return f"j {t()}"
    if op==3: return f"jal {t()}"
    if op in (4,5,0x14,0x15):
        mm={4:"beq",5:"bne",0x14:"beql",0x15:"bnel"}[op]
        if op==4 and rs==0 and rt==0: return f"b {b()}"
        return f"{mm} {R[rs]},{R[rt]},{b()}"
    if op in (6,7,0x16,0x17):
        return f"{ {6:'blez',7:'bgtz',0x16:'blezl',0x17:'bgtzl'}[op] } {R[rs]},{b()}"
    I={0x08:"addi",0x09:"addiu",0x0a:"slti",0x0b:"sltiu",0x0c:"andi",0x0d:"ori",
       0x0e:"xori",0x19:"daddiu"}
    if op in I:
        if op==0x09 and rs==0: return f"li {R[rt]},{s}"
        return f"{I[op]} {R[rt]},{R[rs]},{s if op in (8,9,0x19) else hex(imm)}"
    if op==0x0f: return f"lui {R[rt]},0x{imm:x}"
    M={0x20:"lb",0x21:"lh",0x22:"lwl",0x23:"lw",0x24:"lbu",0x25:"lhu",0x26:"lwr",
       0x28:"sb",0x29:"sh",0x2a:"swl",0x2b:"sw",0x2e:"swr",0x1a:"ldl",0x1b:"ldr",
       0x37:"ld",0x3f:"sd"}
    if op in M: return f"{M[op]} {R[rt]},{s}({R[rs]})"
    return f".word 0x{w:08x} (op=0x{op:02x})"

def off92(a): return a-0x100000+0x1000
def off10(a): return a-0x100000

# role: (v9.2 start, exclusive end, v10 start, exclusive end).
# Bounds follow the complete listings and terminal instructions, not Ghidra's
# truncated EE function bodies. For example, memcpy's three returns all belong
# to its 106-word body, while reset v10 tail-jumps at 105324 (delay 105328).
RANGES = {
    'lines': (0x1033c0, 0x103410, 0x104470, 0x1044c0),
    'v1dec': (0x103410, 0x1034dc, 0x1044c0, 0x10458c),
    'inverse': (0x1034e0, 0x10357c, 0x104590, 0x10462c),
    'multiply': (0x103580, 0x1035ac, 0x104630, 0x10465c),
    'rekey': (0x1035b0, 0x103f60, 0x104660, 0x104d3c),
    'v7dec': (0x103f60, 0x1042b0, 0x104d40, 0x105090),
    'auto': (0x1042b0, 0x104544, 0x105090, 0x1052a4),
    'reset': (0x104548, 0x10455c, 0x1052a8, 0x10532c),
    'rc4init': (0x132c98, 0x132d2c, 0x131360, 0x1313f4),
    'rc4crypt': (0x132d30, 0x132db4, 0x1313f8, 0x13147c),
    'rsawrap': (0x134020, 0x134044, 0x1326e8, 0x13270c),
    'memcpy': (0x1461b0, 0x146358, 0x1447d4, 0x14497c),
    'memset': (0x146358, 0x146404, 0x14497c, 0x144a28),
    'udiv': (0x14cbd8, 0x14d1a8, 0x14b230, 0x14b800),
    'umod': (0x14d1a8, 0x14d6e8, 0x14b800, 0x14bd40),
    'bignum': (0x133220, 0x134020, 0x1318e8, 0x1326e8),
}
FUNCS = {name: (bounds[0], bounds[2]) for name, bounds in RANGES.items()}
# The independently matched contiguous bignum block has a uniform relocation.
# Preserve each entry's identity, rather than collapsing its internal calls.
for entry in (0x133220, 0x133298, 0x133320, 0x1333d0, 0x133428,
              0x133670, 0x1337c0, 0x133828, 0x133870, 0x1338c0,
              0x133948, 0x133cc0, 0x133dd0):
    FUNCS[f'nn_{entry:x}'] = (entry, entry - 0x1938)
ROLE={"v92":{v[0]:k for k,v in FUNCS.items()},"v10":{v[1]:k for k,v in FUNCS.items()}}
# struct regions, identical internal layout, rebased: (name, v9.2 base, v10 base, size)
REGIONS=[("S",0x289ac8,0x764bd0,0x600),("R",0x36dcc8,0x9eff48,0x648),
         ("N",0x369000,0x9eb330,4),
         ("clz_udiv",0x36d6d0,0x9ef970,0x100),
         ("clz_umod",0x36d7d0,0x9efa70,0x100)]
def region(img,a):
    for name,b9,b10,sz in REGIONS:
        b=b9 if img=="v92" else b10
        if b<=a<b+sz: return f"{name}+{a-b:#x}"
    return None


def code_coordinate(img, address, start, end):
    if address in ROLE[img]:
        return ROLE[img][address]
    if start <= address < end:
        return f'local+{address - start:#x}'
    # Equal-size code ranges provide corresponding interior instruction slots.
    for name, (s9, e9, s10, e10) in RANGES.items():
        lo, hi = (s9, e9) if img == 'v92' else (s10, e10)
        if e9 - s9 == e10 - s10 and lo <= address < hi:
            return f'{name}+{address - lo:#x}'
    return f'UNKNOWN@{address:#x}'

LOADS={0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x37,0x1a,0x1b}
MEM=LOADS|{0x28,0x29,0x2a,0x2b,0x2e,0x3f}
BR={1:"bz",4:"beq",5:"bne",6:"blez",7:"bgtz",0x14:"beql",0x15:"bnel",0x16:"blezl",0x17:"bgtzl"}

def norm(data, offfn, start, end, img):
    if start % 4 or end % 4 or start >= end:
        raise ValueError(f'invalid instruction range {start:#x}..{end:#x}')
    rows = []
    for address in range(start, end, 4):
        offset = offfn(address)
        if offset < 0 or offset + 4 > len(data):
            raise ValueError(f'{img}: missing bytes at {address:#x}')
        rows.append((address, struct.unpack_from('<I', data, offset)[0]))

    # State is deliberately limited to constant construction within one basic
    # block. Branch targets and post-delay-slot boundaries invalidate it.
    boundaries = set()
    for address, word in rows:
        op, rs, fn = word >> 26, word >> 21 & 31, word & 63
        imm = word & 0xffff
        signed = imm - 0x10000 if imm & 0x8000 else imm
        if op in BR:
            boundaries.update((address + 8, address + 4 + signed * 4))
        elif op in (2, 3):
            boundaries.update((address + 8, ((address + 4) & 0xf0000000) | ((word & 0x3ffffff) << 2)))
        elif op == 0 and fn in (8, 9):
            boundaries.add(address + 8)

    state, highs, out = {}, {}, []

    def numeric_use(register):
        value = state.get(register)
        if value and value[0] == 'HI':
            highs[value[2]]['unsafe'] = True

    def clear_state():
        for register in state:
            numeric_use(register)
        state.clear()

    for address, word in rows:
        if address in boundaries:
            clear_state()
        op, rs, rt, rd, fn = word >> 26, word >> 21 & 31, word >> 16 & 31, word >> 11 & 31, word & 63
        imm = word & 0xffff
        signed = imm - 0x10000 if imm & 0x8000 else imm
        token = f'raw {word:08x}'
        if op == 0x0f:
            origin = len(out)
            highs[origin] = {'uses': set(), 'unsafe': False}
            state[rt] = ('HI', imm << 16, origin)
        elif op in (0x09, 0x19, 0x0d):
            value = state.get(rs)
            if value:
                target = (value[1] | imm) if op == 0x0d else (value[1] + signed) & 0xffffffff
                coordinate = region(img, target)
                if coordinate:
                    token = f'op{op:02x} {REG[rt]},{REG[rs]},&{coordinate}'
                    if value[2] is not None:
                        highs[value[2]]['uses'].add(coordinate)
                    state[rt] = ('ADDR', target, value[2])
                else:
                    numeric_use(rs)
                    state[rt] = ('CONST', target, None)
            else:
                state.pop(rt, None)
        elif op in MEM:
            value = state.get(rs)
            if value:
                target = (value[1] + signed) & 0xffffffff
                coordinate = region(img, target)
                if coordinate:
                    token = f'm{op:02x} {REG[rt]},[{coordinate}]({REG[rs]})'
                    if value[2] is not None:
                        highs[value[2]]['uses'].add(coordinate)
                else:
                    numeric_use(rs)
                    token = f'm{op:02x} {REG[rt]},[UNKNOWN@{target:#x}]({REG[rs]})'
            if op in LOADS:
                state.pop(rt, None)
            else:
                numeric_use(rt)
        elif op in (2, 3):
            target = ((address + 4) & 0xf0000000) | ((word & 0x3ffffff) << 2)
            token = f'{"j" if op == 2 else "jal"} {code_coordinate(img, target, start, end)}'
            # A bare high half passed to a callee is not a proven address.
            for register in range(4, 12):
                numeric_use(register)
        elif op == 0:
            if fn in (0x21, 0x2d, 0x25) and rt == 0 and rs in state:
                state[rd] = state[rs]
            else:
                numeric_use(rs)
                numeric_use(rt)
                state.pop(rd, None)
        elif op in BR:
            numeric_use(rs)
            if op in (4, 5, 0x14, 0x15):
                numeric_use(rt)
        else:
            numeric_use(rs)
            numeric_use(rt)
            state.pop(rt, None)
        state.pop(0, None)
        out.append((address, word, token))

    # Unconsumed high halves can be observable return/register values.
    clear_state()
    for index, high in highs.items():
        if high['uses'] and not high['unsafe']:
            address, word, _ = out[index]
            out[index] = (address, word, f'lui {REG[word >> 16 & 31]},HI({",".join(sorted(high["uses"]))})')
    return out


def rawmaskable(left, right):
    """Validate a changed raw field against its proven normalized coordinate."""
    _, x, tx = left
    _, y, ty = right
    if x == y:
        return True
    if tx != ty or 'UNKNOWN@' in tx or x >> 26 != y >> 26:
        return False
    op = x >> 26
    if op in (2, 3):
        return tx.startswith(('j ', 'jal '))
    if x >> 16 != y >> 16:
        return False
    if op == 0x0f:
        return ',HI(' in tx
    if op in (0x09, 0x0d, 0x19) or op in MEM:
        return '&' in tx or '[' in tx
    return False


D9 = D10 = None
def diff(role,s9,e9,s10,e10):
    n9=norm(D9,off92,s9,e9,"v92"); n10=norm(D10,off10,s10,e10,"v10")
    t9=[t[2] for t in n9]; t10=[t[2] for t in n10]
    print("\n"+"="*70)
    print(f"{role}: v9.2 {s9:#x}..{e9:#x} ({len(n9)})  v10 {s10:#x}..{e10:#x} ({len(n10)})")
    if t9==t10:
        bad=[i for i in range(len(n9)) if not rawmaskable(n9[i],n10[i])]
        unknown = [i for i, (_, _, token) in enumerate(n9) if 'UNKNOWN@' in token]
        if bad or unknown:
            print("  UNRESOLVED: normalized equality includes unvalidated words or references")
            for i in bad:
                print(f"    - {n9[i][0]:#x} {n9[i][1]:08x} {dec(n9[i][1],n9[i][0])}")
                print(f"    + {n10[i][0]:#x} {n10[i][1]:08x} {dec(n10[i][1],n10[i][0])}")
            for i in unknown:
                print(f'    {n9[i][0]:#x}: {n9[i][2]}')
            return 'unresolved'
        print("  IDENTICAL modulo validated relocation (static instructions only)")
        return 'identical'
    sm=difflib.SequenceMatcher(a=t9,b=t10,autojunk=False)
    print(f"  CHANGED ({sum(1 for o in sm.get_opcodes() if o[0]!='equal')} hunks). - v9.2 / + v10:")
    for tg,i1,i2,j1,j2 in sm.get_opcodes():
        if tg=="equal": continue
        print(f"  @@ {tg} v9.2[{i1}:{i2}] v10[{j1}:{j2}]")
        for k in range(i1,i2): print(f"    - {n9[k][0]:#x} {n9[k][1]:08x} {dec(n9[k][1],n9[k][0])}")
        for k in range(j1,j2): print(f"    + {n10[k][0]:#x} {n10[k][1]:08x} {dec(n10[k][1],n10[k][0])}")
    return 'changed'


def main(argv=None):
    global D9, D10
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('v92', nargs='?', default='elf/CBv92.unpacked.elf')
    parser.add_argument('v10', nargs='?', default='elf/CBv10.unpacked.bin')
    parser.add_argument('--allow-differences', action='store_true',
                        help='allow CHANGED functions, but not UNRESOLVED comparisons')
    args = parser.parse_args(argv)
    try:
        D9, D10 = Path(args.v92).read_bytes(), Path(args.v10).read_bytes()
        results = [diff(name, *bounds) for name, bounds in RANGES.items()]
    except (OSError, ValueError, struct.error) as error:
        print(f'error: {error}', file=sys.stderr)
        return 2
    print('\nSummary: ' + ', '.join(f'{results.count(kind)} {kind}'
                                   for kind in ('identical', 'changed', 'unresolved')))
    return int('unresolved' in results or ('changed' in results and not args.allow_differences))


if __name__ == '__main__':
    sys.exit(main())
