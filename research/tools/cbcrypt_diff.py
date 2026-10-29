#!/usr/bin/env python3
# Relocation-aware normalized diff of the CB code-crypto call tree, v9.2 vs v10
# (REVERSING.md section 11).
#
# The two images are the same code linked at different addresses, plus some real
# changes. A raw byte diff is useless (every address differs). This decodes each
# function and normalizes away relocations, so only real differences survive:
#   - call targets          -> role name from FUNCS (else "?")
#   - lui high halves        -> masked
#   - global addresses       -> resolved to (region + offset); the SAME struct is
#                               one name in both images, so a different *offset*
#                               (e.g. key+0x10 vs key+0x14) still shows as a diff
#   - plain pointer args      -> (register, offset) kept literal
# Registers, shift amounts, real constants and branch displacements stay literal.
# For functions that normalize equal it also checks every position differs at the
# raw-word level only in a relocation field, so masking can't hide a real change.
#
#   python3 -I tools/cbcrypt_diff.py [elf/CBv92.unpacked.elf elf/CBv10.unpacked.bin]
#
# v9.2 maps vaddr V -> file V-0x100000+0x1000 (PT_LOAD p_offset 0x1000); the v10
# image is raw at base 0x100000.
import sys, struct, difflib

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

V92 = sys.argv[1] if len(sys.argv)>1 else "elf/CBv92.unpacked.elf"
V10 = sys.argv[2] if len(sys.argv)>2 else "elf/CBv10.unpacked.bin"
def off92(a): return a-0x100000+0x1000
def off10(a): return a-0x100000

FUNCS = {   # role: (v9.2, v10) call targets
    "lines":(0x1033c0,0x104470), "v1dec":(0x103410,0x1044c0),
    "inverse":(0x1034e0,0x104590), "multiply":(0x103580,0x104630),
    "rekey":(0x1035b0,0x104660), "v7dec":(0x103f60,0x104d40),
    "auto":(0x1042b0,0x105090), "reset":(0x104548,0x1052a8),
    "rc4init":(0x132c98,0x131360), "rc4crypt":(0x132d30,0x1313f8),
    "rsawrap":(0x134020,0x1326e8), "memcpy":(0x1461b0,0x1447d4),
    "memset":(0x146358,0x14497c), "udiv":(0x14cbd8,0x14b230),
    "umod":(0x14d1a8,0x14b800),
}
ROLE={"v92":{v[0]:k for k,v in FUNCS.items()},"v10":{v[1]:k for k,v in FUNCS.items()}}
# struct regions, identical internal layout, rebased: (name, v9.2 base, v10 base, size)
REGIONS=[("S",0x289ac8,0x764bd0,0x600),("R",0x36dcc8,0x9eff48,0x6d0),
         ("N",0x369000,0x9eb330,0x400)]
def region(img,a):
    for name,b9,b10,sz in REGIONS:
        b=b9 if img=="v92" else b10
        if b<=a<b+sz: return f"{name}+{a-b:#x}"
    return None

LOADS={0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x37,0x1a,0x1b}
MEM=LOADS|{0x28,0x29,0x2a,0x2b,0x2e,0x3f}
BR={1:"bz",4:"beq",5:"bne",6:"blez",7:"bgtz",0x14:"beql",0x15:"bnel",0x16:"blezl",0x17:"bgtzl"}

def norm(data,offfn,start,end,img):
    st={}; out=[]; a=start
    while a<end:
        w=struct.unpack_from("<I",data,offfn(a))[0]
        op=w>>26; rs=(w>>21)&31; rt=(w>>16)&31; rd=(w>>11)&31; fn=w&63
        imm=w&0xffff; sm=imm-0x10000 if imm&0x8000 else imm; kill=[]
        def A(reg,ab): st[reg]=('ADDR',ab); r=region(img,ab); return f"{REG[reg]}=&{r}" if r else f"{REG[reg]}=&?"
        if w==0: tok="nop"
        elif op==0x0f: st[rt]=('HI',imm<<16); tok=f"lui {REG[rt]},HI"
        elif op in (0x09,0x19):
            s=st.get(rs)
            if s and s[0]=='HI': tok=A(rt,s[1]+sm)
            elif s and s[0]=='ADDR': st[rt]=('ADDR',s[1]+sm); tok=f"addiu {REG[rt]},{REG[rs]},+{sm}"
            else: tok=f"addiu {REG[rt]},{REG[rs]},{sm}"; kill.append(rt)
        elif op==0x0d:
            s=st.get(rs)
            if s and s[0]=='HI': tok=A(rt,s[1]|imm)
            else: tok=f"ori {REG[rt]},{REG[rs]},0x{imm:x}"; kill.append(rt)
        elif op in MEM:
            mn=f"m{op:02x}"; s=st.get(rs)
            if s and s[0]=='HI': tok=f"{mn} {REG[rt]},[{region(img,s[1]+sm) or '?'}]"
            elif s and s[0]=='ADDR':
                r=region(img,s[1]+sm); tok=f"{mn} {REG[rt]},[{r}]" if r else f"{mn} {REG[rt]},{sm}(PTR)"
            else: tok=f"{mn} {REG[rt]},{sm}({REG[rs]})"
            if op in LOADS: kill.append(rt)
        elif op in (2,3):
            tgt=((a+4)&0xf0000000)|((w&0x3ffffff)<<2)
            tok=f'{"j" if op==2 else "jal"} {ROLE[img].get(tgt,"?")}'
        elif op==0:
            if fn==8: tok=f"jr {REG[rs]}"
            elif fn==9: tok=f"jalr {REG[rd]},{REG[rs]}"; kill.append(rd)
            elif fn in (0x21,0x2d):
                if rt==0 and rs in st: st[rd]=st[rs]
                else: kill.append(rd)
                tok=f"move {REG[rd]},{REG[rs]}" if rt==0 else f"addu {REG[rd]},{REG[rs]},{REG[rt]}"
            else: tok=f"R{fn:02x} {REG[rd]},{REG[rs]},{REG[rt]}"; kill.append(rd)
        elif op in BR: tok=f"{BR[op]} {REG[rs]},{REG[rt]},+{sm}"
        else: tok=f"op{op:02x} {REG[rt]},{REG[rs]},0x{imm:x}"; kill.append(rt)
        out.append((a,w,tok))
        for r in kill: st.pop(r,None)
        a+=4
    return out

def rawmaskable(x,y):
    if x==y: return True
    op=x>>26
    if op!=y>>26: return False
    if op==0x0f: return (x>>16)==(y>>16)
    if op in (2,3): return True
    if op in (0x09,0x0d,0x19) or op in MEM: return (x>>16)==(y>>16)
    return False

def find_end(data,offfn,start,cap=0x800):
    a=start
    while a<start+cap:
        if struct.unpack_from("<I",data,offfn(a))[0]==0x03e00008: return a+8
        a+=4
    return start+cap

D9=open(V92,"rb").read(); D10=open(V10,"rb").read()
def diff(role,s9,e9,s10,e10):
    n9=norm(D9,off92,s9,e9,"v92"); n10=norm(D10,off10,s10,e10,"v10")
    t9=[t[2] for t in n9]; t10=[t[2] for t in n10]
    print("\n"+"="*70)
    print(f"{role}: v9.2 {s9:#x}..{e9:#x} ({len(n9)})  v10 {s10:#x}..{e10:#x} ({len(n10)})")
    if t9==t10:
        bad=[i for i in range(len(n9)) if not rawmaskable(n9[i][1],n10[i][1])]
        if bad:
            print("  EQUAL tokens but non-reloc raw diff (INVESTIGATE):")
            for i in bad:
                print(f"    - {n9[i][0]:#x} {dec(n9[i][1],n9[i][0])}")
                print(f"    + {n10[i][0]:#x} {dec(n10[i][1],n10[i][0])}")
        else: print("  IDENTICAL modulo relocation")
        return
    sm=difflib.SequenceMatcher(a=t9,b=t10,autojunk=False)
    print(f"  CHANGED ({sum(1 for o in sm.get_opcodes() if o[0]!='equal')} hunks). - v9.2 / + v10:")
    for tg,i1,i2,j1,j2 in sm.get_opcodes():
        if tg=="equal": continue
        print(f"  @@ {tg} v9.2[{i1}:{i2}] v10[{j1}:{j2}]")
        for k in range(i1,i2): print(f"    - {n9[k][0]:#x} {dec(n9[k][1],n9[k][0])}")
        for k in range(j1,j2): print(f"    + {n10[k][0]:#x} {dec(n10[k][1],n10[k][0])}")

if __name__=="__main__":
    s9=[0x1033c0,0x103410,0x1034e0,0x103580,0x1035b0,0x103f60,0x1042b0,0x104548]
    s10=[0x104470,0x1044c0,0x104590,0x104630,0x104660,0x104d40,0x105090,0x1052a8]
    for i,r in enumerate(["lines","v1dec","inverse","multiply","rekey","v7dec","auto"]):
        diff(r,s9[i],s9[i+1],s10[i],s10[i+1])
    for r,a9,a10 in [("reset",0x104548,0x1052a8),("rc4init",0x132c98,0x131360),
                     ("rc4crypt",0x132d30,0x1313f8),("rsawrap",0x134020,0x1326e8),
                     ("memcpy",0x1461b0,0x1447d4),("memset",0x146358,0x14497c),
                     ("udiv",0x14cbd8,0x14b230),("umod",0x14d1a8,0x14b800)]:
        diff(r,a9,find_end(D9,off92,a9),a10,find_end(D10,off10,a10))
    # the bignum/RSA core is one block of equal size in both
    diff("bignum",0x133220,0x134020,0x1318e8,0x1326e8)
