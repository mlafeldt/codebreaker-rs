# Model of CodeBreaker v10's per-line auto decrypt (0x105090 and callees),
# as a diff against fwmodel.py's v9.2 model. Written from the v10 listings and
# checked against the Ghidra emulation (tools/ghidra/EmuP.java "v10"). The four
# code changes vs v9.2 are REVERSING.md §11.3; this file is their executable
# form (reset zeroes the default seeds, rekey(init) ignores val, v7_decrypt's
# key-from-line 5th word lands in beefcodf, auto always rekey(1) on a beefcode).
#
# usage: python3 -I fwmodel10.py check <CBv10.unpacked.bin> <emu.out>
#        python3 -I fwmodel10.py run <CBv10.unpacked.bin> <lists.txt> <out.txt>
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fwmodel as m
from fwmodel import M32, BEEF, N, Rc4, le_words, from_le, num_code_lines, v1_decrypt, cb_rsa, inverse


class Image10(m.Image):
    BASE = 0x100000                            # raw image, no ELF header


class Tables10:
    def __init__(self, img):
        self.v1 = [img.words(0x764be0 + 0x40 * i, 16) for i in range(3)]
        self.seeds = img.bytes(0x764ca0, 0x500)
        self.rc4key = img.words(0x7651a0, 5)
        assert img.words(0x9eb330, 1)[0] | (M32 << 32) == N


class Fw10(m.Fw):
    def __init__(self, t):
        super().__init__(t)
        self.defseeds = bytearray(t.seeds)     # 0x764ca0, live: reset zeroes it

    def reset(self):                           # 0x1052a8
        self.mode = 0
        self.lines = 0
        self.defseeds = bytearray(0x500)       # 5x memset(0x764ca0 + 0x100 i, 0, 0x100)

    # 0x104660
    def rekey(self, init, val):
        if init:
            self.opt = 0
            self.bf = 0
            self.seeds = bytearray(self.defseeds)   # val is not used
            self.key = list(self.t.rc4key)
        else:
            # no val == 0 case; byte j of the index is (val + j) & 0xff,
            # not byte j of val
            for i in range(4):
                self.key[i] = sum(self.seeds[0x100 * ((i + j) % 4) + ((val + j) & 0xff)] << (8 * j)
                                  for j in range(4))
        for i in range(5):
            rc4 = Rc4(le_words(self.key))
            tab = self.seeds[0x100 * i:0x100 * (i + 1)]
            rc4.crypt(tab)
            self.seeds[0x100 * i:0x100 * (i + 1)] = tab
            k = le_words(self.key)
            rc4.crypt(k)
            self.key = from_le(k)
        self.kc = list(self.key)

    # 0x104d40: as v9.2, except that the key-from-line path stores its 5th
    # word at key + 0x14 (beefcodf) instead of key + 0x10 (0x10505c)
    def v7_decrypt(self, addr, val):
        s = self.seed_words()
        for i in range(63, -1, -1):
            val = (((val - (addr ^ s[256 + i])) & M32) ^ s[64 + i]) + s[192 + i] & M32
            addr = (((addr + (val ^ s[256 + i])) & M32) ^ s[i]) - s[128 + i] & M32
        x = addr << 32 | val
        if x < N:
            x = cb_rsa(x)
            addr, val = x >> 32, x & M32
        b = le_words([addr, val])
        Rc4(le_words(self.key)).crypt(b)
        addr, val = from_le(b)
        addr = addr * inverse(((self.kc[0] - self.kc[1]) & M32) | 1) & M32
        val = val * inverse(((self.kc[2] + self.kc[3]) & M32) | 1) & M32
        if self.bf == 0:
            if addr & ~1 & M32 == BEEF:
                self.rekey(0, val)
                self.bf = 1
            elif self.opt != 0:
                kc = self.kc
                self.key[:4] = [addr ^ kc[0], val ^ kc[1], (addr - kc[2]) & M32, (val + kc[3]) & M32]
                self.bf = ((addr - val) & M32) ^ kc[4]
        else:
            rc4 = Rc4(le_words([addr, val]))
            rc4.crypt(self.seeds)
            self.bf = 0
            self.opt = 0
        return addr, val

    # 0x105090: V7 is mode bit 16 only (no forced line), no opt == 2 return,
    # and every beefcode reinitializes with rekey(1)
    def decrypt_line(self, addr, val):
        if not self.mode & 0x10000:
            if self.lines == 0:
                self.lines = num_code_lines(addr)
                if (addr >> 24) & 0xe == 0:
                    self.lines -= 1
                    self.v1 = 0
                    return addr, val
                if addr & ~1 & M32 == BEEF:
                    self.lines += 1
                    self.v1 = 0
                    return addr, val
                self.v1 = 1
            elif self.v1 == 0:
                self.lines -= 1
                return addr, val
            addr, val = v1_decrypt(self.t, addr, val)
            self.lines -= 1
        else:
            addr, val = self.v7_decrypt(addr, val)
            if self.lines == 0:
                self.lines = num_code_lines(addr)
                if self.lines == 1 and addr == M32:
                    self.mode = ((self.mode >> 16) << 24 | val & 0xffffff) & M32
                    self.lines = 0
                    self.opt = (self.mode >> 16) & 2
                    return addr, val
            self.lines -= 1
        if self.mode & 0xffff:
            self.mode = (self.mode - 1) & M32
            if self.mode & 0xffff == 0:
                self.mode = (self.mode >> 24) << 16
        if addr & ~1 & M32 == BEEF:
            self.mode |= 0x10000
            self.rekey(1, val)
            self.bf = addr & 1
            self.lines = 1
        return addr, val


if __name__ == '__main__':
    m.Fw = Fw10                                # check()/run() instantiate m.Fw
    t = Tables10(Image10(sys.argv[2]))
    if sys.argv[1] == 'check':
        sys.exit(0 if m.check(t, sys.argv[3]) else 1)
    elif sys.argv[1] == 'run':
        m.run(t, sys.argv[3], sys.argv[4])
