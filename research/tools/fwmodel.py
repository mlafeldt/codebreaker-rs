# Model of CodeBreaker v9.2's per-line auto decrypt (0x1042b0 and callees),
# written from the listings (research/REVERSING.md) and checked against the
# Ghidra emulation (tools/ghidra/Emu.java). It can also encrypt, which gen.py
# uses to build inputs that reach particular paths.
#
# usage: python3 -I fwmodel.py check <unpacked.elf> <emu.out>
#   replays every list in an Emu.java output file and compares each decrypted
#   line and the crypto globals after it
#        python3 -I fwmodel.py run <unpacked.elf> <lists.txt> <out.txt>
#   decrypts lists like Emu.java does and writes the same format (primitive
#   calls aren't supported), for emudiff.py without Ghidra
import struct, sys, zlib

M32 = 0xffffffff
BEEF = 0xbeefc0de
N = 0xfffffffffffffff5          # RSA modulus
RSA_D = 11
RSA_E = 2682110966135737091     # inverse of 11 mod phi(N), see src/cb7.rs


class Image:
    BASE = 0x100000 - 0x1000

    def __init__(self, path):
        self.data = open(path, 'rb').read()

    def words(self, addr, n):
        return list(struct.unpack_from('<%dI' % n, self.data, addr - self.BASE))

    def bytes(self, addr, n):
        return self.data[addr - self.BASE:addr - self.BASE + n]


class Tables:
    def __init__(self, img):
        self.v1 = [img.words(0x289ad8 + 0x40 * i, 16) for i in range(3)]
        self.seeds = img.bytes(0x289b98, 0x500)
        self.rc4key = img.words(0x28a098, 5)
        assert img.words(0x369000, 1)[0] | (M32 << 32) == N


class Rc4:
    def __init__(self, key):
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xff
            s[i], s[j] = s[j], s[i]
        self.s, self.i, self.j = s, 0, 0

    def crypt(self, buf):
        s = self.s
        for k in range(len(buf)):
            self.i = (self.i + 1) & 0xff
            self.j = (self.j + s[self.i]) & 0xff
            s[self.i], s[self.j] = s[self.j], s[self.i]
            buf[k] ^= s[(s[self.i] + s[self.j]) & 0xff]


def le_words(ws):
    return bytearray(struct.pack('<%dI' % len(ws), *ws))


def from_le(b):
    return list(struct.unpack('<%dI' % (len(b) // 4), bytes(b)))


def num_code_lines(addr):                      # 0x1033c0
    cmd = addr >> 28
    if cmd == 3:
        return 2 if addr & 0x400000 else 1
    return 2 if 3 <= cmd <= 6 else 1


def v1_decrypt(t, addr, val):                  # 0x103410
    cmd = addr >> 28
    if cmd > 2:
        val = ((val ^ addr) - t.v1[2][cmd]) & M32
    tmp = addr ^ t.v1[0][cmd]
    x = (tmp - t.v1[1][cmd]) & M32
    addr = (tmp & 0xff000000) | ((x & 0xffff) << 8) | ((x >> 16) & 0xff)
    return addr, val


def v1_encrypt(t, addr, val):                  # inverse of v1_decrypt
    cmd = addr >> 28
    tmp = addr & 0xff000000
    x = ((addr & 0xff) << 16) | ((addr >> 8) & 0xffff)
    addr = (tmp | ((x + t.v1[1][cmd]) & 0xffffff)) ^ t.v1[0][cmd]
    if cmd > 2:
        val = addr ^ ((val + t.v1[2][cmd]) & M32)
    return addr, val


def inverse(x):                                # 0x1034e0, x odd
    return pow(x, -1, 1 << 32)


# The firmware's bignum library (32-bit limbs, little-endian lists here).
# Only the paths that 2-limb operands take are modeled.

def nn_cmp(a, b):                              # 0x133320 for equal lengths
    for x, y in zip(reversed(a), reversed(b)):
        if x != y:
            return 1 if x > y else -1
    return 0


def nn_sub(a, off, b, n):                      # 0x133298, n limbs, returns borrow
    borrow = 0
    for i in range(n):
        d = a[off + i] - b[i] - borrow
        a[off + i] = d & M32
        borrow = 1 if d < 0 else 0
    return borrow


def nn_add(a, off, b, n, m):                   # 0x133220, adds m limbs of b into n limbs
    carry = 0
    for i in range(m):
        s = a[off + i] + b[i] + carry
        a[off + i] = s & M32
        carry = s >> 32
    for i in range(m, n):
        if not carry:
            break
        s = a[off + i] + 1
        a[off + i] = s & M32
        carry = s >> 32
    return carry


def nn_mod(a, alen, b, blen):                  # 0x133948, a %= b in place
    while alen and a[alen - 1] == 0:
        alen -= 1
    while blen and b[blen - 1] == 0:
        blen -= 1
    if not blen or blen > alen:
        return
    assert blen == 2, 'only the 2-limb modulus is modeled'
    v1 = b[1]
    assert v1 >> 31, 'N is already normalized, so no shift'
    a[alen] = 0
    u = alen + 1
    while u != blen:
        i = u - blen
        if nn_cmp(a[i:i + blen], b) > 0:
            nn_sub(a, i, b, blen)
        # __udivdi3 (0x14cbd8) gives a 64-bit quotient, of which only the low
        # word is used: q is not clamped to 2^32 - 1 (Knuth D3), so it wraps
        # when the window's top limb equals v1.
        q = ((a[u - 1] << 32 | a[u - 2]) // v1) & M32
        t = [0] * (blen + 1)                   # 0x1337c0
        c = 0
        for k in range(blen):
            p = q * b[k] + c
            t[k] = p & M32
            c = p >> 32
        t[blen] = c
        if nn_sub(a, i - 1, t, blen + 1):
            if not nn_add(a, i - 1, b, blen + 1, blen):
                nn_add(a, i - 1, b, blen + 1, blen)
        u -= 1
    if nn_cmp(a[:blen], b) > 0:
        nn_sub(a, 0, b, blen)


def cb_modmul(r, x, n):                        # one 0x133670 + 0x133948 step
    p = r[0] | r[1] << 32
    q = x[0] | x[1] << 32
    a = [(p * q) >> (32 * k) & M32 for k in range(4)] + [0, 0, 0]
    nn_mod(a, 4, list(n), 2)
    return a[:2]                               # the caller copies 2 limbs back


def cb_rsa(x):
    """x^11 mod N as computed by 0x134020/0x133dd0 (x < N)."""
    n = [N & M32, N >> 32]
    a = [x & M32, x >> 32, 0, 0, 0]
    nn_mod(a, 2, list(n), 2)                   # initial reduction
    base = a[:2]
    r = list(base)
    for bit in (2, 1, 0):                      # 11 = 0b1011, below the top bit
        r = cb_modmul(r, r, n)
        if RSA_D >> bit & 1:
            r = cb_modmul(r, base, n)
    return r[0] | r[1] << 32


class Fw:
    """Globals of the per-line decrypt, initial values as in the image."""

    def __init__(self, t):
        self.t = t
        self.mode = 0          # 0x289ac8
        self.lines = 0         # 0x289acc
        self.v1 = 0            # 0x289ad0
        self.seeds = bytearray(0x500)   # 0x36dcc8
        self.kc = [0] * 5      # 0x36e1c8, key copy used by the multiplications
        self.key = [0] * 5     # 0x36e2e8
        self.bf = 0            # 0x36e2fc, BEEFC0DF seen
        self.opt = 0           # 0x36e300, option state

    def reset(self):                           # 0x104548
        self.mode = 0
        self.lines = 0

    def state(self):
        return dict(mode=self.mode, lines=self.lines, v1=self.v1, bf=self.bf, opt=self.opt,
                    key=list(self.key), kc=list(self.kc), seeds=zlib.crc32(self.seeds))

    # 0x1035b0
    def rekey(self, init, val):
        if init:
            self.opt = 0
            self.bf = 0
            self.key = list(self.t.rc4key)
            if val == 0:
                self.seeds = bytearray(0x500)
            else:
                self.seeds = bytearray(self.t.seeds)
                self.derive(val)
        else:
            if val == 0:
                self.seeds = bytearray(0x500)
            self.derive(val)
        for i in range(5):
            rc4 = Rc4(le_words(self.key))
            tab = self.seeds[0x100 * i:0x100 * (i + 1)]
            rc4.crypt(tab)
            self.seeds[0x100 * i:0x100 * (i + 1)] = tab
            k = le_words(self.key)
            rc4.crypt(k)
            self.key = from_le(k)
        self.kc = list(self.key)

    def derive(self, val):
        b = val.to_bytes(4, 'little')
        for i in range(4):
            self.key[i] = sum(self.seeds[0x100 * ((i + j) % 4) + b[j]] << (8 * j) for j in range(4))

    def seed_words(self):
        return from_le(self.seeds)

    # 0x103f60
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
                self.key = [addr ^ kc[0], val ^ kc[1], (addr - kc[2]) & M32, (val + kc[3]) & M32,
                            ((addr - val) & M32) ^ kc[4]]
        else:
            rc4 = Rc4(le_words([addr, val]))   # extra seed, kept at 0x36e308
            rc4.crypt(self.seeds)
            self.bf = 0
            self.opt = 0
        return addr, val

    # Inverse of the crypto in v7_decrypt for the current state (no state change)
    def v7_encrypt(self, addr, val):
        addr = addr * (((self.kc[0] - self.kc[1]) & M32) | 1) & M32
        val = val * (((self.kc[2] + self.kc[3]) & M32) | 1) & M32
        b = le_words([addr, val])
        Rc4(le_words(self.key)).crypt(b)
        addr, val = from_le(b)
        x = addr << 32 | val
        if x < N:
            x = pow(x, RSA_E, N)
            addr, val = x >> 32, x & M32
        return self.rounds_encrypt(addr, val)

    def rounds_encrypt(self, addr, val):
        s = self.seed_words()
        for i in range(64):
            addr = ((((addr + s[128 + i]) & M32) ^ s[i]) - (val ^ s[256 + i])) & M32
            val = ((((val - s[192 + i]) & M32) ^ s[64 + i]) + (addr ^ s[256 + i])) & M32
        return addr, val

    def is_v7(self):
        return bool(self.mode & 0x10000) or self.opt == 2

    # 0x1042b0
    def decrypt_line(self, addr, val):
        if not self.is_v7():
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
                    self.opt = (val & 0x20000) >> 16
                    return addr, val
            self.lines -= 1
            if self.opt == 2:
                self.opt = 0
                return addr, val
        if self.mode & 0xffff:
            self.mode = (self.mode - 1) & M32
            if self.mode & 0xffff == 0:
                self.mode = (self.mode >> 24) << 16
        if addr & ~1 & M32 == BEEF:
            if not self.mode & 0x10000:
                self.mode |= 0x10000
                self.rekey(1, val)
            else:
                self.rekey(0, val)
            self.bf = addr & 1
            self.lines = 1
        return addr, val


def parse_emu(path):
    """Yields (name, [(in, out, state)]) per list of an Emu.java output."""
    name, rows = None, []
    for l in open(path):
        l = l.strip()
        if l.startswith('==='):
            if name is not None:
                yield name, rows
            name, rows = l[3:].strip(), []
        elif l and not l.startswith('!'):
            p = l.split()
            st = dict(kv.split('=') for kv in p[5:])
            st = {k: ([int(x, 16) for x in v.split(',')] if ',' in v else int(v, 16)) for k, v in st.items()}
            rows.append(((int(p[0], 16), int(p[1], 16)), (int(p[3], 16), int(p[4], 16)), st))
    if name is not None:
        yield name, rows


def check(t, path):
    bad = 0
    total = 0
    for name, rows in parse_emu(path):
        fw = Fw(t)
        fw.reset()
        for i, (inp, out, st) in enumerate(rows):
            got = fw.decrypt_line(*inp)
            total += 1
            mst = fw.state()
            if got != out or mst != st:
                bad += 1
                if bad <= 20:
                    print(f'{name}:{i} in {inp[0]:08X} {inp[1]:08X}: emu {out[0]:08X} {out[1]:08X} {st}')
                    print(f'{" " * len(name)}   model {got[0]:08X} {got[1]:08X} {mst}')
                break
    print(f'model vs emu: {total} lines, {bad} lists differ')
    return bad == 0


def run(t, lists, out):
    with open(out, 'w') as f:
        for l in open(lists):
            l = l.strip()
            if not l or l.startswith('#'):
                continue
            if l.startswith('==='):
                f.write(l + '\n')
                fw = Fw(t)
                fw.reset()
                continue
            a, v = (int(x, 16) for x in l.split())
            o = fw.decrypt_line(a, v)
            s = fw.state()
            f.write('%08X %08X -> %08X %08X mode=%08X lines=%08X v1=%X bf=%X opt=%X key=%s kc=%s seeds=%08X\n' % (
                a, v, o[0], o[1], s['mode'], s['lines'], s['v1'], s['bf'], s['opt'],
                ','.join('%08X' % x for x in s['key']), ','.join('%08X' % x for x in s['kc']), s['seeds']))


if __name__ == '__main__':
    t = Tables(Image(sys.argv[2]))
    if sys.argv[1] == 'check':
        sys.exit(0 if check(t, sys.argv[3]) else 1)
    elif sys.argv[1] == 'run':
        run(t, sys.argv[3], sys.argv[4])
