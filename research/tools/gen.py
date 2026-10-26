# Generates input lists for tools/ghidra/Emu.java and compare/examples/emucmp.rs.
#
# usage: python3 -I gen.py <unpacked.elf> <kind> <out.txt> [seed]
#   kind = random    random words, plus V1 beefcodes followed by random V7
#                    cipher text
#          targeted  plain text programs encrypted with fwmodel (every
#                    command nibble and line count in every mode, beefcodes,
#                    options, RSA boundaries), plus primitive calls
#          plain     plain text programs for the encryption check (encrypted
#                    by emucmp.rs, not here)
#          report    the short lists used as test vectors in REVERSING.md
import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fwmodel import BEEF, M32, N, Fw, Image, Tables, v1_encrypt

R = None


def rw():
    return R.getrandbits(32)


def code(cmd, bit22=None):
    a = (cmd << 28) | (rw() & 0x0fffffff)
    if bit22 is not None:
        a = (a & ~0x400000) | (0x400000 if bit22 else 0)
    return a


class Prog:
    """Encrypts plain text lines for the firmware state reached so far.
    enc: 'raw' or 'v1' for a code start outside V7 mode (ignored otherwise),
    'cipher' to pass the word through as cipher text."""

    def __init__(self, t, name):
        self.fw = Fw(t)
        self.fw.reset()
        self.t = t
        self.name = name
        self.lines = []

    def add(self, a, v, enc='v1'):
        fw = self.fw
        if enc == 'cipher':
            c = (a, v)
        elif fw.is_v7():
            c = fw.v7_encrypt(a, v)
        elif fw.lines == 0:
            # Keep the code start detectable as intended (beefcodes aside)
            if a & ~1 & M32 != BEEF:
                if enc == 'raw':
                    a &= ~0x0e000000
                elif (a >> 24) & 0x0e == 0x0a:
                    a ^= 0x02000000
            c = (a, v) if enc == 'raw' else v1_encrypt(self.t, a, v)
        else:
            c = v1_encrypt(self.t, a, v) if fw.v1 else (a, v)
        fw.decrypt_line(*c)
        self.lines.append(c)
        return self

    def v7_from_rounds(self, a, v):
        """Cipher text whose 64 decryption rounds give a:v (RSA boundary)."""
        return self.add(*self.fw.rounds_encrypt(a, v), enc='cipher')

    def text(self):
        return '=== %s\n%s\n' % (self.name, '\n'.join('%08X %08X' % c for c in self.lines))


def default_v7(p):
    # V1-encrypted BEEFC0DE 00000000 = B4336FA9 4DFEFB79, the CMGSCCC default
    return p.add(BEEF, 0, 'v1')


def random_lists(t, n):
    out = []
    for k in range(n):
        p = Prog(t, f'rand{k}')
        for i in range(R.randint(5, 40)):
            r = R.random()
            if r < 0.15:
                p.add(rw() & 0xf1ffffff, rw(), 'cipher')            # raw-looking
            elif r < 0.2:
                p.add(BEEF | R.getrandbits(1), R.choice([0, rw()]), 'v1')
            elif r < 0.22:
                p.add(BEEF | R.getrandbits(1), R.choice([0, rw()]), 'raw')
            else:
                p.add(rw(), rw(), 'cipher')
        out.append(p)
    return out


MODES = ['raw', 'v1', 'v7']


def enter(p, mode):
    if mode == 'v7':
        p.add(BEEF, R.choice([0, rw()]), 'v1')


def targeted(t):
    out = []

    # Every command nibble, bit 22 both ways, in every mode, with two more
    # lines so continuation and the next code start are both seen.
    for mode in MODES:
        for cmd in range(16):
            for b22 in (0, 1):
                for nxt in ('raw', 'v1'):
                    p = Prog(t, f'cmd-{mode}-{cmd:X}-b22={b22}-{nxt}')
                    enter(p, mode)
                    p.add(code(cmd, b22), rw(), mode if mode != 'v7' else 'v1')
                    p.add(code(R.randrange(16)), rw(), nxt)
                    p.add(code(R.randrange(16)), rw(), nxt)
                    p.add(code(R.randrange(16)), rw(), nxt)
                    out.append(p)

    # V1 cmd 3 whose bit 22 differs between plain and cipher text
    for b22 in (0, 1):
        for k in range(4):
            while True:
                a = code(3, b22)
                if bool(v1_encrypt(t, a, 0)[0] & 0x400000) != bool(b22):
                    break
            p = Prog(t, f'cmd3-flip-b22={b22}-{k}')
            p.add(a, rw(), 'v1').add(code(2), rw(), 'v1').add(code(2), rw(), 'raw').add(code(2), rw(), 'v1')
            out.append(p)

    # Beefcodes in every mode and position
    for mode in MODES:
        for bc in (BEEF, BEEF | 1):
            for val in (0, rw()):
                for enc in ('raw', 'v1'):
                    for pos in ('start', 'cont'):
                        p = Prog(t, f'beef-{mode}-{bc:08X}-{val:08X}-{enc}-{pos}')
                        enter(p, mode)
                        if pos == 'cont':
                            p.add(code(4), rw(), enc if mode != 'v7' else 'v1')
                        p.add(bc, val, enc)
                        for _ in range(4):
                            p.add(code(2), rw(), R.choice(['raw', 'v1']))
                        out.append(p)
    # BEEFC0DF extra seed line variants, and repeated beefcodes
    for mode in ('v1', 'v7'):
        for extra in ('plain', 'BEEFC0DE', 'BEEFC0DF', 'BEEFC0DE0', 'FFFFFFFF'):
            for val in (0, rw()):
                p = Prog(t, f'beefdf-{mode}-extra={extra}-{val:08X}')
                enter(p, mode)
                p.add(BEEF | 1, val, 'v1')
                if extra == 'plain':
                    p.add(rw(), rw())
                elif extra == 'FFFFFFFF':
                    p.add(M32, 0x30001)
                elif extra == 'BEEFC0DE0':
                    p.add(BEEF, 0)
                else:
                    p.add(int(extra, 16), rw())
                for _ in range(4):
                    p.add(code(R.choice([0, 1, 2, 4, 9])), rw())
                out.append(p)
    for first in (0, rw()):
        for second in (0, rw()):
            for third in (0, rw()):
                p = Prog(t, f'beef3-{first:08X}-{second:08X}-{third:08X}')
                p.add(BEEF, first).add(BEEF, second).add(BEEF | 1, third).add(rw(), rw())
                p.add(code(2), rw()).add(code(4), rw()).add(BEEF, 0).add(code(1), rw())
                out.append(p)

    # FFFFFFFF encryption options
    def after(p, n):
        for _ in range(n):
            r = R.random()
            if r < 0.1:
                p.add(BEEF | R.getrandbits(1), R.choice([0, rw()]), R.choice(['raw', 'v1']))
                if p.fw.bf:
                    p.add(rw(), rw())
            elif r < 0.2:
                p.add(M32, R.getrandbits(24) & 0xff0000 | R.choice([0, 1, 2, 3, 5]))
            else:
                p.add(code(R.choice([0, 1, 2, 3, 4, 5, 9, 0xd])), rw(), R.choice(['raw', 'v1']))

    for b16 in (0, 1):
        for b17 in (0, 1):
            for cnt in (0, 1, 2, 3, 0xffff):
                for k in range(3):
                    hi = R.getrandbits(6) << 18 if k else 0
                    v = hi | b17 << 17 | b16 << 16 | cnt
                    p = Prog(t, f'opt-{v:08X}-{k}')
                    enter(p, 'v7')
                    if k == 2:
                        p.add(code(2), rw())
                    p.add(M32, v)
                    after(p, 10)
                    out.append(p)
    for k in range(40):
        p = Prog(t, f'optmix{k}')
        enter(p, R.choice(MODES))
        after(p, 25)
        out.append(p)
    # FFFFFFFF not at a code start, and in V1 mode
    for mode in ('v1', 'v7', 'raw'):
        p = Prog(t, f'ffff-cont-{mode}')
        enter(p, mode)
        p.add(code(4), rw(), 'v1').add(M32, 0x30002).add(code(2), rw()).add(code(2), rw())
        out.append(p)
        p = Prog(t, f'ffff-start-{mode}')
        enter(p, mode)
        p.add(M32, 0x30002, 'v1').add(code(2), rw()).add(code(2), rw()).add(code(2), rw())
        out.append(p)

    # RSA boundaries: values after the 64 rounds
    for x in (0, 1, 2, M32, 1 << 32, N - 2, N - 1, N, N + 1, (1 << 64) - 1):
        p = Prog(t, f'rsa-{x:016X}')
        enter(p, 'v7')
        p.v7_from_rounds(x >> 32, x & M32)
        p.add(code(2), rw())
        out.append(p)

    text = ''.join(p.text() for p in out)

    # Primitives
    prims = ['=== primitives']
    edge = [0, 1, 2, 3, 5, 0x7fffffff, 0x80000000, 0x80000001, 0xfffffffd, 0xfffffffe, M32]
    for b in edge + [rw() for _ in range(20)]:
        prims.append(f'!inv {b | 1:08X}')
        prims.append(f'!mul {rw():08X} {b:08X}')
        prims.append(f'!mul {M32:08X} {b:08X}')
    for x in [0, 1, 2, 3, M32, 1 << 32, (1 << 32) + 1, N - 2, N - 1, 1 << 63, (1 << 63) - 1] + \
            [R.getrandbits(64) % N for _ in range(20)] + [R.getrandbits(32) for _ in range(5)]:
        prims.append(f'!rsa {x:016X}')
    return text + '\n'.join(prims) + '\n'


def plain_lists(t, n):
    """Plain text for the encryption check: default V7 key, then a mix of
    codes, beefcodes and BEEFC0DF extra lines. V1 code starts avoid plain top
    bytes whose cipher text would look unencrypted."""
    out = []
    for k in range(n):
        lines = []
        v1 = k % 3 == 0
        if not v1:
            lines.append((BEEF, 0))
        for i in range(R.randint(5, 30)):
            r = R.random()
            if r < 0.1:
                bc = BEEF | R.getrandbits(1)
                lines.append((bc, R.choice([0, rw()])))
                if bc & 1:
                    r2 = R.random()
                    lines.append((BEEF | R.getrandbits(1), rw()) if r2 < 0.2 else (rw(), rw()))
            else:
                while True:
                    a = rw()
                    if (a >> 24) & 0x0e != 0x0a:
                        break
                lines.append((a, rw()))
        out.append(f'=== plain{k}\n' + '\n'.join('%08X %08X' % c for c in lines))
    return '\n'.join(out) + '\n'


def report_lists(t):
    """Short lists used as test vectors in REVERSING.md."""
    out = []

    def prog(name, lines):
        p = Prog(t, name)
        for l in lines:
            p.add(*l)
        out.append(p)

    d = (BEEF, 0, 'v1')   # B4336FA9 4DFEFB79
    # BEEFC0DF whose extra seed line is itself a beefcode
    prog('enc-df-extra-de', [d, (BEEF | 1, 0), (BEEF, 0x12345678), (0x01234567, 0x89ABCDEF),
                             (0x9029BEAC, 0x0C0A9225)])
    prog('enc-df-extra-df', [d, (BEEF | 1, 0xB16B00B5), (BEEF | 1, 0x12345678), (0x01234567, 0x89ABCDEF),
                             (0x9029BEAC, 0x0C0A9225), (0x201F6024, 0)])
    # The line after a beefcode is never a code start, so option lines need
    # a code in between (x)
    x = (0x9029BEAC, 0x0C0A9225)
    # Options: V7 off for two decrypted lines; the raw code in between doesn't count
    prog('opt-v7-off-2', [d, x, (M32, 0x00000002), (0x2043AFCC, 0x2411FFFF, 'v1'), (0x0031789A, 0x63, 'raw'),
                          (0x201F6024, 0, 'v1'), (0x2096F5B8, 0xBE), (0x9029BEAC, 0x0C0A9225)])
    # Options: V7 off for good (counter 0), then a beefcode starts over with the default key
    prog('opt-v7-off-beef', [d, (BEEF | 1, 0xB16B00B5), (0x01234567, 0x89ABCDEF), (M32, 0),
                             (0x2043AFCC, 0x2411FFFF, 'v1'), (BEEF, 0, 'v1'), (0x2096F5B8, 0xBE)])
    # Options: bit 17 takes the key from the next line; the multiplications keep the old key
    prog('opt-key', [d, x, (M32, 0x00030000), (0x12345678, 0x9ABCDEF0), (0x2043AFCC, 0x2411FFFF),
                     (0x201F6024, 0), (BEEF, 0), (0x2096F5B8, 0xBE)])
    # Options: bit 17 with V7 off: one V7 line (new key), then V1 for 1 line, then V7 again
    prog('opt-key-v7-off', [d, x, (M32, 0x00020001), (0x12345678, 0x9ABCDEF0), (0x2043AFCC, 0x2411FFFF, 'v1'),
                            (0x201F6024, 0), (0x2096F5B8, 0xBE)])
    # FFFFFFFF that isn't an option line: after a beefcode, and as the 2nd line of a code
    prog('ffff-after-beef', [d, (M32, 0x00000001), (0x2043AFCC, 0x2411FFFF), (0x201F6024, 0)])
    prog('ffff-2nd-line', [d, x, (0x4043AFCC, 0x00020001), (M32, 0x00000001), (0x2043AFCC, 0x2411FFFF),
                           (0x201F6024, 0)])
    # The line after a beefcode is a continuation even if it starts a 2-line
    # code, so the code's 2nd line is read as a code start (here: an option)
    prog('beef-phase', [d, (0x4043AFCC, 0x00020001), (M32, 0x00000001), (0x2043AFCC, 0x2411FFFF, 'v1'),
                        (0x201F6024, 0)])
    # RSA inputs (values after the 64 rounds) that the firmware's bignum code
    # gets wrong: N - 1, the start of the always-wrong range, and a value
    # outside it whose square lands in it
    p = Prog(t, 'rsa-wrong')
    p.add(*d)
    for x in (N - 1, 0xFFFFFFFF80000000, 0x1BFCD151A41D1904, 0xFFFFFFFF7FFFFFFF):
        p.v7_from_rounds(x >> 32, x & M32)
    out.append(p)
    return ''.join(p.text() for p in out)


if __name__ == '__main__':
    t = Tables(Image(sys.argv[1]))
    R = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 1)
    kind = sys.argv[2]
    if kind == 'random':
        text = ''.join(p.text() for p in random_lists(t, 120))
    elif kind == 'targeted':
        text = targeted(t)
    elif kind == 'plain':
        text = plain_lists(t, 120)
    elif kind == 'report':
        text = report_lists(t)
    open(sys.argv[3], 'w').write(text)
