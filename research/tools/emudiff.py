# Compares Emu.java output (firmware) with emucmp.rs output (crate) list by
# list, and checks the firmware model against both.
#
# usage: python3 -I emudiff.py <unpacked.elf> <emu.out> <crate.out> [plain.txt]
#   With plain.txt (the plain text that was encrypted by the crate to make the
#   emulator's input), also checks that the firmware decrypts it back.
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fwmodel import M32, N, RSA_D, Fw, Image, Tables, parse_emu


def parse_crate(path):
    name, rows = None, []
    for l in open(path):
        l = l.strip()
        if l.startswith('==='):
            if name is not None:
                yield name, rows
            name, rows = l[3:].strip(), []
        elif l:
            p = l.split()
            st = dict(kv.split('=') for kv in p[5:])
            st['lines'] = int(st['lines'], 16)
            st['key'] = [int(x, 16) for x in st['key'].split(',')]
            rows.append(((int(p[0], 16), int(p[1], 16)), (int(p[3], 16), int(p[4], 16)), st))
    if name is not None:
        yield name, rows


def parse_plain(path):
    name, rows, out = None, [], {}
    for l in open(path):
        l = l.strip()
        if l.startswith('==='):
            name = l[3:].strip()
            out[name] = rows = []
        elif l and not l.startswith('!'):
            a, v = l.split()
            rows.append((int(a, 16), int(v, 16)))
    return out


def check_primitives(path):
    """Checks Emu.java primitive calls against the math src/ implements:
    mod_inverse, mul_decrypt (a * inverse(b | 1)) and rsa_crypt/mod_pow."""
    n = bad = 0
    for l in open(path):
        p = l.split()
        if not l.startswith('!'):
            continue
        n += 1
        got = int(p[-1], 16)
        if p[0] == '!inv':
            want = pow(int(p[1], 16), -1, 1 << 32)
        elif p[0] == '!mul':
            want = int(p[1], 16) * pow(int(p[2], 16) | 1, -1, 1 << 32) & M32
        elif p[0] == '!rsa':
            want = pow(int(p[1], 16), RSA_D, N)
        if got != want:
            bad += 1
            print(f'PRIM {l.strip()} want {want:X}')
    if n:
        print(f'primitives: {n} calls, {bad} differ from src/ math')


def fw_scheme(st):
    return 'V7' if st['mode'] & 0x10000 else ('V1' if st['v1'] else 'Raw')


def main():
    t = Tables(Image(sys.argv[1]))
    emu = list(parse_emu(sys.argv[2]))
    crate = list(parse_crate(sys.argv[3]))
    plain = parse_plain(sys.argv[4]) if len(sys.argv) > 4 else None
    lines = out_diff = state_diff = model_bad = plain_bad = 0
    groups = {}
    assert len(crate) == len(emu)
    for (name, rows), (cname, crows) in zip(emu, crate):
        assert cname == name and len(crows) == len(rows), name
        fw = Fw(t)
        fw.reset()
        first_out = first_state = None
        for i, ((inp, out, st), (cinp, cout, cst)) in enumerate(zip(rows, crows)):
            assert inp == cinp
            lines += 1
            if fw.decrypt_line(*inp) != out or fw.state() != st:
                if not model_bad:
                    print(f'MODEL {name}:{i} differs from emulation')
                model_bad += 1
            if first_out is None and out != cout:
                first_out = i
            if first_out is None and first_state is None:
                # Compare what the crate has a counterpart for. The crate
                # keeps its key after leaving V7 (it never does), and only
                # tracks code_lines/scheme in auto mode.
                diffs = []
                if st['lines'] != cst['lines']:
                    diffs.append(f"lines fw={st['lines']} crate={cst['lines']}")
                if fw_scheme(st) != cst['scheme']:
                    diffs.append(f"scheme fw={fw_scheme(st)} crate={cst['scheme']}")
                if st['mode'] & 0x10000 and st['key'] != cst['key']:
                    diffs.append('key')
                if st['mode'] & 0x10000 and st['bf'] != int(cst['bf']):
                    diffs.append(f"beefcodf fw={st['bf']} crate={cst['bf']}")
                if diffs:
                    first_state = (i, diffs)
        if plain is not None:
            want = plain[name]
            got = [out for _, out, _ in rows]
            if got != want:
                plain_bad += 1
                j = next(k for k in range(len(want)) if got[k] != want[k])
                print(f'ENCRYPT {name}:{j} plain {want[j][0]:08X} {want[j][1]:08X} '
                      f'-> crate cipher {rows[j][0][0]:08X} {rows[j][0][1]:08X} -> fw {got[j][0]:08X} {got[j][1]:08X}'
                      f'  context: {[f"{a:08X} {v:08X}" for a, v in want[max(0, j - 3):j]]}')
        g = name.split('-')[0].rstrip('0123456789')
        groups.setdefault(g, [0, 0, 0])
        groups[g][0] += 1
        if first_out is not None:
            out_diff += 1
            groups[g][1] += 1
            i = first_out
            ctx = [f'{a:08X} {v:08X}->{o[0]:08X} {o[1]:08X}' for (a, v), o, _ in rows[max(0, i - 3):i]]
            print(f'OUTPUT {name}:{i} in {rows[i][0][0]:08X} {rows[i][0][1]:08X}: '
                  f'fw {rows[i][1][0]:08X} {rows[i][1][1]:08X} crate {crows[i][1][0]:08X} {crows[i][1][1]:08X}'
                  f'  fw state {fw_scheme(rows[i][2])} mode={rows[i][2]["mode"]:08X} opt={rows[i][2]["opt"]}'
                  f'  before: {ctx}')
        elif first_state is not None:
            state_diff += 1
            groups[g][2] += 1
            print(f'STATE  {name}:{first_state[0]} {first_state[1]}')
    print(f'\n{len(emu)} lists, {lines} lines: {out_diff} lists with output diffs, '
          f'{state_diff} more with state diffs only, model mismatches {model_bad}'
          + (f', encryption round-trip failures {plain_bad}' if plain is not None else ''))
    for g, (n, o, s) in sorted(groups.items()):
        print(f'  {g:10} lists={n:4} output_diff={o:4} state_diff={s:4}')
    check_primitives(sys.argv[2])


main()
