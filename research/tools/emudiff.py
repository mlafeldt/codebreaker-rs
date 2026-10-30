# Compare firmware outputs with the crate, and every logged model state with
# emulation. Crate state comparison is limited to lines, effective scheme, and
# key/beefcodf while V7 is active; it does not compare seeds or the V7 counter.
# usage: python3 -I emudiff.py <unpacked.elf> <emu.out> <crate.out> [plain.txt]
# Exit 0: agreement / exact --expected baseline; 1: differences; 2: bad input.
# --write-differences exports a baseline for review without accepting it.
import argparse
import os
import struct
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from comparison import add_expectations, align, finish, output_row, read_groups, uint
from fwmodel import M32, N, RSA_D, Fw, Image, Tables


def parse_outputs(path, firmware):
    groups, primitives = [], []
    for name, texts in read_groups(path):
        rows = []
        for index, text in enumerate(texts):
            kind, inp, out, raw = output_row(text)
            if kind == 'primitive':
                if not firmware:
                    raise ValueError(f'{path}: unexpected primitive in crate output')
                primitives.append((name, index, inp, out))
                continue
            required = ({'mode', 'lines', 'v1', 'bf', 'opt', 'key', 'kc', 'seeds'} if firmware
                        else {'scheme', 'lines', 'bf', 'init', 'key'})
            if set(raw) != required:
                raise ValueError(f'{path}: unexpected state fields in {name}:{index}')
            state = {}
            for key, value in raw.items():
                if key == 'scheme':
                    if value not in ('Raw', 'V1', 'V7'):
                        raise ValueError(f'{path}: invalid scheme {value!r}')
                    state[key] = value
                elif key in ('key', 'kc'):
                    state[key] = [uint(word) for word in value.split(',')]
                    if len(state[key]) != 5:
                        raise ValueError(f'{path}: expected five key words')
                else:
                    state[key] = uint(value)
            rows.append((inp, out, state))
        groups.append((name, rows))
    return groups, primitives


def parse_plain(path):
    groups = []
    for name, texts in read_groups(path):
        rows = []
        for text in texts:
            if text.startswith('!'):
                raise ValueError(f'{path}: primitive in plaintext input')
            words = text.split()
            if len(words) != 2:
                raise ValueError(f'{path}: malformed plaintext row')
            rows.append(tuple(uint(word) for word in words))
        groups.append((name, rows))
    return groups


def fw_scheme(state):
    return 'V7' if state['mode'] & 0x10000 else ('V1' if state['v1'] else 'Raw')


def state_differences(firmware, crate):
    differences = {}
    if firmware['lines'] != crate['lines']:
        differences['lines'] = [firmware['lines'], crate['lines']]
    fs, cs = fw_scheme(firmware), crate['scheme']
    if firmware['lines'] == 0 and firmware['opt'] != 2 and fs != 'V7':
        fs, cs = fs == 'V7', cs == 'V7'  # raw/V1 flag is overwritten before use
    if fs != cs:
        differences['scheme'] = [fs, cs]
    if firmware['mode'] & 0x10000:
        for key in ('key', 'bf'):
            if firmware[key] != crate[key]:
                differences[key] = [firmware[key], crate[key]]
    return differences


def main(argv=None, *, fw_class=Fw, image_class=Image, table_class=Tables):
    parser = argparse.ArgumentParser(description='Compare firmware, crate and model results.')
    parser.add_argument('image')
    parser.add_argument('firmware')
    parser.add_argument('crate')
    parser.add_argument('plain', nargs='?')
    add_expectations(parser)
    args = parser.parse_args(argv)
    try:
        tables = table_class(image_class(args.image))
        emu, primitives = parse_outputs(args.firmware, True)
        crate, _ = parse_outputs(args.crate, False)
        align(emu, crate)
        plain = parse_plain(args.plain) if args.plain else None
        if plain is not None:
            align(emu, plain)
        lines = out_diff = state_diff = model_bad = plain_bad = primitive_bad = 0
        differences, groups = [], {}
        for group_index, ((name, rows), (_, crows)) in enumerate(zip(emu, crate)):
            model = fw_class(tables)
            model.reset()
            first_out = first_state = None
            plain_failed = False
            for i, ((inp, out, state), (cinp, cout, cstate)) in enumerate(zip(rows, crows)):
                if inp != cinp:
                    raise ValueError(f'{name}:{i}: input words differ')
                lines += 1
                modeled = model.decrypt_line(*inp)
                if modeled != out or model.state() != state:
                    if not model_bad:
                        print(f'MODEL {name}:{i} differs from emulation')
                    model_bad += 1
                    differences.append({'kind': 'model', 'list': name, 'line': i,
                                        'firmware': [out, state], 'model': [modeled, model.state()]})
                if out != cout:
                    if first_out is None:
                        first_out = i
                        print(f'OUTPUT {name}:{i} in {inp[0]:08X} {inp[1]:08X}: '
                              f'fw {out[0]:08X} {out[1]:08X} crate {cout[0]:08X} {cout[1]:08X}')
                    differences.append({'kind': 'output', 'list': name, 'line': i,
                                        'input': inp, 'firmware': out, 'crate': cout})
                elif first_out is None:
                    fields = state_differences(state, cstate)
                    if fields:
                        if first_state is None:
                            first_state = i
                            print(f'STATE {name}:{i} {fields}')
                        differences.append({'kind': 'state', 'list': name, 'line': i, 'fields': fields})
                if plain is not None:
                    want = plain[group_index][1][i]
                    if out != want:
                        if not plain_failed:
                            print(f'ENCRYPT {name}:{i} want {want[0]:08X} {want[1]:08X} '
                                  f'firmware {out[0]:08X} {out[1]:08X}')
                        plain_failed = True
                        differences.append({'kind': 'plaintext', 'list': name, 'line': i,
                                            'expected': want, 'firmware': out})
            group = name.split('-')[0].rstrip('0123456789')
            counts = groups.setdefault(group, [0, 0, 0])
            counts[0] += 1
            if first_out is not None:
                out_diff += 1
                counts[1] += 1
            elif first_state is not None:
                state_diff += 1
                counts[2] += 1
            plain_bad += plain_failed
        for name, index, inp, actual in primitives:
            op, *words = inp
            if op == '!inv':
                want = pow(words[0], -1, 1 << 32)
            elif op == '!mul':
                want = words[0] * pow(words[1] | 1, -1, 1 << 32) & M32
            else:
                want = pow(words[0], RSA_D, N)
            if actual != want:
                primitive_bad += 1
                print(f'PRIM {name}:{index} {inp}: firmware {actual:X} exact {want:X}')
                differences.append({'kind': 'primitive', 'list': name, 'line': index,
                                    'input': inp, 'firmware': actual, 'exact': want})
        if not lines and not primitives:
            raise ValueError('no output rows to compare')
        print(f'\n{len(emu)} lists, {lines} lines: {out_diff} lists with output diffs, '
              f'{state_diff} more with state diffs only, model mismatches {model_bad}'
              + (f', encryption round-trip failures {plain_bad}' if plain is not None else ''))
        for group, (count, outputs, states) in sorted(groups.items()):
            print(f'  {group:10} lists={count:4} output_diff={outputs:4} state_diff={states:4}')
        if primitives:
            print(f'primitives: {len(primitives)} calls, {primitive_bad} differ from exact math')
        inputs = [args.image, args.firmware, args.crate] + ([args.plain] if args.plain else [])
        return finish(differences, args, inputs, hard_failures=model_bad + plain_bad)
    except (OSError, ValueError, KeyError, IndexError, struct.error, AssertionError) as exc:
        parser.exit(2, f'{parser.prog}: {exc or "invalid image or output data"}\n')


if __name__ == '__main__':
    sys.exit(main())
