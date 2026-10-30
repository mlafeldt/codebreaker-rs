# Compare two EmuP outputs, including every row and primitive result.
# usage: python3 -I cmpout.py <a.out> <b.out> [max-first-lines]
# Exit 0: agreement / exact --expected baseline; 1: differences; 2: bad input.
import argparse
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from comparison import add_expectations, align, finish, output_row, read_groups


def main(argv=None):
    parser = argparse.ArgumentParser(description='Compare complete firmware output logs.')
    parser.add_argument('left')
    parser.add_argument('right')
    parser.add_argument('max_first_lines', nargs='?', type=int, default=8)
    add_expectations(parser)
    args = parser.parse_args(argv)
    try:
        if args.max_first_lines < 0:
            raise ValueError('max-first-lines must be nonnegative')
        left, right = read_groups(args.left), read_groups(args.right)
        align(left, right)
        differences, first = [], []
        nout = nstate = nlines = nprim = 0
        for (name, rows), (_, others) in zip(left, right):
            has_output = has_state = False
            for i, (text, other_text) in enumerate(zip(rows, others)):
                kind, inp, out, state = output_row(text)
                other_kind, other_inp, other_out, other_state = output_row(other_text)
                if kind != other_kind or inp != other_inp:
                    raise ValueError(f'{name}:{i}: inputs or row kinds differ')
                nlines += 1
                if kind == 'primitive':
                    differs = out != other_out
                    nprim += differs
                else:
                    differs = out != other_out or state != other_state
                    has_output |= out != other_out
                    has_state |= state != other_state
                if differs:
                    differences.append({'kind': kind, 'list': name, 'line': i,
                                        'input': inp, 'left': [out, state], 'right': [other_out, other_state]})
                    if len(first) < args.max_first_lines:
                        first.append(f'{name}:{i}: {text} | {other_text}')
            nout += has_output
            nstate += has_state and not has_output
        if not nlines:
            raise ValueError('no output rows to compare')
        print(f'{len(left)} lists, {nlines} lines: {nout} lists output differ, '
              f'{nstate} state-only, {nprim} primitive differ')
        for row in first:
            print('  ' + row)
        return finish(differences, args, [args.left, args.right])
    except (OSError, ValueError) as exc:
        parser.exit(2, f'{parser.prog}: {exc}\n')


if __name__ == '__main__':
    sys.exit(main())
