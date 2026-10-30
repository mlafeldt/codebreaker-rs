"""Input validation and exact expected-difference records for research CLIs."""
import hashlib
import json
from pathlib import Path


def read_groups(path):
    groups, seen, rows = [], set(), None
    for number, text in enumerate(Path(path).read_text().splitlines(), 1):
        text = text.strip()
        if not text or text.startswith('#'):
            continue
        if text.startswith('==='):
            name = text[3:].strip()
            if not name or name in seen:
                raise ValueError(f'{path}:{number}: empty or duplicate list name {name!r}')
            seen.add(name)
            rows = []
            groups.append((name, rows))
        elif rows is None:
            raise ValueError(f'{path}:{number}: row before a list header')
        else:
            rows.append(text)
    if not groups:
        raise ValueError(f'{path}: no lists')
    return groups


def uint(text, bits=32):
    value = int(text, 16)
    if not 0 <= value < 1 << bits:
        raise ValueError(f'out-of-range {bits}-bit word: {text!r}')
    return value


def output_row(text):
    parts = text.split()
    if parts[0].startswith('!'):
        arity = {'!inv': 1, '!mul': 2, '!rsa': 1}.get(parts[0])
        if arity is None or len(parts) != arity + 3 or parts[-2] != '->':
            raise ValueError(f'malformed primitive row: {text}')
        bits = 64 if parts[0] == '!rsa' else 32
        return 'primitive', (parts[0], *[uint(x, bits) for x in parts[1:-2]]), uint(parts[-1], bits), {}
    if len(parts) < 6 or parts[2] != '->':
        raise ValueError(f'malformed output row: {text}')
    fields = {}
    for item in parts[5:]:
        if item.count('=') != 1:
            raise ValueError(f'malformed state field: {item!r}')
        key, value = item.split('=')
        if not key or not value or key in fields:
            raise ValueError(f'empty or duplicate state field: {item!r}')
        fields[key] = value
    return 'code', (uint(parts[0]), uint(parts[1])), (uint(parts[3]), uint(parts[4])), fields


def align(left, right):
    if [name for name, _ in left] != [name for name, _ in right]:
        raise ValueError('list names or order differ')
    for (name, rows), (_, others) in zip(left, right):
        if len(rows) != len(others):
            raise ValueError(f'{name}: row counts differ ({len(rows)} vs {len(others)})')


def add_expectations(parser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--expected', help='require exactly these input hashes and difference records')
    group.add_argument('--write-differences', help='export difference records; exit status is still strict')


def finish(differences, args, inputs, hard_failures=0):
    observation = {
        'version': 1,
        'inputs': [hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in inputs],
        'differences': differences,
    }
    observation = json.loads(json.dumps(observation))  # portable code-word tuples
    if args.write_differences:
        target = Path(args.write_differences)
        if target.resolve() in {Path(path).resolve() for path in inputs}:
            raise ValueError('difference output would overwrite an input file')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(observation, indent=2) + '\n')
    if args.expected:
        expected = json.loads(Path(args.expected).read_text())
        if (not isinstance(expected, dict) or set(expected) != set(observation)
                or type(expected.get('version')) is not int or expected['version'] != 1
                or not isinstance(expected.get('inputs'), list)
                or not all(isinstance(value, str) and len(value) == 64
                           and all(char in '0123456789abcdef' for char in value)
                           for value in expected['inputs'])
                or not isinstance(expected.get('differences'), list)
                or not all(isinstance(value, dict) for value in expected['differences'])):
            raise ValueError('unsupported expected-difference format')
        if expected != observation:
            print('Expected input hashes or difference records do not match.')
            return 1
        if hard_failures:
            print('Model or plaintext failures cannot be accepted as expected differences.')
            return 1
        print('Input hashes and all expected difference records match.')
        return 0
    return int(bool(differences or hard_failures))
