"""CLI regressions for incomplete comparisons and false success statuses."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib


TOOLS = Path(__file__).resolve().parents[1]


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, content):
        path = self.root / name
        path.write_text(content)
        return path

    def run_tool(self, tool, *args):
        return subprocess.run(
            [sys.executable, '-I', str(TOOLS / tool), *map(str, args)],
            capture_output=True, text=True,
        )

    def logs(self, right_val='00000001'):
        left = self.write('left.out', '=== demo\n00000000 00000001 -> 00000000 00000001 mode=0\n')
        right = self.write('right.out', f'=== demo\n00000000 00000001 -> 00000000 {right_val} mode=0\n')
        return left, right

    def test_missing_tail_is_invalid(self):
        left, right = self.logs()
        with left.open('a') as out:
            out.write('00000000 00000002 -> 00000000 00000002 mode=0\n')
        result = self.run_tool('cmpout.py', left, right)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('row', result.stderr.lower())

    def test_duplicate_names_are_invalid(self):
        left, right = self.logs()
        for path in (left, right):
            with path.open('a') as out:
                out.write('=== demo\n00000000 00000001 -> 00000000 00000001 mode=0\n')
        result = self.run_tool('cmpout.py', left, right)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('duplicate', result.stderr.lower())

    def test_output_and_primitive_differences_fail(self):
        left, right = self.logs('00000002')
        self.assertEqual(self.run_tool('cmpout.py', left, right).returncode, 1)
        left.write_text('=== primitive\n!inv 3 -> AAAAAAAB\n')
        right.write_text('=== primitive\n!inv 3 -> 00000000\n')
        self.assertEqual(self.run_tool('cmpout.py', left, right).returncode, 1)

    def test_equal_logs_succeed(self):
        self.assertEqual(self.run_tool('cmpout.py', *self.logs()).returncode, 0)

    def test_state_only_differences_fail(self):
        left, right = self.logs()
        right.write_text(right.read_text().replace('mode=0', 'mode=1'))
        result = self.run_tool('cmpout.py', left, right)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('1 state-only', result.stdout)

    def test_export_cannot_overwrite_an_input(self):
        left, right = self.logs()
        original = left.read_bytes()
        result = self.run_tool('cmpout.py', left, right, '--write-differences', left)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(left.read_bytes(), original)

    def test_malformed_expectation_is_invalid(self):
        left, right = self.logs()
        baseline = self.write('expected.json', '{"version": 1, "differences": false}')
        result = self.run_tool('cmpout.py', left, right, '--expected', baseline)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_expected_differences_are_exact_and_input_bound(self):
        left, right = self.logs('00000002')
        baseline = self.root / 'expected.json'
        result = self.run_tool('cmpout.py', left, right, '--write-differences', baseline)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(json.loads(baseline.read_text())['differences'])
        result = self.run_tool('cmpout.py', left, right, '--expected', baseline)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        right.write_text(right.read_text().replace('00000002 mode', '00000003 mode'))
        result = self.run_tool('cmpout.py', left, right, '--expected', baseline)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_stale_expectation_does_not_hide_a_resolved_difference(self):
        left, right = self.logs('00000002')
        baseline = self.root / 'expected.json'
        self.run_tool('cmpout.py', left, right, '--write-differences', baseline)
        right.write_text(left.read_text())
        result = self.run_tool('cmpout.py', left, right, '--expected', baseline)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def firmware_files(self, version, firmware_val=1, crate_val=1):
        # The model reads tables directly, so a zeroed synthetic image only
        # needs the modulus word. No proprietary image is required by tests.
        base, modulus = ((0xff000, 0x369000) if version == 9 else (0x100000, 0x9eb330))
        data = bytearray(modulus - base + 4)
        struct.pack_into('<I', data, modulus - base, 0xfffffff5)
        image = self.root / f'image{version}'
        image.write_bytes(data)
        zeros = ','.join(['00000000'] * 5)
        crc = zlib.crc32(bytes(0x500))
        emu = self.write('emu.out',
            f'=== demo\n00000000 00000001 -> 00000000 {firmware_val:08X} '
            f'mode=00000000 lines=00000000 v1=0 bf=0 opt=0 '
            f'key={zeros} kc={zeros} seeds={crc:08X}\n')
        crate = self.write('crate.out',
            f'=== demo\n00000000 00000001 -> 00000000 {crate_val:08X} '
            f'scheme=Raw lines=00000000 bf=0 init=0 key={zeros}\n')
        return image, emu, crate

    def test_both_firmware_drivers_fail_on_output_differences(self):
        for version, tool in [(9, 'emudiff.py'), (10, 'emudiff10.py')]:
            with self.subTest(version=version):
                result = self.run_tool(tool, *self.firmware_files(version, crate_val=2))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn('output diffs', result.stdout)

    def test_selected_crate_state_difference_fails(self):
        files = self.firmware_files(9)
        files[2].write_text(files[2].read_text().replace('lines=00000000', 'lines=00000001'))
        result = self.run_tool('emudiff.py', *files)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('1 more with state diffs only', result.stdout)

    def test_known_rsa_primitive_difference_needs_exact_expectations(self):
        files = self.firmware_files(9)
        with files[1].open('a') as out:
            out.write('!rsa fffffffffffffff4 -> 04f363dfecae2b57\n')
        baseline = self.root / 'rsa.expected.json'
        result = self.run_tool('emudiff.py', *files, '--write-differences', baseline)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('1 differ from exact math', result.stdout)
        result = self.run_tool('emudiff.py', *files, '--expected', baseline)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_model_disagreement_cannot_be_waived(self):
        for version, tool in [(9, 'emudiff.py'), (10, 'emudiff10.py')]:
            with self.subTest(version=version):
                files = self.firmware_files(version, firmware_val=2, crate_val=2)
                baseline = self.root / 'expected.json'
                result = self.run_tool(tool, *files, '--write-differences', baseline)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                result = self.run_tool(tool, *files, '--expected', baseline)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn('model mismatches 1', result.stdout)

    def test_plaintext_disagreement_cannot_be_waived(self):
        files = self.firmware_files(9)
        plain = self.write('plain.txt', '=== demo\n00000000 00000002\n')
        baseline = self.root / 'expected.json'
        result = self.run_tool('emudiff.py', *files, plain, '--write-differences', baseline)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        result = self.run_tool('emudiff.py', *files, plain, '--expected', baseline)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('encryption round-trip failures 1', result.stdout)

    def test_both_firmware_drivers_accept_exact_expectations(self):
        for version, tool in [(9, 'emudiff.py'), (10, 'emudiff10.py')]:
            with self.subTest(version=version):
                files = self.firmware_files(version, crate_val=2)
                baseline = self.root / 'expected.json'
                result = self.run_tool(tool, *files, '--write-differences', baseline)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                result = self.run_tool(tool, *files, '--expected', baseline)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_misaligned_or_empty_firmware_inputs_are_invalid(self):
        files = self.firmware_files(9)
        files[2].write_text('=== demo\n')
        self.assertEqual(self.run_tool('emudiff.py', *files).returncode, 2)
        files[1].write_text('')
        files[2].write_text('')
        self.assertEqual(self.run_tool('emudiff.py', *files).returncode, 2)


if __name__ == '__main__':
    unittest.main()
