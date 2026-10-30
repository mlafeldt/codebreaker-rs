"""Regression cases for false agreement in the firmware comparison aid.

All input images are synthetic; the tests need no CodeBreaker binaries.
"""
import contextlib
import importlib.util
import io
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'cbcrypt_diff.py'


def words(*values):
    return struct.pack('<%dI' % len(values), *values)


def jal(target):
    return 0x0c000000 | (target >> 2)


def load_tool():
    # The legacy module reads the images while importing. Supply empty files
    # so the regressions can run against it before that side effect is fixed.
    with tempfile.TemporaryDirectory() as tmp:
        a, b = Path(tmp) / 'a', Path(tmp) / 'b'
        a.write_bytes(b'')
        b.write_bytes(b'')
        spec = importlib.util.spec_from_file_location('cbcrypt_diff', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        with patch.object(sys, 'argv', [str(SCRIPT), str(a), str(b)]):
            spec.loader.exec_module(module)
    return module


class NormalizerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def tokens(self, data, image):
        return [row[2] for row in self.tool.norm(data, lambda a: a, 0, len(data), image)]

    def comparison(self, left, right):
        output = io.StringIO()
        with patch.dict(self.tool.diff.__globals__, {
            'D9': left, 'D10': right,
            'off92': lambda a: a, 'off10': lambda a: a,
        }), contextlib.redirect_stdout(output):
            self.tool.diff('synthetic', 0, len(left), 0, len(right))
        return output.getvalue()

    def test_unknown_call_targets_do_not_collapse(self):
        self.assertNotEqual(self.tokens(words(jal(0x123450)), 'v92'),
                            self.tokens(words(jal(0x123454)), 'v10'))

    def test_interior_call_mutation_is_not_a_relocation(self):
        # The review's real mutation was bignum call 0x131af0 -> 0x131af4.
        output = self.comparison(words(jal(0x133428)), words(jal(0x131af4)))
        self.assertNotIn('IDENTICAL', output)

    def test_known_relocated_call_still_matches(self):
        output = self.comparison(words(jal(0x1034e0)), words(jal(0x104590)))
        self.assertIn('IDENTICAL', output)

    def test_known_relocated_data_address_still_matches(self):
        output = self.comparison(words(0x3c020029, 0x8c429ad8),
                                 words(0x3c020076, 0x8c424be0))
        self.assertIn('IDENTICAL', output)

    def test_equal_unknown_calls_remain_unresolved(self):
        output = self.comparison(words(jal(0x123450)), words(jal(0x123450)))
        self.assertIn('UNRESOLVED', output)
        self.assertNotIn('IDENTICAL', output)

    def test_lui_numeric_constant_is_not_masked(self):
        output = self.comparison(words(0x3c02ffff), words(0x3c02fffe))
        self.assertNotIn('IDENTICAL', output)

    def test_unknown_data_addresses_do_not_collapse(self):
        # LUI followed by an absolute load, outside the mapped data regions.
        self.assertNotEqual(self.tokens(words(0x3c020200, 0x8c420000), 'v92'),
                            self.tokens(words(0x3c020300, 0x8c420000), 'v10'))

    def test_numeric_use_of_address_high_half_is_not_masked(self):
        # A recognized later address must not hide an earlier use as a value.
        left = words(0x3c020029, 0x00401825, 0x8c429ad8)
        right = words(0x3c020076, 0x00401825, 0x8c424be0)
        self.assertNotIn('IDENTICAL', self.comparison(left, right))

    def test_changed_struct_offset_is_not_a_relocation(self):
        self.assertNotIn('IDENTICAL', self.comparison(
            words(0x3c020037, 0x8c42e2f8),
            words(0x3c02009f, 0x8c42057c)))

    def test_changed_shift_amount_is_not_hidden(self):
        self.assertNotIn('IDENTICAL', self.comparison(words(0x00021040), words(0x00021080)))

    def test_cli_compares_past_memcpy_first_return(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / 'v92', Path(tmp) / 'v10'
            left, right = bytearray(0x50000), bytearray(0x50000)
            # First memcpy return is at word 41; its actual body has 106 words.
            for index in (41, 62, 104):
                struct.pack_into('<I', left, 0x1461b0 - 0xff000 + index * 4, 0x03e00008)
                struct.pack_into('<I', right, 0x1447d4 - 0x100000 + index * 4, 0x03e00008)
            struct.pack_into('<I', right, 0x1447d4 - 0x100000 + 90 * 4, 0x24420001)
            a.write_bytes(left)
            b.write_bytes(right)
            result = subprocess.run([sys.executable, '-I', str(SCRIPT), str(a), str(b)],
                                    text=True, capture_output=True)
            self.assertIn('memcpy:', result.stdout)
            memcpy = result.stdout.split('memcpy:', 1)[1].split('===', 1)[0]
            self.assertNotIn('IDENTICAL', memcpy)
            self.assertIn('(106)', memcpy)

    def test_allow_differences_cannot_hide_unresolved_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / 'v92', Path(tmp) / 'v10'
            left, right = bytearray(0x50000), bytearray(0x50000)
            struct.pack_into('<I', left, 0x1033c0 - 0xff000, jal(0x123450))
            struct.pack_into('<I', right, 0x104470 - 0x100000, jal(0x123450))
            a.write_bytes(left)
            b.write_bytes(right)
            result = subprocess.run([sys.executable, '-I', str(SCRIPT), str(a), str(b),
                                     '--allow-differences'], text=True, capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('UNRESOLVED', result.stdout)

    def test_missing_image_bytes_are_invalid_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / 'empty'
            a.write_bytes(b'')
            result = subprocess.run([sys.executable, '-I', str(SCRIPT), str(a), str(a)],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('missing bytes', result.stderr)


if __name__ == '__main__':
    unittest.main()
