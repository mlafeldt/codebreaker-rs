"""Validate unpacking with a synthetic loader and encrypted zlib body."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib


SCRIPT = Path(__file__).resolve().parents[1] / 'cbv10_unpack.py'
SPEC = importlib.util.spec_from_file_location('cbv10_unpack', SCRIPT)
UNPACK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UNPACK)
KEY = bytes(range(20))
PAYLOAD = b'Synthetic CodeBreaker unpacking fixture.\n' * 8


class UnpackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.image = self.root / 'loader'
        self.output = self.root / 'unpacked'

    def loader(self, *, want=None, compressed=None, compressed_size=None, body=None):
        if compressed is None:
            compressed = zlib.compress(PAYLOAD)
        if body is None:
            body = struct.pack('<II', len(PAYLOAD) if want is None else want,
                               len(compressed) if compressed_size is None else compressed_size)
            body += compressed
        encrypted = UNPACK.rc4(KEY, body)
        data = bytearray(UNPACK.o(0x1383580) + 4)
        struct.pack_into('<I', data, UNPACK.o(0x1383580), len(encrypted))
        offset = UNPACK.o(0x1012ab0)
        data[offset:offset + len(encrypted)] = encrypted
        # Choose stored key bytes so the default derivation recovers KEY too.
        mask = UNPACK.derive_key(data)
        offset = UNPACK.o(0x1010940)
        data[offset:offset + 20] = bytes(a ^ b for a, b in zip(KEY, mask))
        self.image.write_bytes(data)

    def run_unpack(self, *args):
        return subprocess.run(
            [sys.executable, '-I', str(SCRIPT), str(self.image),
             '--out', str(self.output), *args],
            capture_output=True, text=True, timeout=10,
        )

    def assert_invalid(self, *args):
        # Invalid input must neither create an output nor overwrite an old one.
        for existing in (False, True):
            with self.subTest(existing_output=existing):
                if existing:
                    self.output.write_bytes(b'keep this output')
                result = self.run_unpack(*args)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn('error:', result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                if existing:
                    self.assertEqual(self.output.read_bytes(), b'keep this output')
                else:
                    self.assertFalse(self.output.exists())

    def test_valid_body_with_derived_and_explicit_key(self):
        self.loader()
        for args in ((), ('--key', KEY.hex())):
            with self.subTest(args=args):
                result = self.run_unpack(*args)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.output.read_bytes(), PAYLOAD)

    def test_wrong_key_fails_without_writing(self):
        self.loader()
        self.assert_invalid('--key', bytes(20).hex())

    def test_inflated_size_mismatch_fails_without_writing(self):
        self.loader(want=len(PAYLOAD) + 1)
        self.assert_invalid()

    def test_inflated_size_too_small_fails(self):
        self.loader(want=len(PAYLOAD) - 1)
        self.assert_invalid()

    def test_malformed_keys_are_rejected(self):
        self.loader()
        for key in ('', '00', 'gg' * 20, '00' * 21):
            with self.subTest(key=key):
                self.assert_invalid('--key', key)
                self.output.unlink(missing_ok=True)

    def test_truncated_loader_is_rejected(self):
        self.image.write_bytes(b'not a complete loader')
        self.assert_invalid()

    def test_encrypted_body_must_fit_in_loader(self):
        self.loader()
        data = bytearray(self.image.read_bytes())
        struct.pack_into('<I', data, UNPACK.o(0x1383580), len(data))
        self.image.write_bytes(data)
        self.assert_invalid()

    def test_decrypted_body_requires_complete_header(self):
        self.loader(body=b'\0' * 4)
        self.assert_invalid()

    def test_compressed_body_must_fit_declared_encrypted_size(self):
        self.loader(compressed_size=1000)
        self.assert_invalid()

    def test_invalid_zlib_stream_fails(self):
        self.loader(compressed=b'\x78invalid stream')
        self.assert_invalid()

    def test_truncated_zlib_stream_fails(self):
        self.loader(compressed=zlib.compress(PAYLOAD)[:-2])
        self.assert_invalid()

    def test_zlib_trailing_data_is_rejected(self):
        self.loader(compressed=zlib.compress(PAYLOAD) + b'extra bytes')
        self.assert_invalid()


if __name__ == '__main__':
    unittest.main()
