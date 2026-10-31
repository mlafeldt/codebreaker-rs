"""Exercise runner failures without Ghidra or firmware images."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


RUNNER = Path(__file__).resolve().parents[1] / 'runemu.sh'


class RunEmuTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'proj').mkdir()
        (self.root / 'elf/emu').mkdir(parents=True)
        for image in ('v92', 'v10'):
            (self.root / f'proj/{image}.gpr').write_text('test project')
            (self.root / f'proj/{image}.rep').mkdir()
        headless = self.root / 'headless'
        headless.write_text(f'#!{sys.executable}\n' + '''\
from pathlib import Path
import sys
import time

args = sys.argv[sys.argv.index('EmuP.java') + 1:]
source, output, coverage = map(Path, args[:3])
name = source.stem
if name == 'fail':
    print('worker failed', flush=True)
    sys.exit(7)
if name == 'incomplete':
    sys.exit(0)
if name == 'late':
    time.sleep(0.1)
if name not in ('missing', 'empty'):
    output.write_text(source.read_text())
    coverage.write_text('00100000 test:reset\\n')
elif name == 'empty':
    output.touch()
    coverage.touch()
print('lines=1 steps=12 ms=1')
''')
        headless.chmod(0o755)
        self.env = dict(os.environ, GHIDRA=str(headless), PROJ='proj')

    def run_runner(self, *args):
        for name in args[1:]:
            if '/' not in name:
                (self.root / f'elf/emu/{name}.txt').write_text('=== test\n00000000 00000000\n')
        return subprocess.run(
            ['bash', str(RUNNER), *args], cwd=self.root, env=self.env,
            capture_output=True, text=True, timeout=10,
        )

    def test_worker_failure_is_reported(self):
        result = self.run_runner('v92', 'fail')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('done:', result.stdout)
        self.assertIn('fail', result.stderr)

    def test_project_copy_failure_is_reported(self):
        self.env['PROJ'] = 'missing-project'
        result = self.run_runner('v92', 'ok')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('done:', result.stdout)

    def test_all_workers_are_waited_even_after_a_failure(self):
        result = self.run_runner('v92', 'fail', 'late')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('v92 late done:', result.stdout)
        self.assertTrue((self.root / 'elf/emu/late.cov').is_file())

    def test_zero_exit_without_completion_is_failure(self):
        result = self.run_runner('v92', 'incomplete')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('done:', result.stdout)

    def test_completion_requires_nonempty_outputs(self):
        for name in ('missing', 'empty'):
            with self.subTest(name=name):
                result = self.run_runner('v92', name)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn('done:', result.stdout)

    def test_stale_outputs_do_not_make_a_run_succeed(self):
        for suffix in ('out', 'cov'):
            (self.root / f'elf/emu/missing.{suffix}').write_text('stale output\n')
        result = self.run_runner('v92', 'missing')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_success_for_both_images_and_cases_override(self):
        (self.root / 'cases').mkdir()
        content = '=== preferred\n00000000 00000001\n'
        (self.root / 'cases/ok.txt').write_text(content)
        for image, directory in (('v92', 'emu'), ('v10', 'emu10')):
            with self.subTest(image=image):
                result = self.run_runner(image, 'ok')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f'{image} ok done: lines=1 steps=12 ms=1', result.stdout)
                self.assertEqual((self.root / f'elf/{directory}/ok.out').read_text(), content)

    def test_usage_requires_image_and_safe_corpus_names(self):
        for args in ((), ('v92',), ('other', 'ok'), ('v92', '../ok'), ('v92', 'ok', 'ok')):
            with self.subTest(args=args):
                result = self.run_runner(*args)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
