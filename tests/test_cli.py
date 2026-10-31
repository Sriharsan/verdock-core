import os
import subprocess
import sys
import tempfile
import unittest

from verdock_core import ed25519

sys.path.insert(0, os.path.dirname(__file__))
from vectors import PUBLIC_KEY, V1_LINE, V2_LINE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.path = os.path.join(self.tmp.name, "log.ndjson")

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        return subprocess.run([sys.executable, "-m", "verdock_core", *args], cwd=ROOT,
                              capture_output=True, text=True, encoding="utf-8")

    def _write(self, *lines):
        with open(self.path, "w", encoding="utf-8", newline="") as handle:
            handle.write("".join(line + "\n" for line in lines))

    def test_ok(self):
        self._write(V1_LINE, V2_LINE)
        result = self._run("verify", self.path, "--public-key", PUBLIC_KEY)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("line 1: ok", result.stdout)
        self.assertIn("line 2: ok", result.stdout)

    def test_tampered(self):
        self._write(V1_LINE.replace("alice", "mallory", 1), V2_LINE)
        result = self._run("verify", self.path, "--public-key", PUBLIC_KEY)
        self.assertEqual(result.returncode, 1)
        self.assertIn("line 1: FAIL signature invalid", result.stdout)
        self.assertIn("line 2: FAIL chain break", result.stdout)

    def test_wrong_key_missing_file_and_usage(self):
        self._write(V1_LINE)
        other = ed25519.public_key(bytes(32)).hex()
        self.assertEqual(self._run("verify", self.path, "--public-key", other).returncode, 1)
        self.assertEqual(self._run("verify", self.path + ".missing", "--public-key", PUBLIC_KEY).returncode, 2)
        self.assertEqual(self._run("verify", self.path, "--public-key", "zz").returncode, 2)
        self.assertEqual(self._run("verify", self.path).returncode, 2)


if __name__ == "__main__":
    unittest.main()
