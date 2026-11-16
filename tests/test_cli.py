import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from ip_inventory.cli import main

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


class TestCli(unittest.TestCase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_messy_sample_exits_2_and_covers_rules(self):
        code, out, _ = self.run_cli([os.path.join(SAMPLES, "ips_messy.json"), "--as-of", "2026-11-17"])
        self.assertEqual(code, 2)
        for rule in ("IP001", "IP002", "IP003", "IP004"):
            self.assertIn(rule, out)

    def test_clean_sample_exits_0(self):
        code, out, _ = self.run_cli([os.path.join(SAMPLES, "ips_clean.json"), "--as-of", "2026-11-17"])
        self.assertEqual(code, 0)
        self.assertIn("RESULT: clean", out)

    def test_invalid_ip_exits_2(self):
        doc = '{"known_entities": [], "reserved_ips": [{"ocid": "x", "ip_address": "999.1.1.1", "created_at": "2026-01-01"}]}'
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write(doc)
            path = fh.name
        try:
            code, _, err = self.run_cli([path])
            self.assertEqual(code, 2)
            self.assertIn("invalid ip_address", err)
        finally:
            os.unlink(path)

    def test_malformed_json_exits_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{nah")
            path = fh.name
        try:
            code, _, err = self.run_cli([path])
            self.assertEqual(code, 2)
            self.assertIn("not valid JSON", err)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
