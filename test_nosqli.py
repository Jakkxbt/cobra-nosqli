import subprocess, sys, time, unittest
from pathlib import Path

ROOT = Path(__file__).parent

class LabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.apps = [subprocess.Popen([sys.executable, str(ROOT/name), "--port", str(port)])
                    for name, port in (("vuln_app.py", 18880), ("safe_app.py", 18881))]
        time.sleep(.25)
    @classmethod
    def tearDownClass(cls):
        for app in cls.apps: app.terminate(); app.wait(timeout=2)
    def scan(self, port, *extra):
        return subprocess.run([sys.executable, str(ROOT/"nosqli.py"), f"http://127.0.0.1:{port}/login",
                               "--login", "--json", *extra], text=True, capture_output=True)
    def test_vulnerable_form_is_critical(self):
        r = self.scan(18880); self.assertEqual(r.returncode, 1); self.assertIn('"severity": "CRITICAL"', r.stdout)
    def test_vulnerable_json_is_critical(self):
        r = self.scan(18880, "--json-login"); self.assertEqual(r.returncode, 1); self.assertIn('"severity": "CRITICAL"', r.stdout)
    def test_safe_is_clean(self):
        for extra in ((), ("--json-login",)):
            r = self.scan(18881, *extra); self.assertEqual(r.returncode, 0, r.stdout+r.stderr); self.assertIn('"clean": true', r.stdout)

if __name__ == "__main__": unittest.main()
