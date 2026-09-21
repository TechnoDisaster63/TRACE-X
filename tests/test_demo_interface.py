import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DemoInterfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        env = os.environ.copy()
        env["TRACE_X_OUTPUT_DIR"] = str(Path(cls.tmp.name) / "output")
        env["TRACE_X_REPORTS_DIR"] = str(Path(cls.tmp.name) / "reports")
        cls.proc = subprocess.Popen([sys.executable, "demo.py", "--port", "0", "--no-browser"], cwd=ROOT,
                                    env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        line = cls.proc.stdout.readline().strip()
        cls.port = int(line.rsplit(":", 1)[1].rstrip("/"))

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate(); cls.proc.wait(timeout=5); cls.tmp.cleanup()

    def request(self, method, path, body=None, headers=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse(); data = response.read(); conn.close()
        return response, data

    def test_ui_and_scenario_index(self):
        response, body = self.request("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertIn(b"URLs never visited", body)
        response, body = self.request("GET", "/api/scenarios")
        scenarios = json.loads(body)
        self.assertEqual({x["id"] for x in scenarios}, {"legitimate", "phishing", "bec", "lookalike", "malformed", "campaign"})

    def test_scenario_analysis_preserves_safety_boundaries_and_valid_package(self):
        boundary = "----TRACE-X-TEST"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"scenario\"\r\n\r\nphishing\r\n"
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"trusted_domains\"\r\n\r\npaypal.com\r\n"
                f"--{boundary}--\r\n").encode()
        response, raw = self.request("POST", "/api/analyze", body, {"Content-Type": f"multipart/form-data; boundary={boundary}", "Content-Length": str(len(body))})
        self.assertEqual(response.status, 200, raw)
        data = json.loads(raw)
        self.assertTrue(data["case_package"]["verification"]["valid"])
        self.assertFalse(data["recommendation"]["executable"])
        self.assertFalse(data["boundaries"]["urls_visited"])
        self.assertFalse(data["boundaries"]["attachments_executed"])
        self.assertEqual(data["boundaries"]["campaign_scope"], "BATCH_ONLY")
        self.assertEqual(data["boundaries"]["authentication"], "REPORTED_HEADER_ANALYSIS; NOT INDEPENDENTLY VERIFIED")
        self.assertTrue(data["evidence"])
        self.assertTrue(all(x["id"].startswith("EV-") for x in data["evidence"]))

    def test_rejects_missing_choice(self):
        boundary = "----TRACE-X-EMPTY"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"scenario\"\r\n\r\n\r\n"
                f"--{boundary}--\r\n").encode()
        response, raw = self.request("POST", "/api/analyze", body, {"Content-Type": f"multipart/form-data; boundary={boundary}", "Content-Length": str(len(body))})
        self.assertEqual(response.status, 400)
        self.assertIn(".eml", json.loads(raw)["error"])


if __name__ == "__main__":
    unittest.main()
