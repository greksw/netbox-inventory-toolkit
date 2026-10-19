import json
import tempfile
import unittest
from pathlib import Path

from netbox.zabbix_bridge import read_metric, summarize


class ZabbixBridgeTests(unittest.TestCase):
    def sample(self, status="clean", differences=0, checked_at="2026-10-19T18:56:26+00:00"):
        return {"status": status, "counts": {"differences": differences},
                "checked_at": checked_at,
                "differences": [{"object": "internal"}]}

    def test_clean(self):
        self.assertEqual(
            summarize(self.sample(), "success", 1792436300)["status"], 0)

    def test_drift(self):
        result = summarize(self.sample("drift", 3), "success", 1792436300)
        self.assertEqual((result["status"], result["differences"]), (1, 3))

    def test_systemd_failure_overrides_old_clean(self):
        self.assertEqual(
            summarize(self.sample(), "exit-code", 1792436300)["status"], 2)

    def test_stale_report_is_error(self):
        self.assertEqual(
            summarize(self.sample(), "success", 1792445000)["status"], 2)

    def test_inconsistent_clean_is_error(self):
        self.assertEqual(
            summarize(self.sample("clean", 2), "success", 1792436300)["status"], 2)

    def test_inconsistent_drift_is_error(self):
        self.assertEqual(
            summarize(self.sample("drift", 0), "success", 1792436300)["status"], 2)

    def test_invalid_report_is_error(self):
        for bad in (None, {}, [], {"status": "clean"}, {"status": "error"}):
            with self.subTest(bad=bad):
                self.assertEqual(summarize(bad, "success")["status"], 2)

    def test_missing_file_fails_closed(self):
        p = Path("/nonexistent/test-metrics.json")
        self.assertEqual(read_metric(p, "status"), 2)
        self.assertEqual(read_metric(p, "timestamp"), 0)

    def test_reader_sanitized_numbers(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "metrics.json"
            p.write_text(json.dumps({"status": 1, "differences": 3,
                                     "timestamp": 1792436300}))
            self.assertEqual(read_metric(p, "status"), 1)
            self.assertEqual(read_metric(p, "differences"), 3)
            self.assertEqual(read_metric(p, "timestamp"), 1792436300)

    def test_bad_values_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "metrics.json"
            p.write_text(json.dumps({"status": False, "differences": 0,
                                     "timestamp": 1792436300}))
            self.assertEqual(read_metric(p, "status"), 2)


if __name__ == "__main__":
    unittest.main()
