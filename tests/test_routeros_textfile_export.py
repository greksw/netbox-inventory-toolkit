"""Offline textfile contract tests."""
import json
import unittest
from routeros.textfile_export import parse_audit, render_metrics

COUNTS = {
    "routeros_vlans": 2,
    "netbox_vlans": 2,
    "routeros_static_ips": 3,
    "netbox_static_ips": 3,
    "routeros_dynamic_ips": 1,
    "routeros_disabled_ips": 0,
}


def report(state, differences):
    return (f"ROUTEROS IPAM AUDIT: {state}\n"
            f"Differences: {differences}\n"
            f"Categories: {{}}\n"
            f"Counts: {json.dumps(COUNTS)}\n")


class TextfileTests(unittest.TestCase):
    def test_clean(self):
        result = parse_audit(0, report("CLEAN", 0))
        self.assertEqual(result["status"], 0)
        sample = render_metrics(result, 123456)
        self.assertIn("netbox_routeros_ipam_audit_status 0", sample)
        self.assertIn("netbox_routeros_ipam_audit_differences 0", sample)

    def test_drift(self):
        result = parse_audit(1, report("DRIFT", 2))
        self.assertEqual(result["status"], 1)
        self.assertEqual(result["differences"], 2)

    def test_fail_closed(self):
        for rc, stdout in [
            (0, report("DRIFT", 2)),
            (1, report("CLEAN", 0)),
            (1, report("DRIFT", 0)),
            (2, "ROUTEROS IPAM AUDIT: ERROR\n"),
            (0, "ROUTEROS IPAM AUDIT: CLEAN\n"),
            (0, report("CLEAN", 0) + report("CLEAN", 0)),
        ]:
            with self.subTest(rc=rc):
                self.assertEqual(parse_audit(rc, stdout), {"status": 2})
        sample = render_metrics({"status": 2}, 123456)
        self.assertIn("netbox_routeros_ipam_audit_status 2", sample)
        self.assertNotIn("netbox_routeros_ipam_audit_differences", sample)


if __name__ == "__main__":
    unittest.main()
