import unittest
from netbox.enrich_existing import (
    EnrichmentError, plan_from_inventory, assert_counts, reconcile_in_netbox,
)

def sample():
    return {"schema_version": "0.3",
            "summary": {"selected": 1, "collected": 1, "errors": 0},
            "audit_summary": {"topology_review_passed": True},
            "errors": [],
            "nodes": [{"name": "pve01",
                       "dmi": {"serial_number": "SERIAL-TEST"},
                       "network_audit": {"topology_consistent": True},
                       "network_interfaces": [
                           {"name": "eno1", "type": "eth",
                            "mac_address": "02:01:02:03:04:05"},
                           {"name": "vmbr0", "type": "bridge"}]}]}

class EnrichTests(unittest.TestCase):
    def test_plan_and_counts(self):
        plan = plan_from_inventory(sample())
        assert_counts(plan, devices=1, interfaces=2, serials=1, macs=1)
        self.assertEqual(len(plan["macs"]), 1)

    def test_wrong_counts_blocked(self):
        with self.assertRaises(EnrichmentError):
            assert_counts(plan_from_inventory(sample()),
                          devices=1, interfaces=2, serials=1, macs=2)

    def test_partial_snapshot_blocked(self):
        x = sample()
        x["summary"]["selected"] = 2
        with self.assertRaises(EnrichmentError):
            plan_from_inventory(x)

    def test_report_errors_blocked(self):
        x = sample()
        x["errors"].append({"stage": "ssh"})
        with self.assertRaises(EnrichmentError):
            plan_from_inventory(x)

    def test_missing_topology_blocked(self):
        x = sample()
        x["nodes"][0]["network_audit"]["topology_consistent"] = False
        with self.assertRaises(EnrichmentError):
            plan_from_inventory(x)

    def test_duplicate_mac_blocked(self):
        x = sample()
        x["nodes"].append({**x["nodes"][0], "name": "pve02", "dmi": {}})
        x["summary"]["selected"] = x["summary"]["collected"] = 2
        with self.assertRaises(EnrichmentError):
            plan_from_inventory(x)

    def test_duplicate_serial_blocked(self):
        x = sample()
        x["nodes"].append({**x["nodes"][0], "name": "pve02",
                           "network_interfaces": []})
        x["summary"]["selected"] = x["summary"]["collected"] = 2
        with self.assertRaises(EnrichmentError):
            plan_from_inventory(x)

    def test_duplicate_interface_blocked(self):
        x = sample()
        x["nodes"][0]["network_interfaces"].append(
            {"name": "eno1", "type": "bridge"})
        with self.assertRaises(EnrichmentError):
            plan_from_inventory(x)

    def test_invalid_mac_blocked(self):
        for mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff",
                    "01:00:5e:00:00:01", "invalid"):
            x = sample()
            x["nodes"][0]["network_interfaces"][0]["mac_address"] = mac
            with self.subTest(mac=mac), self.assertRaises(EnrichmentError):
                plan_from_inventory(x)

    def test_apply_requires_confirmation_before_import(self):
        with self.assertRaises(EnrichmentError):
            reconcile_in_netbox(plan_from_inventory(sample()),
                                "office", "hypervisor", apply=True)
if __name__ == "__main__":
    unittest.main()
