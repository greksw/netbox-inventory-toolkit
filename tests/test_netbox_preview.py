import json
from pathlib import Path
import tempfile
import unittest

from netbox.preview import PreviewError, ReadOnlyNetBox, compare, offline_plan, read_inventory, save_private


def fixture():
    return {
        "schema_version": "0.3", "summary": {"selected": 1, "collected": 1, "errors": 0},
        "errors": [], "nodes": [{"name": "pve01", "dmi": {"manufacturer": "Example", "model": "Mini", "serial_number": "ABC"},
                                "network_audit": {"topology_consistent": True},
                                "network_interfaces": [{"name": "eno1", "type": "eth", "mac_address": "02:00:00:00:00:01"},
                                                       {"name": "vmbr0", "type": "bridge", "ipv4_cidr": "192.0.2.1/24"}]}],
    }


class FakeAPI:
    def __init__(self, lookup):
        self.lookup = lookup
        self.queries = []
    def list(self, endpoint, params=None):
        self.queries.append((endpoint, params))
        return self.lookup.get(endpoint, [])


class Tests(unittest.TestCase):
    def test_summary(self):
        plan = offline_plan(fixture())
        self.assertTrue(plan["summary"]["ready_to_compare"])
        self.assertEqual(plan["summary"]["physical_interfaces"], 1)
        self.assertEqual(plan["summary"]["deferred_interfaces"], 1)
        self.assertEqual(plan["summary"]["deferred_ip_addresses"], 1)
        self.assertNotIn("serial_number", plan["devices"][0])
        self.assertNotIn("mac_address", plan["devices"][0])

    def test_errors_block(self):
        item = fixture()
        item["errors"] = [{"stage": "mac"}]
        self.assertIn("collector_errors", offline_plan(item)["summary"]["blocking_issue_codes"])

    def test_partial_collection_blocks(self):
        item = fixture()
        item["summary"]["selected"] = 2
        self.assertIn("incomplete_collection", offline_plan(item)["summary"]["blocking_issue_codes"])

    def test_inconsistent_topology_blocks(self):
        item = fixture()
        item["nodes"][0]["network_audit"]["topology_consistent"] = False
        self.assertIn("topology_not_verified", offline_plan(item)["summary"]["blocking_issue_codes"])

    def test_duplicate_mac_blocks(self):
        item = fixture()
        second = dict(item["nodes"][0])
        second["name"] = "pve02"
        item["nodes"].append(second)
        item["summary"] = {"selected": 2, "collected": 2, "errors": 0}
        self.assertIn("duplicate_current_mac", offline_plan(item)["summary"]["blocking_issue_codes"])

    def test_netbox_missing_device(self):
        api = FakeAPI({
            "/api/dcim/sites/": [{"slug": "office"}],
            "/api/dcim/device-roles/": [{"slug": "hypervisor"}],
            "/api/dcim/device-types/": [{"id": 1, "model": "Mini", "manufacturer": {"name": "Example"}}],
        })
        result = compare(offline_plan(fixture()), api, "office", "hypervisor")
        self.assertEqual(result["statuses"], {"missing_device": 1})
        self.assertEqual(result["writes"], 0)

    def test_netbox_existing_device(self):
        api = FakeAPI({
            "/api/dcim/sites/": [{"slug": "office"}],
            "/api/dcim/device-roles/": [{"slug": "hypervisor"}],
            "/api/dcim/device-types/": [{"id": 1, "model": "Mini", "manufacturer": {"name": "Example"}}],
            "/api/dcim/devices/": [{"id": 8, "name": "pve01", "site": {"slug": "office"},
                                     "role": {"slug": "hypervisor"}, "device_type": {"id": 1}}],
            "/api/dcim/interfaces/": [],
        })
        result = compare(offline_plan(fixture()), api, "office", "hypervisor")
        self.assertEqual(result["statuses"], {"existing_device": 1})
        self.assertEqual(result["devices"][0]["missing_nics"], 1)

    def test_netbox_ambiguous(self):
        api = FakeAPI({
            "/api/dcim/sites/": [{"slug": "office"}],
            "/api/dcim/device-roles/": [{"slug": "hypervisor"}],
            "/api/dcim/device-types/": [{"id": 1, "model": "Mini", "manufacturer": {"name": "Example"}}],
            "/api/dcim/devices/": [{"id": 8, "name": "pve01", "site": {"slug": "other"}}],
        })
        result = compare(offline_plan(fixture()), api, "office", "hypervisor")
        self.assertEqual(result["statuses"], {"ambiguous_name": 1})

    def test_token_and_url_validation(self):
        for url in ("http://netbox", "https://user:pass@netbox", "https://netbox/api/", "https://netbox/?x=1"):
            with self.subTest(url=url), self.assertRaises(PreviewError):
                ReadOnlyNetBox(url, "nbt_abc.def")
        with self.assertRaises(PreviewError):
            ReadOnlyNetBox("https://netbox", "legacy-token")

    def test_private_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "private" / "preview.json"
            save_private(f, {"a": 1})
            self.assertEqual(json.loads(f.read_text()), {"a": 1})
            self.assertEqual(f.stat().st_mode & 0o777, 0o600)

    def test_wrong_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "in.json"
            f.write_text('{"schema_version": "0.2"}')
            with self.assertRaises(PreviewError):
                read_inventory(f)


if __name__ == "__main__":
    unittest.main()