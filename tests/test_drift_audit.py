import unittest
from unittest.mock import patch
from netbox.drift_audit import (
    AuditError, detect_drift, verified_inventory, netbox_interface_mac,
    NetBoxReadOnly,
)

def sample():
    return {
        "schema_version": "0.3",
        "summary": {"selected": 1, "collected": 1, "errors": 0},
        "errors": [],
        "nodes": [{
            "name": "pve01",
            "dmi": {"serial_number": "SERIAL-TEST"},
            "network_audit": {"topology_consistent": True},
            "network_interfaces": [
                {"name": "eno1", "type": "eth",
                 "mac_address": "02:01:02:03:04:05"},
                {"name": "vmbr0", "type": "bridge"},
            ],
        }],
    }

class Client:
    def __init__(self, *, serial="SERIAL-TEST", mac="02:01:02:03:04:05",
                 omit_interface=False, site="office"):
        self.serial, self.mac = serial, mac
        self.omit_interface, self.site = omit_interface, site
    def listing(self, path, params):
        if path.endswith("/devices/"):
            return [{"id": 7, "name": "pve01", "serial": self.serial,
                     "site": {"slug": self.site}, "role": {"slug": "hypervisor"}}]
        if path.endswith("/interfaces/"):
            return ([{"name": "vmbr0", "mac_address": None}] if self.omit_interface else
                    [{"name": "eno1", "mac_address": self.mac},
                     {"name": "vmbr0", "mac_address": None}])
        return []

class DriftTests(unittest.TestCase):
    def report(self, client, source=None):
        return detect_drift(source or sample(), client, "office", "hypervisor", 1)

    def test_clean(self):
        result = self.report(Client())
        self.assertEqual(result["status"], "clean")
        self.assertEqual(result["counts"]["physical_macs_checked"], 1)
        self.assertEqual(result["netbox_writes"], 0)

    def test_mac_missing(self):
        self.assertEqual(self.report(Client(mac=None))["by_kind"], {"mac_missing": 1})

    def test_mac_mismatch(self):
        self.assertEqual(self.report(Client(mac="02:01:02:03:04:06"))["by_kind"],
                         {"mac_mismatch": 1})

    def test_serial_mismatch(self):
        self.assertEqual(self.report(Client(serial="OTHER"))["by_kind"],
                         {"serial_mismatch": 1})

    def test_interface_missing(self):
        self.assertEqual(self.report(Client(omit_interface=True))["by_kind"],
                         {"interface_missing": 1})

    def test_mapping_changed(self):
        self.assertEqual(self.report(Client(site="other"))["by_kind"],
                         {"device_mapping_changed": 1})

    def test_node_count_changed(self):
        result = detect_drift(sample(), Client(), "office", "hypervisor", 2)
        self.assertIn("node_count_changed", result["by_kind"])

    def test_incomplete_errors(self):
        s = sample()
        s["errors"] = [{"stage": "ssh"}]
        with self.assertRaises(AuditError):
            verified_inventory(s)

    def test_unknown_mac_shape_is_error(self):
        with self.assertRaises(AuditError):
            netbox_interface_mac({"name": "eno1"})

    def test_primary_mac_nested_object(self):
        self.assertEqual(
            netbox_interface_mac({"primary_mac_address":
                                  {"mac_address": "02:01:02:03:04:05"}}),
            "02:01:02:03:04:05"
        )

    def test_insecure_url_rejected(self):
        for value in ("http://netbox", "https://user:secret@netbox",
                      "https://netbox/api/", "https://netbox/?x=1"):
            with self.subTest(url=value), self.assertRaises(AuditError):
                NetBoxReadOnly(value, "nbt_example.secret")

    def test_token_validation(self):
        with self.assertRaises(AuditError):
            NetBoxReadOnly("https://netbox.test", "invalid")

if __name__ == "__main__":
    unittest.main()
