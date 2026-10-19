import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from collectors.proxmox_inventory import (
    CollectionError, collect, normalize_interface, normalize_node,
    save_json, validate_node, remote_dmi, audit_network, normalize_mac, serial_valid,
)


class FakePvesh:
    def __init__(self, data):
        self.data = data
        self.queries = []

    def get(self, path):
        self.queries.append(path)
        if path not in self.data:
            raise CollectionError("no fixture for " + path)
        return self.data[path]


FIXTURES = {
    "/nodes": [{"node": "pve01", "status": "online"}, {"node": "pve02", "status": "online"}],
    "/nodes/pve01/status": {
        "cpuinfo": {"model": "Example CPU", "sockets": 1, "cores": 8, "cpus": 16},
        "memory": {"total": 34359738368},
    },
    "/nodes/pve01/network": [
        {"iface": "vmbr0", "type": "bridge", "bridge_ports": "eno1", "address": "192.0.2.10", "netmask": "255.255.255.0"},
        {"iface": "eno1", "type": "eth", "active": 1},
        {"iface": "vmbr200", "type": "bridge", "bridge_vlan_aware": 1, "bridge_vids": "2-4094"},
    ],
    "/nodes/pve02/status": {
        "cpuinfo": {"model": "Second CPU", "cores": "6", "cpus": "12"}, "memory": {"total": 17179869184},
    },
    "/nodes/pve02/network": [{"iface": "bond0", "type": "bond", "slaves": "eno1 eno2", "bond_mode": "802.3ad"}],
}


class ProxmoxInventoryTests(unittest.TestCase):
    @patch("collectors.proxmox_inventory.local_dmi", return_value={"manufacturer": "Example Inc", "model": "Server A"})
    def test_collect_all(self, _mock):
        client = FakePvesh(FIXTURES)
        report = collect(client, local_name="pve01", cluster_label="test-cluster")
        self.assertEqual(report["summary"], {"selected": 2, "collected": 2, "errors": 0})
        self.assertEqual(report["nodes"][0]["cpu"]["threads"], 16)
        self.assertEqual(report["nodes"][0]["dmi"]["model"], "Server A")
        self.assertEqual(next(i for i in report["nodes"][0]["network_interfaces"] if i["name"] == "vmbr0")["ipv4_cidr"], "192.0.2.10/24")
        self.assertEqual(report["nodes"][1]["network_interfaces"][0]["slaves"], "eno1 eno2")
        self.assertTrue(all(q.startswith("/nodes") for q in client.queries))

    def test_selected_node(self):
        client = FakePvesh(FIXTURES)
        report = collect(client, requested=["pve02"], local_name="collector")
        self.assertEqual(report["summary"]["collected"], 1)
        self.assertFalse(any("pve01/status" in s for s in client.queries))

    def test_missing_node_fails_closed(self):
        report = collect(FakePvesh(FIXTURES), requested=["pve03"], local_name="collector")
        self.assertEqual(report["summary"]["errors"], 1)
        self.assertEqual(report["nodes"], [])

    def test_partial_failure_is_visible(self):
        data = dict(FIXTURES)
        del data["/nodes/pve02/network"]
        report = collect(FakePvesh(data), local_name="collector")
        self.assertEqual(report["summary"]["collected"], 1)
        self.assertEqual(report["errors"][0]["node"], "pve02")

    def test_node_rejects_injection(self):
        for value in ["", "--help", "pve/../../x", "a b", "a;whoami"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_node(value)

    def test_cidr_invalid_is_not_fabricated(self):
        item = normalize_interface({"iface": "vmbr0", "address": "192.0.2.1", "netmask": "invalid"})
        self.assertNotIn("ipv4_cidr", item)

    def test_missing_values_are_null(self):
        result = normalize_node("pve01", {}, [])
        self.assertIsNone(result["memory_total_bytes"])
        self.assertIsNone(result["cpu"]["threads"])

    def test_atomic_output_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / "private" / "inventory.json"
            save_json({"nodes": []}, file)
            self.assertEqual(json.loads(file.read_text())["nodes"], [])
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    def test_no_ssh_for_non_dmi_case(self):
        with patch("collectors.proxmox_inventory.remote_dmi") as remote:
            collect(FakePvesh(FIXTURES), local_name="collector")
            remote.assert_not_called()

    def test_invalid_ssh_user(self):
        with self.assertRaises(ValueError):
            remote_dmi("pve01", "root;echo injected", 5)

    def test_invalid_discovery_shape(self):
        with self.assertRaises(CollectionError):
            collect(FakePvesh({"/nodes": {"unexpected": 1}}))

    def test_normalize_mac_from_api(self):
        for field in ("hwaddress", "mac", "mac_address", "hwaddr"):
            item = normalize_interface({
                "iface": "eno1", "type": "eth",
                field: "AA-BB-CC-DD-EE-01",
            })
            self.assertEqual(item["mac_address"], "aa:bb:cc:dd:ee:01")
        self.assertIsNone(normalize_mac("auto"))
        self.assertNotIn("mac_address", normalize_interface({
            "iface": "eno1", "type": "eth", "hwaddress": "random"
        }))

    def test_serial_validity(self):
        self.assertFalse(serial_valid("To Be Filled By O.E.M."))
        self.assertFalse(serial_valid("Default String"))
        self.assertTrue(serial_valid("TEST-000123"))

    def test_network_topology_valid(self):
        entries = [
            normalize_interface({"iface": "eno1", "type": "eth", "hwaddress": "02:00:00:00:00:01"}),
            normalize_interface({"iface": "eno1.200", "type": "vlan", "vlan-id": 200, "vlan-raw-device": "eno1"}),
            normalize_interface({"iface": "vmbr200", "type": "bridge", "bridge_ports": "eno1.200"}),
        ]
        audit = audit_network(entries)
        self.assertTrue(audit["topology_consistent"])
        self.assertEqual(audit["vlan_with_id_count"], 1)
        self.assertEqual(audit["vlan_with_parent_count"], 1)
        self.assertEqual(audit["bridge_with_ports_count"], 1)
        self.assertEqual(audit["mac_count"], 1)

    def test_network_topology_missing_references(self):
        entries = [
            normalize_interface({"iface": "bond0", "type": "bond", "slaves": "eno1 eno2"}),
            normalize_interface({"iface": "vlan200", "type": "vlan", "vlan-id": 200, "vlan-raw-device": "bond0"}),
            normalize_interface({"iface": "vmbr0", "type": "bridge", "bridge_ports": "vlan200 missingport"}),
        ]
        audit = audit_network(entries)
        self.assertFalse(audit["topology_consistent"])
        self.assertEqual(sorted(i["code"] for i in audit["topology_issues"]),
                         ["bond_slave_not_found", "bond_slave_not_found", "bridge_port_not_found"])

    def test_topology_warning_not_silenced(self):
        result = collect(FakePvesh(FIXTURES), local_name="collector")
        self.assertGreater(result["audit_summary"]["topology_issues"], 0)
        self.assertFalse(result["audit_summary"]["topology_review_passed"])
        self.assertEqual(result["summary"]["errors"], 0)

    def test_dmi_serial_is_not_read_without_permission(self):
        # Missing/locked serials remain optional; no source is fabricated.
        with patch("collectors.proxmox_inventory.Path.read_text",
                   side_effect=PermissionError):
            from collectors.proxmox_inventory import local_dmi
            self.assertEqual(local_dmi(), {})


if __name__ == "__main__":
    unittest.main()