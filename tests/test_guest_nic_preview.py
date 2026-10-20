"""Offline fixtures for read-only guest NIC preview."""
import unittest
from datetime import datetime, timezone
from netbox.preview_guest_nics import PreviewError, preview, validate_source, virtualization_listing

def source():
    return {
        "schema_version": "guests-0.1",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"selected": 2, "collected": 2, "errors": 0},
        "guests": [
            {"vmid": 101, "type": "qemu", "node": "pve01", "power_state": "running",
             "cpu": {"configured_max_vcpus": 4}, "memory_mib": 4096,
             "interfaces": [{"key": "net0", "mac": "02:11:22:33:44:55", "bridge": "vmbr100"}]},
            {"vmid": 102, "type": "lxc", "node": "pve01", "power_state": "stopped",
             "cpu": {"configured_max_vcpus": 2}, "memory_mib": 2048,
             "interfaces": [{"key": "net0", "name": "eth0", "mac": "02:11:22:33:44:55", "bridge": "vmbr0"}]},
        ],
    }

def vms():
    return [
        {"id": 15, "cluster": {"name": "corp"}, "custom_fields": {
            "proxmox_vmid": 101, "proxmox_guest_type": "qemu",
            "proxmox_node": "pve01", "proxmox_power_state": "running"},
         "vcpus": 4, "memory": 4096},
        {"id": 16, "cluster": {"name": "corp"}, "custom_fields": {
            "proxmox_vmid": 102, "proxmox_guest_type": "lxc",
            "proxmox_node": "pve01", "proxmox_power_state": "stopped"},
         "vcpus": 2, "memory": 2048},
    ]

class BridgeClient:
    def get(self, path):
        assert path == "/nodes/pve01/network"
        return [{"iface": "vmbr100", "type": "bridge"}]

class PreviewTests(unittest.TestCase):
    def test_duplicate_mac_held_for_stopped_guest(self):
        result = preview(source(), vms(), [], BridgeClient(), "corp", 2)
        self.assertEqual(result["summary"]["create_vm_interface"], 2)
        self.assertEqual(result["summary"]["mac_eligible_after_review"], 1)
        self.assertEqual(result["summary"]["mac_held"], 1)
        self.assertEqual(result["summary"]["warnings"],
                         {"bridge_not_found": 1, "duplicate_mac": 1})
        self.assertEqual([p["vm_interface_name"] for p in result["plan"]], ["net0", "eth0"])
        self.assertEqual(result["plan"][1]["mac_action"], "hold_duplicate_mac")
        self.assertEqual(result["netbox_writes"], 0)

    def test_existing_interface_idempotent(self):
        result = preview(source(), vms(),
                         [{"name": "net0", "virtual_machine": {"id": 15}}],
                         BridgeClient(), "corp", 2)
        self.assertEqual(result["summary"]["already_present"], 1)

    def test_cpu_drift_rejected(self):
        data = vms()
        data[0]["vcpus"] = 8
        with self.assertRaises(PreviewError):
            preview(source(), data, [], BridgeClient(), "corp", 2)

    def test_vmid_drift_rejected(self):
        data = vms()
        data[0]["custom_fields"]["proxmox_vmid"] = 999
        with self.assertRaises(PreviewError):
            preview(source(), data, [], BridgeClient(), "corp", 2)

    def test_duplicate_vmid_rejected(self):
        data = source()
        data["guests"][1]["vmid"] = 101
        with self.assertRaises(PreviewError):
            validate_source(data, 2)

    def test_missing_mac_rejected(self):
        data = source()
        data["guests"][1]["interfaces"][0]["mac"] = None
        with self.assertRaises(PreviewError):
            validate_source(data, 2)

    def test_incomplete_collection_rejected(self):
        with self.assertRaises(PreviewError):
            validate_source({"schema_version": "guests-0.1"}, 2)

    def test_forbidden_api_endpoint(self):
        with self.assertRaises(PreviewError):
            virtualization_listing(object(), "/api/dcim/devices/")
