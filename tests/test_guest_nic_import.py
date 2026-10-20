import unittest
from datetime import datetime, timezone
from netbox.import_guest_nics import verify_preview, GuestNICImportError

def fixture():
    rows=[]
    for vmid, mac, status, bridge in [
        (101,"02:11:22:33:44:55","stopped","vmbr0"),
        (102,"02:11:22:33:44:55","running","vmbr100"),
    ]:
        rows.append({"vmid":vmid,"netbox_vm_id":vmid+1000,
                     "vm_interface_name":"net0","proxmox_config_key":"net0",
                     "proxmox_bridge":bridge,"mac":mac,"power_state":status,
                     "action":"create_vm_interface",
                     "mac_action":("hold_duplicate_mac" if vmid==101 else "eligible_after_review")})
    return {
        "schema_version":"vm-nic-preview-0.1",
        "read_only":True,"netbox_writes":0,"cluster":"test",
        "checked_at":datetime.now(timezone.utc).isoformat(),
        "summary":{"vm_count":2,"vnic_count":2,"create_vm_interface":2,
                   "already_present":0,"mac_eligible_after_review":1,"mac_held":1},
        "plan":rows,
        "warnings":[{"type":"duplicate_mac","vmids":[101,102]},
                    {"type":"bridge_not_found","vmid":101,"bridge":"vmbr0"}],
    }

class ImportTests(unittest.TestCase):
    def test_verified(self):
        plan=verify_preview(fixture(),cluster="test",expected_vms=2,
                            expected_nics=2,expected_macs=1,expected_held=(101,))
        self.assertEqual(len(plan),2)

    def test_wrong_held_vm_rejected(self):
        with self.assertRaises(GuestNICImportError):
            verify_preview(fixture(),cluster="test",expected_vms=2,
                           expected_nics=2,expected_macs=1,expected_held=(102,))

    def test_unreviewed_extra_warning_rejected(self):
        record=fixture()
        record["warnings"].append({"type":"unexpected"})
        with self.assertRaises(GuestNICImportError):
            verify_preview(record,cluster="test",expected_vms=2,
                           expected_nics=2,expected_macs=1,expected_held=(101,))

    def test_duplicate_mac_without_warning_rejected(self):
        record=fixture()
        record["warnings"]=[]
        with self.assertRaises(GuestNICImportError):
            verify_preview(record,cluster="test",expected_vms=2,
                           expected_nics=2,expected_macs=1,expected_held=(101,))

    def test_stale_preview_rejected(self):
        record=fixture()
        record["checked_at"]="2025-01-01T00:00:00+00:00"
        with self.assertRaises(GuestNICImportError):
            verify_preview(record,cluster="test",expected_vms=2,
                           expected_nics=2,expected_macs=1,expected_held=(101,))
