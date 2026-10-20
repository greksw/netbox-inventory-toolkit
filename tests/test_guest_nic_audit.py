import unittest
from datetime import datetime, timezone
from netbox.audit_guest_nics import audit

def sample():
    src={"schema_version":"guests-0.1","collected_at":datetime.now(timezone.utc).isoformat(),
         "summary":{"selected":2,"collected":2,"errors":0},"guests":[]}
    vms=[]; interfaces=[]
    for vmid, state, bridge in [(101,"stopped","vmbr0"),(102,"running","vmbr100")]:
        src["guests"].append({"vmid":vmid,"type":"qemu","node":"test-pve","power_state":state,
            "cpu":{"configured_max_vcpus":2},"memory_mib":4096,
            "interfaces":[{"key":"net0","mac":"02:aa:bb:cc:dd:ee","bridge":bridge}]})
        vms.append({"id":vmid+1000,"cluster":{"name":"test"},"vcpus":2,"memory":4096,
                    "custom_fields":{"proxmox_vmid":vmid,"proxmox_guest_type":"qemu",
                      "proxmox_node":"test-pve","proxmox_power_state":state}})
        interfaces.append({"name":"net0","virtual_machine":{"id":vmid+1000},
            "description":"Proxmox host bridge: "+bridge+("; base-image MAC held" if vmid==101 else ""),
            "primary_mac_address":None if vmid==101 else {"mac_address":"02:aa:bb:cc:dd:ee"}})
    return src,vms,interfaces

class GuestAuditTests(unittest.TestCase):
    def test_known_held_mac_is_clean(self):
        s,v,i=sample()
        result=audit(s,v,i,cluster="test",expected_guests=2,held_vmids=[101])
        self.assertEqual(result["status"],"clean")
        self.assertEqual(result["counts"]["macs_present"],1)
        self.assertEqual(result["counts"]["approved_exceptions"],1)

    def test_missing_interface_is_drift(self):
        s,v,i=sample()
        result=audit(s,v,i[:1],cluster="test",expected_guests=2,held_vmids=[101])
        self.assertEqual(result["status"],"drift")
        self.assertEqual(result["by_kind"]["vm_interface_missing"],1)

    def test_changed_mac_is_drift(self):
        s,v,i=sample()
        i[1]["primary_mac_address"]={"mac_address":"02:aa:bb:cc:dd:01"}
        result=audit(s,v,i,cluster="test",expected_guests=2,held_vmids=[101])
        self.assertEqual(result["by_kind"]["vm_mac_mismatch"],1)

    def test_extra_interface_is_drift(self):
        s,v,i=sample()
        i.append({"name":"net1","virtual_machine":{"id":1102},
                  "primary_mac_address":None,"description":""})
        result=audit(s,v,i,cluster="test",expected_guests=2,held_vmids=[101])
        self.assertEqual(result["by_kind"]["vm_interface_extra"],1)

    def test_removed_duplicate_is_drift(self):
        s,v,i=sample()
        s["guests"][0]["interfaces"][0]["mac"]="02:aa:bb:cc:dd:02"
        result=audit(s,v,i,cluster="test",expected_guests=2,held_vmids=[101])
        self.assertEqual(result["by_kind"]["held_mac_no_longer_duplicated"],1)
