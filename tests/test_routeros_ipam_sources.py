import unittest
from datetime import datetime
from routeros.ipam_audit import compare
from routeros.ipam_sources import routeros_snapshot, netbox_snapshot, safe_origin, IPAMAuditError

class FakeReader:
    def __init__(self, data): self.data=data
    def listing(self, path, params=None): return self.data[path]

class SourceTests(unittest.TestCase):
    def test_unsafe_url(self):
        for url in ("http://router","https://router/path","https://user:pass@router","https://router/?x=1"):
            with self.assertRaises(IPAMAuditError): safe_origin(url)
    def test_snapshot_pair(self):
        ros=FakeReader({
            "/rest/interface/vlan":[{"vlan-id":"100","name":"vlan100","interface":"bonding1","disabled":"false"}],
            "/rest/ip/address":[{"address":"192.0.2.1/24","interface":"vlan100","dynamic":"false","disabled":"false"}]
        })
        net=FakeReader({
            "/api/dcim/devices/":[{"id":12,"name":"test-router","site":{"slug":"sample-site"},"role":{"slug":"router"}}],
            "/api/dcim/interfaces/":[{"id":101,"name":"vlan100","device":{"id":12}}],
            "/api/ipam/vlans/":[{"id":3,"vid":100,"group":{"slug":"sample-vlans"}}],
            "/api/ipam/prefixes/":[{"prefix":"192.0.2.0/24","vlan":{"id":3}}],
            "/api/ipam/ip-addresses/":[{"address":"192.0.2.1/24","assigned_object_type":"dcim.interface","assigned_object_id":101}]
        })
        a=routeros_snapshot(ros)
        b=netbox_snapshot(net,router_name="test-router",site_slug="sample-site",vlan_group_slug="sample-vlans")
        report=compare(a,b,expected_vlans=1,expected_static_addresses=1)
        self.assertEqual(report["status"],"CLEAN")
    def test_unknown_router_identity(self):
        with self.assertRaises(IPAMAuditError):
            netbox_snapshot(FakeReader({"/api/dcim/devices/":[]}),router_name="test-router",site_slug="sample-site",vlan_group_slug="sample-vlans")
    def test_extra_prefix_rejected(self):
        reader=FakeReader({
            "/api/dcim/devices/":[{"id":12,"name":"test-router","site":{"slug":"sample-site"},"role":{"slug":"router"}}],
            "/api/dcim/interfaces/":[{"id":101,"name":"vlan100","device":{"id":12}}],
            "/api/ipam/vlans/":[{"id":3,"vid":100,"group":{"slug":"sample-vlans"}}],
            "/api/ipam/prefixes/":[{"prefix":"192.0.2.0/24","vlan":{"id":3}},{"prefix":"198.51.100.0/24","vlan":{"id":3}}],
            "/api/ipam/ip-addresses/":[]})
        with self.assertRaises(IPAMAuditError):
            netbox_snapshot(reader,router_name="test-router",site_slug="sample-site",vlan_group_slug="sample-vlans")

if __name__=="__main__": unittest.main()
