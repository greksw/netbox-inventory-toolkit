import unittest
from datetime import datetime, timezone
from routeros.ipam_audit import compare, IPAMAuditError

def fixture():
    now=datetime.now(timezone.utc).isoformat()
    router={"schema_version":"routeros-ipam-0.1","collected_at":now,"vlans":[
        {"vid":100,"name":"vlan100","parent":"bonding1","disabled":False},
        {"vid":200,"name":"vlan200","parent":"bonding1","disabled":False}],
        "addresses":[
        {"address":"192.0.2.1/24","interface":"vlan100","dynamic":False,"disabled":False},
        {"address":"198.51.100.1/24","interface":"vlan200","dynamic":False,"disabled":False},
        {"address":"10.8.0.5/24","interface":"WAN","dynamic":True,"disabled":False}]}
    netbox={"schema_version":"netbox-router-ipam-0.1","collected_at":now,"vlans":[
        {"vid":100,"prefix":"192.0.2.0/24"},{"vid":200,"prefix":"198.51.100.0/24"}],
        "addresses":[{"address":"192.0.2.1/24","interface":"vlan100"},
                     {"address":"198.51.100.1/24","interface":"vlan200"}]}
    return router,netbox

class TestRouterIPAM(unittest.TestCase):
    def check(self,r,n,**kw):
        return compare(r,n,expected_vlans=2,expected_static_addresses=2,**kw)
    def test_dynamic_needs_review(self):
        r,n=fixture()
        x=self.check(r,n)
        self.assertEqual(x["categories"],{"dynamic_review_required":1})
        self.assertNotIn("10.8.0.5",str(x))
    def test_approved_dynamic_clean(self):
        r,n=fixture()
        self.assertEqual(self.check(r,n,approved_dynamic=(("10.8.0.5/24","WAN"),))["status"],"CLEAN")
    def test_wrong_interface_is_drift(self):
        r,n=fixture()
        n["addresses"][0]["interface"]="WAN"
        x=self.check(r,n)
        self.assertEqual(x["categories"]["static_ip_missing_netbox"],1)
        self.assertEqual(x["categories"]["static_ip_extra_netbox"],1)
    def test_prefix_mismatch(self):
        r,n=fixture()
        n["vlans"][1]["prefix"]="203.0.113.0/24"
        self.assertEqual(self.check(r,n)["categories"]["vlan_prefix_mismatch"],1)
    def test_stale_fails_closed(self):
        r,n=fixture()
        r["collected_at"]="2020-01-01T00:00:00+00:00"
        with self.assertRaises(IPAMAuditError): self.check(r,n)
    def test_count_fails_closed(self):
        r,n=fixture()
        n["addresses"].pop()
        with self.assertRaises(IPAMAuditError): self.check(r,n)
    def test_bad_cidr_fails(self):
        r,n=fixture()
        r["addresses"][0]["address"]="broken"
        with self.assertRaises(IPAMAuditError): self.check(r,n)
    def test_disabled_vlan_fails(self):
        r,n=fixture()
        r["vlans"][0]["disabled"]=True
        with self.assertRaises(IPAMAuditError): self.check(r,n)

if __name__=="__main__": unittest.main()
