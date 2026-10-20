import unittest
from unittest.mock import Mock
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "zabbix"))
from configure_guest_template_api import execute, TEMPLATE, KEYS

class FakeAPI:
    def __init__(self, populated=False):
        self.populated=populated
        self.mutations=[]
    def call(self, method, args):
        if method == "host.get":
            return [{"hostid":"100","host":"test-node","parentTemplates":([{"templateid":"200"}] if self.populated else [])}]
        if method == "template.get":
            return ([{"host":TEMPLATE,"name":"NetBox Guest Inventory Drift","templateid":"200"}] if self.populated else [])
        if method == "templategroup.get":
            return [{"name":"Templates","groupid":"1"}]
        if method == "item.get":
            return ([{"key_":k,"type":"0","value_type":"3","status":"0","itemid":str(i)} for i,k in enumerate(KEYS)] if self.populated else [])
        if method == "trigger.get":
            if not self.populated: return []
            names=["NetBox guest: Inventory drift detected","NetBox guest: Inventory audit failed","NetBox guest: Inventory audit is stale (>26h)","NetBox guest: No audit monitoring data received"]
            expr=[f"last(/{TEMPLATE}/{KEYS[0]})=1",f"last(/{TEMPLATE}/{KEYS[0]})=2",f"now()-last(/{TEMPLATE}/{KEYS[2]})>93600",f"nodata(/{TEMPLATE}/{KEYS[0]},15m)=1"]
            return [{"description":n,"expression":e,"priority":p,"status":"0"} for n,e,p in zip(names,expr,[2,4,3,3])]
        self.mutations.append((method,args))
        if method=="template.create": return {"templateids":["200"]}
        return {}

class GuestTemplateTests(unittest.TestCase):
    def test_dry_run_has_no_writes(self):
        api=FakeAPI()
        execute(api,"test-node",False)
        self.assertEqual(api.mutations, [])
    def test_apply_initial(self):
        api=FakeAPI()
        execute(api,"test-node",True)
        self.assertEqual([m for m,_ in api.mutations].count("item.create"),3)
        self.assertEqual([m for m,_ in api.mutations].count("trigger.create"),4)
        self.assertEqual([m for m,_ in api.mutations].count("host.massadd"),1)
    def test_existing_idempotent(self):
        api=FakeAPI(populated=True)
        execute(api,"test-node",True)
        self.assertEqual(api.mutations,[])
