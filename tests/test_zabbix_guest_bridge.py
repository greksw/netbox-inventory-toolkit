import unittest
from datetime import datetime, timezone
from netbox.zabbix_guest_bridge import summarize

class GuestZabbixBridgeTests(unittest.TestCase):
    def sample(self, state="clean", differences=0):
        return {"schema_version":"guest-nic-drift-0.1",
                "status":state,"counts":{"differences":differences},
                "checked_at":datetime.now(timezone.utc).isoformat()}
    def test_clean(self):
        self.assertEqual(summarize(self.sample(),"success")["status"],0)
    def test_drift(self):
        m=summarize(self.sample("drift",3),"success")
        self.assertEqual((m["status"],m["differences"]),(1,3))
    def test_failure(self):
        self.assertEqual(summarize(self.sample(),"exit-code")["status"],2)
    def test_wrong_report_schema(self):
        m=self.sample();m["schema_version"]="0.1"
        self.assertEqual(summarize(m,"success")["status"],2)
    def test_bad_clean_count(self):
        self.assertEqual(summarize(self.sample("clean",2),"success")["status"],2)
