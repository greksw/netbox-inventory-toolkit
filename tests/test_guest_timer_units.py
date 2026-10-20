import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / "deploy" / "systemd"


class GuestTimerTests(unittest.TestCase):
    def test_service_separate_from_hardware(self):
        unit = (BASE / "netbox-guest-drift.service").read_text()
        self.assertIn("audit_guest_nics.py", unit)
        self.assertIn("/etc/netbox-inventory/drift.env", unit)
        self.assertIn("/etc/netbox-inventory/guest-audit.env", unit)
        self.assertIn("SuccessExitStatus=1", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("ReadWritePaths=/var/lib/netbox-guest-audit", unit)
        self.assertNotIn("ExecStartPost", unit)
        self.assertNotIn("apply=True", unit)
        self.assertNotIn("HI-PVE2", unit)
        self.assertNotIn("362", unit)
        self.assertNotIn("netbox-inventory-drift.service", unit)

    def test_timer_does_not_overlap_hardware_window(self):
        timer = (BASE / "netbox-guest-drift.timer").read_text()
        self.assertIn("OnCalendar=*-*-* 05:45:00", timer)
        self.assertIn("RandomizedDelaySec=15min", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("Unit=netbox-guest-drift.service", timer)
