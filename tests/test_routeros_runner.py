"""Offline tests: no RouterOS/NetBox connections or writes."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch, sentinel

from routeros.run_local_audit import main, run_once, validate_config
from routeros.ipam_audit import IPAMAuditError


def example():
    return {
        "schema_version": "routeros-netbox-ipam-live-v1",
        "routeros": {
            "host": "192.0.2.1", "username": "audit",
            "identity_file": "/private/ssh.key",
            "known_hosts_file": "/private/known_hosts",
        },
        "netbox": {
            "origin": "https://netbox.example.invalid",
            "token_file": "/private/token",
            "ca_file": "/private/ca.crt",
            "router_name": "router-example",
            "site_slug": "site-example",
            "vlan_group_slug": "vlans-example",
        },
        "baseline": {"vlans": 2, "static_ipv4": 3},
        "approved_dynamic": [],
        "max_age_minutes": 60,
    }


class RunnerTests(unittest.TestCase):
    def test_config_valid(self):
        self.assertEqual(validate_config(example()), example())

    def test_config_blocks_unexpected_keys(self):
        cfg = example()
        cfg["routeros"]["command"] = "/system reboot"
        with self.assertRaises(IPAMAuditError):
            validate_config(cfg)

    def test_config_rejects_bad_count(self):
        for value in (False, -1, 0, "3", 1000000):
            cfg = example()
            cfg["baseline"]["vlans"] = value
            with self.subTest(value=value), self.assertRaises(IPAMAuditError):
                validate_config(cfg)

    def test_config_dynamic_requires_exact_reviewed_pair(self):
        cfg = example()
        cfg["approved_dynamic"] = [
            {"address": "198.51.100.10/24", "interface": "uplink"},
        ]
        self.assertEqual(len(validate_config(cfg)["approved_dynamic"]), 1)
        cfg["approved_dynamic"].append(cfg["approved_dynamic"][0])
        with self.assertRaises(IPAMAuditError):
            validate_config(cfg)

    def test_run_once_uses_exact_sources_and_no_writes(self):
        cfg = example()
        cfg["approved_dynamic"] = [
            {"address": "198.51.100.10/24", "interface": "uplink"},
        ]
        with (patch("routeros.run_local_audit.read_root_private", return_value="nbt_example.secret") as read,
              patch("routeros.run_local_audit.RouterOSSSHReader", return_value=sentinel.ssh) as ssh,
              patch("routeros.run_local_audit.routeros_snapshot", return_value=sentinel.router) as rs,
              patch("routeros.run_local_audit.NetBoxReader", return_value=sentinel.netbox) as n,
              patch("routeros.run_local_audit.netbox_snapshot", return_value=sentinel.nb) as ns,
              patch("routeros.run_local_audit.compare", return_value={"status": "CLEAN", "differences": 0}) as cp):
            got = run_once(cfg)
            self.assertEqual(got["status"], "CLEAN")
            read.assert_called_once_with("/private/token", size_limit=512)
            ssh.assert_called_once()
            rs.assert_called_once_with(sentinel.ssh)
            n.assert_called_once_with(origin="https://netbox.example.invalid", token="nbt_example.secret", ca_file="/private/ca.crt")
            ns.assert_called_once()
            self.assertEqual(cp.call_args.kwargs["approved_dynamic"], (("198.51.100.10/24", "uplink"),))

    def test_cli_clean_drift_and_sanitized_error(self):
        for rc, state, differences in [(0, "CLEAN", 0), (1, "DRIFT", 2)]:
            report = {"status": state, "differences": differences,
                      "counts": {"routeros_vlans": 2}, "categories": {}}
            with (patch("routeros.run_local_audit.read_root_private", return_value=json.dumps(example())),
                  patch("routeros.run_local_audit.run_once", return_value=report)):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    code = main(["--config", "/private/settings"])
            self.assertEqual(rc, code)
            self.assertIn("ROUTEROS IPAM AUDIT: " + state, buf.getvalue())
        with (patch("routeros.run_local_audit.read_root_private", side_effect=Exception("sensitive-value")),
              contextlib.redirect_stdout(io.StringIO()) as out):
            self.assertEqual(main(["--config", "/private/settings"]), 2)
        self.assertNotIn("sensitive-value", out.getvalue())


if __name__ == "__main__":
    unittest.main()
