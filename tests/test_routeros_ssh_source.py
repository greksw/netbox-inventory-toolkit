import json
import subprocess
import unittest
from unittest.mock import patch
from routeros.ssh_source import RouterOSSSHReader, IPAMAuditError

class FakeSSH(RouterOSSSHReader):
    def __init__(self):
        self.host="192.0.2.1"
        self.username="audit"
        self.identity="/private/test_key"
        self.known_hosts="/private/known_hosts"
        self.timeout=20

class SSHSourceTests(unittest.TestCase):
    def test_two_allowlisted_commands(self):
        r=FakeSSH()
        for endpoint in ("/rest/interface/vlan","/rest/ip/address"):
            with patch("routeros.ssh_source.subprocess.run") as run:
                run.return_value=subprocess.CompletedProcess([],0,b'[{"name":"vlan10"}]',b"")
                self.assertEqual(len(r.listing(endpoint)),1)
                argv=run.call_args.args[0]
                self.assertIn("StrictHostKeyChecking=yes"," ".join(argv))
                self.assertIn("BatchMode=yes"," ".join(argv))
                self.assertEqual(argv[0],"/usr/bin/ssh")
                self.assertFalse(run.call_args.kwargs.get("shell",False))
    def test_forbidden_command(self):
        with self.assertRaises(IPAMAuditError):
            FakeSSH().listing("/rest/system/script")
    def test_bad_json(self):
        with patch("routeros.ssh_source.subprocess.run") as run:
            run.return_value=subprocess.CompletedProcess([],0,b"not-json",b"")
            with self.assertRaises(IPAMAuditError):
                FakeSSH().listing("/rest/ip/address")
    def test_nonzero_exit_hides_stderr(self):
        with patch("routeros.ssh_source.subprocess.run") as run:
            run.return_value=subprocess.CompletedProcess([],255,b"",b"SECRET-CONTENT")
            with self.assertRaises(IPAMAuditError) as err:
                FakeSSH().listing("/rest/ip/address")
            self.assertNotIn("SECRET-CONTENT",str(err.exception))

if __name__=="__main__": unittest.main()
