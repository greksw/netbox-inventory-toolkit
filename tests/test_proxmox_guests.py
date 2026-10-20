import unittest
from collectors.proxmox_guests import collect, GuestInventoryError

class Fake:
    def __init__(self):
        self.n=0
    def resources(self):
        self.n+=1
        return [{"vmid":101,"type":"qemu","node":"pve01","status":"running","name":"sample"},
                {"vmid":102,"type":"lxc","node":"pve02","status":"stopped","name":"sample-ct"}]
    def configuration(self,node,kind,vmid):
        return ({"sockets":2,"cores":4,"memory":4096,"net0":"virtio=02:11:22:33:44:55,bridge=vmbr0"}
                if vmid==101 else
                {"cores":2,"memory":2048,"net0":"name=eth0,hwaddr=02:11:22:33:44:56,bridge=vmbr1"})
class GuestTests(unittest.TestCase):
    def test_success(self):
        x=collect(Fake(),expected_guests=2)
        self.assertEqual(x["summary"]["by_type"],{"lxc":1,"qemu":1})
        self.assertEqual(x["summary"]["interfaces"],2)
        self.assertEqual(x["guests"][0]["cpu"]["configured_max_vcpus"],8)
    def test_mismatch(self):
        with self.assertRaises(GuestInventoryError):
            collect(Fake(),expected_guests=3)
