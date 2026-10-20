# Read-only Proxmox QEMU/LXC guest collector v0.1

The collector uses pvesh GET for /cluster/resources and the QEMU/LXC config of each guest. Only selected fields are retained: VMID, type, placement, state, CPU, RAM (MiB), and vNIC MAC/bridge/VLAN. Private configuration and disk data are not saved.

On the cluster node:

```bash
cd /root/netbox-inventory-toolkit
python3 -m unittest discover -s tests -v
python3 collectors/proxmox_guests.py --expected-guests 31 --output output/proxmox-guests-v01.json
```

Guest snapshot JSON stays 0600. Missing configurations or changes in cluster membership and placement cause a nonzero exit. Results are read-only and do not modify NetBox. CPU describes configured maximum topology, not usage; RAM describes configured memory, not current consumption. LXC core limits and QEMU sockets/cores have different semantics. Do not assume VM/CT vNIC data is already present in NetBox.
