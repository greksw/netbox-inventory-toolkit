# Read-only guest vNIC preview

Run on the Proxmox cluster collector node, after creating a fresh private guest snapshot. The preview uses Proxmox pvesh GET and NetBox HTTPS GET only. It does not create or update NetBox objects.

```bash
cd /root/netbox-inventory-toolkit
python3 collectors/proxmox_guests.py --expected-guests 31 --cluster-label corporate-pve --output output/proxmox-guests-v01.json
set -a
source /etc/netbox-inventory/drift.env
set +a
python3 netbox/preview_guest_nics.py --inventory output/proxmox-guests-v01.json --cluster HI-PVE2 --expected-guests 31 --output output/guest-nics-preview.json
```

The preview requires a NetBox v2 token allowed to GET virtualization VM and VM interface API endpoints. A hardware-only read-only token may need additional GET permissions. Do not print tokens.

The private report contains MAC addresses and VM identity; retain mode 0600 and never commit it. The printed output contains counts and masked duplicate MAC warnings.

- Each source VMID must map exactly once to an existing NetBox VM in the designated cluster.
- CPU, RAM, type, placement and power state must match before planning.
- QEMU interfaces use Proxmox config keys such as net0; LXC interfaces use guest NIC names such as eth0.
- Duplicated MACs are held except the sole running guest may be marked eligible after review. This is not permission to write.
- Missing Linux bridges are reported as warnings; do not automatically change VM configuration.
- Linux bridge names are not NetBox VMInterface.bridge foreign keys. Persisting bridge metadata or VLAN assignments requires a separate reviewed design.
- The current script does not apply changes, does not compare existing primary MACs, and does not authorize a future apply automatically.
